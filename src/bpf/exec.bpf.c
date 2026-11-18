// SPDX-License-Identifier: GPL-2.0
/* agentbox exec tracer.
 *
 * Three hooks, all filtered to the sandbox's cgroup v2 id:
 *
 *  sys_enter_execve / sys_enter_execveat
 *      What the caller *asked* to run. argv is read from the caller's memory,
 *      so a sibling thread could still rewrite it before the kernel copies it.
 *      Treat it as a claim, not a fact.
 *
 *  sched_process_exec
 *      Fires after the new image is loaded and before any of its user code
 *      runs. argv/envp are read from the NEW mm (the strings the kernel itself
 *      copied onto the new stack); every other thread of the old process is
 *      already gone. exe and cwd are resolved by walking dentries in-kernel,
 *      relative to the task's own root, so paths are what the sandboxed
 *      process sees. This is the authoritative record.
 *
 *  sys_exit_execve / sys_exit_execveat
 *      Only failures are reported (on success the old image no longer exists).
 *
 * Loops run under bpf_loop() (5.17+) so the verifier checks each body once.
 * Events are assembled in a per-CPU scratch buffer and copied to the ring.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 target_cgid = 0;
const volatile bool capture_env = false;
const volatile bool log_reads = false;
const volatile __u32 deny_mode = DENY_OFF;
const volatile bool watch_reads = false;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

/* Events dropped because the ring buffer was full, per event kind. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DROP_KINDS);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

union scratch {
	struct exec_event exec;
	struct file_event file;
	struct connect_event conn;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, union scratch);
} heap SEC(".maps");

/* Request events are built from a sleepable program, which can be preempted
 * mid-run, so they need per-thread (not per-CPU) scratch space.
 *
 * This is a preallocated LRU hash keyed by tid, not task storage: since the
 * local-storage allocator moved to kmalloc_nolock() (Linux 6.19+), task
 * storage values over 8 KiB fail to allocate, and bpf_task_storage_get()
 * just returns NULL. Preallocated elements never allocate at run time. LRU
 * eviction cleans up after threads that died mid-syscall. */
#define TID_SLOTS 1024
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TID_SLOTS);
	__type(key, __u32);
	__type(value, struct exec_request_event);
} req_store SEC(".maps");

/* Faults pages in, unlike bpf_probe_read_user_str (6.12+). */
extern int bpf_copy_from_user_str(void *dst, __u32 dst__sz, const void *unsafe_ptr__ign,
				  __u64 flags) __ksym __weak;

static const __u32 ZERO = 0;

static __always_inline union scratch *scratch(void)
{
	return bpf_map_lookup_elem(&heap, &ZERO);
}

/* This thread's slot in a tid-keyed map, created if missing. The initial
 * contents are whatever is in the per-CPU scratch (callers initialise every
 * field they use); the scratch is only a source big enough to copy from. */
static __always_inline void *tid_slot(void *map)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	void *v = bpf_map_lookup_elem(map, &tid);
	if (v)
		return v;
	union scratch *src = scratch();
	if (!src)
		return NULL;
	bpf_map_update_elem(map, &tid, src, BPF_NOEXIST);
	return bpf_map_lookup_elem(map, &tid);
}

static __always_inline void *tid_get(void *map)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	return bpf_map_lookup_elem(map, &tid);
}

static __always_inline bool in_sandbox(void)
{
	return target_cgid != 0 && bpf_get_current_cgroup_id() == target_cgid;
}

static __always_inline void submit(void *ev, __u64 size)
{
	if (bpf_ringbuf_output(&events, ev, size, 0)) {
		/* every event starts with ev_header.kind */
		__u32 kind = *(__u32 *)ev & (DROP_KINDS - 1);
		__u64 *v = bpf_map_lookup_elem(&drops, &kind);
		if (v)
			__sync_fetch_and_add(v, 1);
	}
}

static __always_inline void fill_header(struct ev_header *h, __u32 kind)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	h->kind = kind;
	h->tid = (__u32)pid_tgid;
	h->pid = pid_tgid >> 32;
	h->ppid = BPF_CORE_READ(task, real_parent, tgid);
	h->uid = (__u32)uid_gid;
	h->gid = uid_gid >> 32;
	h->_pad0 = 0;
	h->ts_boot_ns = bpf_ktime_get_boot_ns();

	/* pid in the innermost pid namespace */
	struct pid *p = BPF_CORE_READ(task, thread_pid);
	unsigned int level = BPF_CORE_READ(p, level);
	struct upid up = {};
	bpf_core_read(&up, sizeof(up), &p->numbers[level & 31]);
	h->ns_pid = up.nr;
}

/* --deny rules (see "deny" below). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct deny_ino_key);
	__type(value, __u32);
} deny_ino SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, char[NAME_MAX_ + 1]);
	__type(value, __u32);
} deny_name SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_denied_event);
} deny_heap SEC(".maps");

/* Is `f` a denied binary? Returns DENY_BY_* or 0. Leaves the file's name,
 * NUL-padded, in `name` (also the hash key). */
static __always_inline __u32 deny_match(struct file *f, char name[NAME_MAX_ + 1])
{
	struct inode *inode = BPF_CORE_READ(f, f_inode);
	struct deny_ino_key k = {
		.dev = BPF_CORE_READ(inode, i_sb, s_dev),
		.ino = BPF_CORE_READ(inode, i_ino),
	};
	if (bpf_map_lookup_elem(&deny_ino, &k))
		return DENY_BY_INODE;
	__builtin_memset(name, 0, NAME_MAX_ + 1);
	const unsigned char *n = BPF_CORE_READ(f, f_path.dentry, d_name.name);
	bpf_probe_read_kernel_str(name, NAME_MAX_ + 1, n);
	if (bpf_map_lookup_elem(&deny_name, name))
		return DENY_BY_NAME;
	return 0;
}

/* Watched reads: read-only opens are normally not reported (too many), but
 * a file is if its own name or one of its parent directories' names is in
 * this set (".ssh", ".aws", ...). That is a coarse filter; userspace then
 * checks the full path against the real watch list. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[NAME_MAX_ + 1]);
	__type(value, __u32);
} watch_name SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[NAME_MAX_ + 1]);
} watch_key SEC(".maps");

#define WATCH_DEPTH 8

static __always_inline bool watch_match(struct file *f)
{
	char *k = bpf_map_lookup_elem(&watch_key, &ZERO);
	if (!k || !f)
		return false;
	struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
	for (int i = 0; i < WATCH_DEPTH; i++) {
		__builtin_memset(k, 0, NAME_MAX_ + 1);
		const unsigned char *n = BPF_CORE_READ(d, d_name.name);
		bpf_probe_read_kernel_str(k, NAME_MAX_ + 1, n);
		if (bpf_map_lookup_elem(&watch_name, k))
			return true;
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (parent == d)
			break;
		d = parent;
	}
	return false;
}

/* Privileged syscalls whose failure is worth a record (filled by userspace). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} watch_sys SEC(".maps");

/* ------------------------------------------------------------ path walking */

struct path_ctx {
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	struct dentry *root_dentry;
	struct vfsmount *root_mnt;
	char *buf; /* PATHBUF + NAME_MAX + 1 bytes */
	__u32 off;
};

/* One step up the tree. Returns 1 to stop. */
static long path_step(__u64 idx, void *arg)
{
	struct path_ctx *c = arg;
	/* Locals, so CO-RE relocations apply to kernel types, not path_ctx. */
	struct dentry *dentry = c->dentry;
	struct vfsmount *vfsmnt = c->vfsmnt;
	struct mount *mnt = c->mnt;

	if (dentry == c->root_dentry && vfsmnt == c->root_mnt)
		return 1;

	struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

	if (dentry == mnt_root || dentry == parent) {
		struct mount *mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
		if (dentry != mnt_root || mnt == mnt_parent)
			return 1; /* namespace root or detached */
		c->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
		c->mnt = mnt_parent;
		c->vfsmnt = &mnt_parent->mnt;
		return 0;
	}

	char *buf = c->buf;
	if (!buf)
		return 1;

	struct qstr name = BPF_CORE_READ(dentry, d_name);
	__u32 len = name.len & NAME_MAX_;
	if (len + 1 > c->off)
		return 1;
	__u32 off = c->off - (len + 1);
	buf[off & (PATHBUF - 1)] = '/';
	bpf_probe_read_kernel(&buf[(off + 1) & (PATHBUF - 1)], len, name.name);
	c->off = off;
	c->dentry = parent;
	return 0;
}

/* Resolve `p` relative to `root`. The string is written backwards so it ends
 * at buf[PATHBUF]; returns its start offset. */
static __always_inline __u32 resolve_path(char buf[PATHBUF + NAME_MAX_ + 1], struct path *p,
					  struct path *root)
{
	struct path_ctx c = {
		.dentry = p->dentry,
		.vfsmnt = p->mnt,
		.mnt = container_of(p->mnt, struct mount, mnt),
		.root_dentry = root->dentry,
		.root_mnt = root->mnt,
		.buf = buf,
		.off = PATHBUF,
	};
	bpf_loop(MAX_PATH_DEPTH, path_step, &c, 0);
	if (c.off >= PATHBUF) { /* the root itself */
		buf[PATHBUF - 1] = '/';
		return PATHBUF - 1;
	}
	return c.off;
}

static __always_inline void task_paths(struct task_struct *task, struct path *root, struct path *pwd)
{
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	bpf_core_read(root, sizeof(*root), &fs->root);
	bpf_core_read(pwd, sizeof(*pwd), &fs->pwd);
}

/* ---------------------------------------------------------------- request */

/* Two capture paths for the same data, chosen at load time by userspace:
 *
 *   fentry.s on the syscall entry (preferred): sleepable, so it can fault in
 *   pages the caller never touched (argv strings in .rodata, fresh stacks).
 *
 *   tracepoint sys_enter_* (fallback, for kernels or policies that refuse
 *   fentry): cannot fault, so an untouched page reads as EFAULT. Those are
 *   flagged REQ_UNREADABLE instead of being reported as a mismatch.
 */

struct argv_ctx {
	struct exec_request_event *e;
	const char *const *argv;
	__u32 off;
	__u32 argc;
	__u32 flags;
};

#define DEFINE_ARGV_STEP(name, READ_PTR, READ_STR)					\
static long name(__u64 i, void *arg)							\
{											\
	struct argv_ctx *c = arg;							\
	struct exec_request_event *e = c->e;						\
	const char *p = NULL;								\
											\
	if (!e)										\
		return 1;								\
	if (READ_PTR(&p, sizeof(p), &c->argv[i])) {					\
		c->flags |= REQ_UNREADABLE;						\
		return 1;								\
	}										\
	if (!p)										\
		return 1;								\
	if (c->off >= ARGBUF || i == MAX_ARGS) {					\
		c->flags |= REQ_TRUNCATED;						\
		return 1;								\
	}										\
	long n = READ_STR(&e->argv[c->off & (ARGBUF - 1)], ARG_MAX_ONE, p);		\
	if (n <= 0) {									\
		c->flags |= REQ_UNREADABLE;						\
		return 1;								\
	}										\
	c->off += n;									\
	c->argc++;									\
	return 0;									\
}

static __always_inline long copy_str_sleepable(void *dst, __u32 size, const void *src)
{
	if (bpf_ksym_exists(bpf_copy_from_user_str))
		return bpf_copy_from_user_str(dst, size, src, 0);
	return bpf_probe_read_user_str(dst, size, src);
}

DEFINE_ARGV_STEP(argv_step_sleepable, bpf_copy_from_user, copy_str_sleepable)
DEFINE_ARGV_STEP(argv_step_atomic, bpf_probe_read_user, bpf_probe_read_user_str)

static __always_inline int handle_enter(const char *filename, const char *const *argv,
					__s32 dirfd, __u32 flags, __u32 is_at, bool sleepable)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct exec_request_event *e =
		tid_slot(&req_store);
	if (!e)
		return 0;

	fill_header(&e->h, EV_EXEC_REQUEST);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->dirfd = dirfd;
	e->flags = flags;
	e->is_execveat = is_at;
	e->_pad1 = 0;
	e->filename[0] = 0;

	struct argv_ctx ac = { .e = e, .argv = argv };
	long n = sleepable ? copy_str_sleepable(e->filename, sizeof(e->filename), filename)
			   : bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
	if (n < 0)
		ac.flags |= REQ_UNREADABLE;

	/* One extra iteration detects argv longer than MAX_ARGS. */
	bpf_loop(MAX_ARGS + 1, sleepable ? argv_step_sleepable : argv_step_atomic, &ac, 0);
	e->argc = ac.argc;
	e->argv_len = ac.off;
	e->req_flags = ac.flags | (sleepable ? REQ_SLEEPABLE : 0);

	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->cwd_off = resolve_path(e->cwd, &pwd, &root);

	submit(e, sizeof(*e));
	return 0;
}

#if defined(__TARGET_ARCH_arm64)
#define SYS(name) "fentry.s/__arm64_sys_" #name
#else
#define SYS(name) "fentry.s/__x64_sys_" #name
#endif

SEC(SYS(execve))
int BPF_PROG(fe_execve, struct pt_regs *regs)
{
	return handle_enter((const char *)PT_REGS_PARM1_CORE_SYSCALL(regs),
			    (const char *const *)PT_REGS_PARM2_CORE_SYSCALL(regs),
			    -100 /* AT_FDCWD */, 0, 0, true);
}

SEC(SYS(execveat))
int BPF_PROG(fe_execveat, struct pt_regs *regs)
{
	return handle_enter((const char *)PT_REGS_PARM2_CORE_SYSCALL(regs),
			    (const char *const *)PT_REGS_PARM3_CORE_SYSCALL(regs),
			    (__s32)PT_REGS_PARM1_CORE_SYSCALL(regs),
			    (__u32)PT_REGS_PARM5_CORE_SYSCALL(regs), 1, true);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter((const char *)ctx->args[0], (const char *const *)ctx->args[1],
			    -100, 0, 0, false);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return handle_enter((const char *)ctx->args[1], (const char *const *)ctx->args[2],
			    (__s32)ctx->args[0], (__u32)ctx->args[4], 1, false);
}

/* ----------------------------------------------------------------- result */

static __always_inline int handle_exit(long ret)
{
	if (ret >= 0 || !in_sandbox())
		return 0;
	struct exec_result_event e = {};
	fill_header(&e.h, EV_EXEC_RESULT);
	e.ret = ret;
	submit(&e, sizeof(e));
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tp_exit_execve(struct trace_event_raw_sys_exit *ctx) { return handle_exit(ctx->ret); }

SEC("tracepoint/syscalls/sys_exit_execveat")
int tp_exit_execveat(struct trace_event_raw_sys_exit *ctx) { return handle_exit(ctx->ret); }

/* ------------------------------------------------------------ actual exec */

SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	if (!in_sandbox())
		return 0;
	union scratch *s = scratch();
	if (!s)
		return 0;
	struct exec_event *e = &s->exec;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	fill_header(&e->h, EV_EXEC);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->old_tid = ctx->old_pid;
	e->denied = 0;

	unsigned int fn_off = ctx->__data_loc_filename & 0xFFFF;
	e->filename[0] = 0;
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (void *)ctx + fn_off);

	struct mm_struct *mm = BPF_CORE_READ(task, mm);

	/* argv from the new image */
	__u64 a0 = BPF_CORE_READ(mm, arg_start), a1 = BPF_CORE_READ(mm, arg_end);
	__u64 len = a1 > a0 ? a1 - a0 : 0;
	e->argv_truncated = 0;
	if (len > ARGBUF) {
		len = ARGBUF;
		e->argv_truncated = 1;
	}
	e->argv_len = len;
	if (bpf_probe_read_user(e->argv, len, (void *)a0))
		e->argv_len = 0;

	e->env_len = 0;
	e->env_truncated = 0;
	if (capture_env) {
		__u64 e0 = BPF_CORE_READ(mm, env_start), e1 = BPF_CORE_READ(mm, env_end);
		__u64 elen = e1 > e0 ? e1 - e0 : 0;
		if (elen > ARGBUF) {
			elen = ARGBUF;
			e->env_truncated = 1;
		}
		e->env_len = elen;
		if (bpf_probe_read_user(e->env, elen, (void *)e0))
			e->env_len = 0;
	}

	/* cwd and exe, relative to the task's own root */
	struct path root = {}, pwd = {}, exe = {};
	task_paths(task, &root, &pwd);
	struct file *exe_file = BPF_CORE_READ(mm, exe_file);
	bpf_core_read(&exe, sizeof(exe), &exe_file->f_path);

	e->cwd_off = resolve_path(e->cwd, &pwd, &root);
	e->exe_off = resolve_path(e->exe, &exe, &root);

	/* Without BPF LSM, the deny list is enforced here: the new image is
	 * loaded but none of its code has run, and SIGKILL is delivered on the
	 * way back to user space. */
	if (deny_mode == DENY_KILL) {
		struct exec_denied_event *d = bpf_map_lookup_elem(&deny_heap, &ZERO);
		if (d) {
			e->denied = deny_match(exe_file, d->name);
			if (e->denied)
				bpf_send_signal(9 /* SIGKILL */);
		}
	}

	submit(e, sizeof(*e));
	return 0;
}

/* ------------------------------------------------------------------ deny
 *
 * --deny rules, filled in by userspace: inodes (dev, ino) of named binaries
 * and bare file names. Both are matched against the file the kernel is
 * actually loading, so symlinks, hard links, bind mounts and argv[0] games
 * don't help; a renamed *copy* of a denied binary only matches by name.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
	if (ret || deny_mode != DENY_LSM || !in_sandbox())
		return ret;
	struct exec_denied_event *e = bpf_map_lookup_elem(&deny_heap, &ZERO);
	if (!e)
		return 0;
	struct file *f = bprm->file;
	__u32 rule = deny_match(f, e->name);
	if (!rule)
		return 0;

	fill_header(&e->h, EV_EXEC_DENIED);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->rule = rule;
	struct task_struct *task = bpf_get_current_task_btf();
	struct path root = {}, fp = {};
	struct fs_struct *fs = task->fs;
	bpf_core_read(&root, sizeof(root), &fs->root);
	bpf_core_read(&fp, sizeof(fp), &f->f_path);
	e->exe_off = resolve_path(e->exe, &fp, &root);
	submit(e, sizeof(*e));
	return -13; /* EACCES */
}

/* ============================================================ file + net ops
 *
 * Same two-sided pattern as exec. At syscall entry the request (paths,
 * sockaddr) is copied into per-task storage. At syscall exit one combined
 * event is emitted carrying the result plus what the kernel says was actually
 * touched:
 *   - dirfd / cwd resolved to a path (what a relative name was relative to)
 *   - open: the path of the fd it returned (after symlinks, bind mounts, ...)
 *   - connect: the socket's peer address as the kernel now holds it
 */

#define AT_FDCWD_ (-100)
#define AT_REMOVEDIR_ 0x200
#define O_ACCMODE_ 03
#define O_WRONLY_ 01
#define O_CREAT_ 0100
#define O_TRUNC_ 01000
#define S_IFMT_ 0170000
#define S_IFSOCK_ 0140000

enum sc_id {
	SC_OPEN = 1, SC_CREAT, SC_OPENAT, SC_OPENAT2,
	SC_UNLINK, SC_UNLINKAT, SC_RMDIR,
	SC_RENAME, SC_RENAMEAT, SC_RENAMEAT2,
	SC_MKDIR, SC_MKDIRAT,
	SC_LINK, SC_LINKAT, SC_SYMLINK, SC_SYMLINKAT,
	SC_CHMOD, SC_FCHMODAT, SC_CHOWN, SC_LCHOWN, SC_FCHOWNAT,
	SC_TRUNCATE,
	/* by file descriptor: finished by finish_fdop */
	SC_FCHMOD, SC_FCHOWN, SC_FTRUNCATE, SC_MMAP,
	/* third optional tier */
	SC_SETXATTR, SC_LSETXATTR, SC_FSETXATTR, SC_REMOVEXATTR, SC_LREMOVEXATTR, SC_FREMOVEXATTR,
	SC_MKNOD, SC_MKNODAT, SC_MPROTECT,
	/* socket ops: everything from here on is finished by finish_connect */
	SC_CONNECT = 100, SC_BIND, SC_LISTEN, SC_ACCEPT, SC_SENDTO, SC_SENDMMSG,
};

struct pending_op {
	__u32 active;
	__u32 sc;
	__u32 op;
	__s32 dirfd;
	__s32 dirfd2;
	__u32 flags;
	__u32 mode;
	__u32 req_flags;
	__s32 fd;
	__u32 addrlen;
	__u8 addr[SOCKADDR_MAX];
	char path[PATHBUF];
	char path2[PATHBUF];
};

/* tid -> pending op; LRU hash for the same reason as req_store. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TID_SLOTS);
	__type(key, __u32);
	__type(value, struct pending_op);
} op_store SEC(".maps");

static __always_inline struct pending_op *begin(__u32 sc, __u32 op)
{
	if (!in_sandbox())
		return NULL;
	struct pending_op *p = tid_slot(&op_store);
	if (!p)
		return NULL;
	p->active = 1;
	p->sc = sc;
	p->op = op;
	p->dirfd = AT_FDCWD_;
	p->dirfd2 = AT_FDCWD_;
	p->flags = 0;
	p->mode = 0;
	p->req_flags = 0;
	p->fd = -1;
	p->addrlen = 0;
	p->path[0] = 0;
	p->path2[0] = 0;
	return p;
}

static __always_inline void copy_path(struct pending_op *p, char *dst, const char *src)
{
	if (bpf_probe_read_user_str(dst, PATHBUF, src) < 0) {
		dst[0] = 0;
		p->req_flags |= REQ_UNREADABLE;
	}
}

static __always_inline int stash_path(__u32 sc, __u32 op, __s32 dirfd, const char *path,
				      __u32 flags, __u32 mode)
{
	struct pending_op *p = begin(sc, op);
	if (!p)
		return 0;
	p->dirfd = dirfd;
	p->flags = flags;
	p->mode = mode;
	copy_path(p, p->path, path);
	return 0;
}

static __always_inline bool open_wanted(__u64 flags)
{
	return log_reads || (flags & O_ACCMODE_) != 0 || (flags & (O_CREAT_ | O_TRUNC_));
}

static __always_inline int stash_open(__u32 sc, __s32 dirfd, const char *path, __u64 flags, __u32 mode)
{
	/* With a watch list, read-only opens are stashed too and filtered at
	 * exit, once the kernel has resolved which file it was. */
	if (!open_wanted(flags) && !watch_reads)
		return 0;
	return stash_path(sc, FOP_OPEN, dirfd, path, (__u32)flags, mode);
}

/* Two-path ops: rename, link (old, new) and symlink (link path, target). */
static __always_inline int stash_two(__u32 sc, __u32 op, __s32 olddfd, const char *oldp,
				     __s32 newdfd, const char *newp, __u32 flags)
{
	struct pending_op *p = begin(sc, op);
	if (!p)
		return 0;
	p->dirfd = olddfd;
	p->dirfd2 = newdfd;
	p->flags = flags;
	copy_path(p, p->path, oldp);
	copy_path(p, p->path2, newp);
	return 0;
}

#define ARG(i) (ctx->args[i])
#define ENTER(name) SEC("tracepoint/syscalls/sys_enter_" #name) \
	int tp_enter_##name(struct trace_event_raw_sys_enter *ctx)
#define EXIT(name, id) SEC("tracepoint/syscalls/sys_exit_" #name) \
	int tp_exit_##name(struct trace_event_raw_sys_exit *ctx) { return finish(id, ctx->ret); }

ENTER(open)   { return stash_open(SC_OPEN, AT_FDCWD_, (const char *)ARG(0), ARG(1), ARG(2)); }
ENTER(creat)  { return stash_open(SC_CREAT, AT_FDCWD_, (const char *)ARG(0),
				  O_CREAT_ | O_WRONLY_ | O_TRUNC_, ARG(1)); }
ENTER(openat) { return stash_open(SC_OPENAT, ARG(0), (const char *)ARG(1), ARG(2), ARG(3)); }
ENTER(openat2)
{
	struct { __u64 flags, mode, resolve; } how = {};
	if (bpf_probe_read_user(&how, sizeof(how), (void *)ARG(2)))
		how.flags = O_WRONLY_; /* unreadable: log it rather than miss it */
	return stash_open(SC_OPENAT2, ARG(0), (const char *)ARG(1), how.flags, how.mode);
}

ENTER(unlink)   { return stash_path(SC_UNLINK, FOP_UNLINK, AT_FDCWD_, (const char *)ARG(0), 0, 0); }
ENTER(unlinkat) { return stash_path(SC_UNLINKAT, (ARG(2) & AT_REMOVEDIR_) ? FOP_RMDIR : FOP_UNLINK,
				    ARG(0), (const char *)ARG(1), ARG(2), 0); }
ENTER(rmdir)    { return stash_path(SC_RMDIR, FOP_RMDIR, AT_FDCWD_, (const char *)ARG(0), 0, 0); }

ENTER(rename)    { return stash_two(SC_RENAME, FOP_RENAME, AT_FDCWD_, (const char *)ARG(0), AT_FDCWD_,
					   (const char *)ARG(1), 0); }
ENTER(renameat)  { return stash_two(SC_RENAMEAT, FOP_RENAME, ARG(0), (const char *)ARG(1), ARG(2),
					   (const char *)ARG(3), 0); }
ENTER(renameat2) { return stash_two(SC_RENAMEAT2, FOP_RENAME, ARG(0), (const char *)ARG(1), ARG(2),
					   (const char *)ARG(3), ARG(4)); }

ENTER(mkdir)   { return stash_path(SC_MKDIR, FOP_MKDIR, AT_FDCWD_, (const char *)ARG(0), 0, ARG(1)); }
ENTER(mkdirat) { return stash_path(SC_MKDIRAT, FOP_MKDIR, ARG(0), (const char *)ARG(1), 0, ARG(2)); }

/* Optional hooks from here on (userspace can leave them unloaded). */
ENTER(link)      { return stash_two(SC_LINK, FOP_LINK, AT_FDCWD_, (const char *)ARG(0), AT_FDCWD_,
				    (const char *)ARG(1), 0); }
ENTER(linkat)    { return stash_two(SC_LINKAT, FOP_LINK, ARG(0), (const char *)ARG(1), ARG(2),
				    (const char *)ARG(3), ARG(4)); }
/* symlink: path = the link being created, path2 = its target text */
ENTER(symlink)   { return stash_two(SC_SYMLINK, FOP_SYMLINK, AT_FDCWD_, (const char *)ARG(1),
				    AT_FDCWD_, (const char *)ARG(0), 0); }
ENTER(symlinkat) { return stash_two(SC_SYMLINKAT, FOP_SYMLINK, ARG(1), (const char *)ARG(2),
				    AT_FDCWD_, (const char *)ARG(0), 0); }
ENTER(chmod)     { return stash_path(SC_CHMOD, FOP_CHMOD, AT_FDCWD_, (const char *)ARG(0), 0, ARG(1)); }
ENTER(fchmodat)  { return stash_path(SC_FCHMODAT, FOP_CHMOD, ARG(0), (const char *)ARG(1), 0, ARG(2)); }
/* chown: flags = uid, mode = gid */
ENTER(chown)     { return stash_path(SC_CHOWN, FOP_CHOWN, AT_FDCWD_, (const char *)ARG(0), ARG(1), ARG(2)); }
ENTER(lchown)    { return stash_path(SC_LCHOWN, FOP_CHOWN, AT_FDCWD_, (const char *)ARG(0), ARG(1), ARG(2)); }
ENTER(fchownat)  { return stash_path(SC_FCHOWNAT, FOP_CHOWN, ARG(0), (const char *)ARG(1), ARG(2), ARG(3)); }
/* truncate: flags = length (low 32 bits), mode = high 32 bits */
ENTER(truncate)  { return stash_path(SC_TRUNCATE, FOP_TRUNCATE, AT_FDCWD_, (const char *)ARG(0),
				     (__u32)ARG(1), (__u32)(ARG(1) >> 32)); }

static __always_inline int stash_addr(__u32 sc, __s32 fd, const void *addr, __u64 addrlen)
{
	struct pending_op *p = begin(sc, 0);
	if (!p)
		return 0;
	p->fd = fd;
	/* Clamp in a 64-bit register the compiler can't narrow: with a __u32 len,
	 * clang compares only the low half (the helper's size param is u32) but
	 * passes the full register, so the verifier sees an unbounded size and
	 * rejects the program with -EACCES. */
	__u64 len = (__u32)addrlen;
	barrier_var(len);
	if (len > SOCKADDR_MAX)
		len = SOCKADDR_MAX;
	p->addrlen = addrlen;
	if (bpf_probe_read_user(p->addr, len, addr))
		p->req_flags |= REQ_UNREADABLE;
	return 0;
}

static __always_inline int stash_fd(__u32 sc, __s32 fd)
{
	struct pending_op *p = begin(sc, 0);
	if (p)
		p->fd = fd;
	return 0;
}

ENTER(connect) { return stash_addr(SC_CONNECT, ARG(0), (const void *)ARG(1), ARG(2)); }
ENTER(bind)    { return stash_addr(SC_BIND, ARG(0), (const void *)ARG(1), ARG(2)); }
ENTER(listen)  { return stash_fd(SC_LISTEN, ARG(0)); }
ENTER(accept)  { return stash_fd(SC_ACCEPT, ARG(0)); }
ENTER(accept4) { return stash_fd(SC_ACCEPT, ARG(0)); }
/* Only sends that name a destination (unconnected UDP and friends). */
ENTER(sendto)
{
	if (!ARG(4))
		return 0;
	return stash_addr(SC_SENDTO, ARG(0), (const void *)ARG(4), ARG(5));
}

/* fd -> struct file *, via the task's fd table */
static __always_inline struct file *fd_file(struct task_struct *task, int fd)
{
	if (fd < 0)
		return NULL;
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	unsigned int max = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned int)fd >= max)
		return NULL;
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
	return f;
}

static __always_inline __u32 resolve_file(char buf[PATH_ARR], struct file *f, struct path *root)
{
	if (!f)
		return PATHBUF;
	struct path fp = {};
	bpf_core_read(&fp, sizeof(fp), &f->f_path);
	return resolve_path(buf, &fp, root);
}

static __always_inline __u32 resolve_dirfd(char buf[PATH_ARR], struct task_struct *task, __s32 dirfd,
					   struct path *pwd, struct path *root)
{
	if (dirfd == AT_FDCWD_)
		return resolve_path(buf, pwd, root);
	return resolve_file(buf, fd_file(task, dirfd), root);
}

static __always_inline int finish_connect(union scratch *s, struct pending_op *p,
					  struct task_struct *task, long ret)
{
	struct connect_event *e = &s->conn;
	fill_header(&e->h, EV_CONNECT);
	e->fd = p->fd;
	e->req_flags = p->req_flags;
	e->ret = ret;
	e->addrlen = p->addrlen;
	e->op = p->sc == SC_BIND ? NOP_BIND : p->sc == SC_LISTEN ? NOP_LISTEN :
		p->sc == SC_ACCEPT ? NOP_ACCEPT : p->sc == SC_SENDTO ? NOP_SENDTO :
		p->sc == SC_SENDMMSG ? NOP_SENDMMSG : NOP_CONNECT;
	e->local_port = 0;
	e->peer_family = 0;
	e->peer_port = 0;
	e->sock_type = 0;
	__builtin_memset(e->peer_addr, 0, sizeof(e->peer_addr));
	bpf_probe_read_kernel(e->req_addr, sizeof(e->req_addr), p->addr);

	/* accept: describe the new connection's socket, not the listener */
	struct file *f = fd_file(task, p->sc == SC_ACCEPT ? (int)ret : p->fd);
	if (f) {
		umode_t m = BPF_CORE_READ(f, f_inode, i_mode);
		if ((m & S_IFMT_) == S_IFSOCK_) {
			struct socket *sock = BPF_CORE_READ(f, private_data);
			struct sock *sk = BPF_CORE_READ(sock, sk);
			e->sock_type = BPF_CORE_READ(sock, type);
			e->peer_family = BPF_CORE_READ(sk, __sk_common.skc_family);
			e->peer_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
			e->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
			if (e->peer_family == 2 /* AF_INET */) {
				__u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
				__builtin_memcpy(e->peer_addr, &d, 4);
			} else if (e->peer_family == 10 /* AF_INET6 */) {
				bpf_core_read(e->peer_addr, 16, &sk->__sk_common.skc_v6_daddr);
			}
		}
	}
	submit(e, sizeof(*e));
	return 0;
}

static __always_inline int finish(__u32 sc, long ret)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct pending_op *p = tid_get(&op_store);
	if (!p || !p->active || p->sc != sc)
		return 0;
	p->active = 0;
	union scratch *s = scratch();
	if (!s)
		return 0;
	if (sc >= SC_CONNECT)
		return finish_connect(s, p, task, ret);

	/* A read-only open only got this far because of the watch list: report
	 * it if it succeeded and the file is under a watched name. */
	bool quiet_read = p->op == FOP_OPEN && !open_wanted(p->flags);
	if (quiet_read && (ret < 0 || !watch_match(fd_file(task, ret))))
		return 0;

	struct file_event *e = &s->file;
	fill_header(&e->h, EV_FILE);
	e->op = p->op;
	e->dirfd = p->dirfd;
	e->dirfd2 = p->dirfd2;
	e->flags = p->flags;
	e->mode = p->mode;
	e->req_flags = p->req_flags;
	e->ret = ret;
	e->watched = quiet_read;
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), p->path);
	bpf_probe_read_kernel_str(e->path2, sizeof(e->path2), p->path2);

	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->dir_off = resolve_dirfd(e->dir, task, p->dirfd, &pwd, &root);
	e->dir2_off = (p->op == FOP_RENAME || p->op == FOP_LINK)
			      ? resolve_dirfd(e->dir2, task, p->dirfd2, &pwd, &root)
			      : PATHBUF;
	e->actual_off = PATHBUF;
	if (p->op == FOP_OPEN && ret >= 0)
		e->actual_off = resolve_file(e->actual, fd_file(task, ret), &root);

	submit(e, sizeof(*e));
	return 0;
}

EXIT(open, SC_OPEN)
EXIT(creat, SC_CREAT)
EXIT(openat, SC_OPENAT)
EXIT(openat2, SC_OPENAT2)
EXIT(unlink, SC_UNLINK)
EXIT(unlinkat, SC_UNLINKAT)
EXIT(rmdir, SC_RMDIR)
EXIT(rename, SC_RENAME)
EXIT(renameat, SC_RENAMEAT)
EXIT(renameat2, SC_RENAMEAT2)
EXIT(mkdir, SC_MKDIR)
EXIT(mkdirat, SC_MKDIRAT)
EXIT(connect, SC_CONNECT)
EXIT(link, SC_LINK)
EXIT(linkat, SC_LINKAT)
EXIT(symlink, SC_SYMLINK)
EXIT(symlinkat, SC_SYMLINKAT)
EXIT(chmod, SC_CHMOD)
EXIT(fchmodat, SC_FCHMODAT)
EXIT(chown, SC_CHOWN)
EXIT(lchown, SC_LCHOWN)
EXIT(fchownat, SC_FCHOWNAT)
EXIT(truncate, SC_TRUNCATE)
EXIT(bind, SC_BIND)
EXIT(listen, SC_LISTEN)
EXIT(accept, SC_ACCEPT)
EXIT(accept4, SC_ACCEPT)
EXIT(sendto, SC_SENDTO)

/* -------------------------------------------------- ops on an open fd
 *
 * Second optional tier. fchmod/fchown/ftruncate change a file through a
 * descriptor, and mmap(PROT_EXEC) of a file is how code gets loaded without
 * an exec (dlopen, LD_PRELOAD, native extensions). There is no path
 * argument: the record carries the path the kernel resolves for the fd.
 */
#define PROT_EXEC_ 0x4
#define MAP_ANONYMOUS_ 0x20
#define MNT_READONLY_ 0x40

static __always_inline int stash_fdop(__u32 sc, __u32 op, __s32 fd, __u32 flags, __u32 mode)
{
	struct pending_op *p = begin(sc, op);
	if (!p)
		return 0;
	p->fd = fd;
	p->flags = flags;
	p->mode = mode;
	return 0;
}

ENTER(fchmod)    { return stash_fdop(SC_FCHMOD, FOP_CHMOD, ARG(0), 0, ARG(1)); }
ENTER(fchown)    { return stash_fdop(SC_FCHOWN, FOP_CHOWN, ARG(0), ARG(1), ARG(2)); }
ENTER(ftruncate) { return stash_fdop(SC_FTRUNCATE, FOP_TRUNCATE, ARG(0), (__u32)ARG(1),
				     (__u32)(ARG(1) >> 32)); }
ENTER(mmap)
{
	if (!(ARG(2) & PROT_EXEC_) || (ARG(3) & MAP_ANONYMOUS_))
		return 0;
	return stash_fdop(SC_MMAP, FOP_EXEC_MAP, ARG(4), ARG(2), 0);
}

static __always_inline int finish_fdop(__u32 sc, long ret)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct pending_op *p = tid_get(&op_store);
	if (!p || !p->active || p->sc != sc)
		return 0;
	p->active = 0;
	struct file *f = fd_file(task, p->fd);
	if (!f)
		return 0;
	if (sc == SC_MMAP) {
		/* Failed, or from a read-only mount: the host's own system
		 * libraries, mapped by every exec. What's worth a record is code
		 * loaded from somewhere the agent can write. */
		if (ret < 0 && ret >= -4095)
			return 0;
		int mflags = BPF_CORE_READ(f, f_path.mnt, mnt_flags);
		if (mflags & MNT_READONLY_)
			return 0;
	}
	union scratch *s = scratch();
	if (!s)
		return 0;
	struct file_event *e = &s->file;
	fill_header(&e->h, EV_FILE);
	e->op = p->op;
	e->dirfd = p->fd;
	e->dirfd2 = AT_FDCWD_;
	e->flags = p->flags;
	e->mode = p->mode;
	e->req_flags = 0;
	e->ret = sc == SC_MMAP ? 0 : ret;
	e->watched = 0;
	e->path[0] = 0;
	e->path2[0] = 0;
	e->dir_off = PATHBUF;
	e->dir2_off = PATHBUF;
	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->actual_off = resolve_file(e->actual, f, &root);
	submit(e, sizeof(*e));
	return 0;
}

#define EXIT_FD(name, id) SEC("tracepoint/syscalls/sys_exit_" #name) \
	int tp_exit_##name(struct trace_event_raw_sys_exit *ctx) { return finish_fdop(id, ctx->ret); }

EXIT_FD(fchmod, SC_FCHMOD)
EXIT_FD(fchown, SC_FCHOWN)
EXIT_FD(ftruncate, SC_FTRUNCATE)
EXIT_FD(mmap, SC_MMAP)

/* sendmsg that names a destination: same record as sendto. */
ENTER(sendmsg)
{
	struct {
		void *name;
		int namelen;
	} mh = {};
	if (bpf_probe_read_user(&mh, sizeof(mh), (void *)ARG(1)) || !mh.name || mh.namelen <= 0)
		return 0;
	return stash_addr(SC_SENDTO, ARG(0), mh.name, mh.namelen);
}
EXIT(sendmsg, SC_SENDTO)

/* ------------------------------------------------- third optional tier
 *
 * Extended attributes, device nodes, sendmmsg, and mprotect() turning a
 * file mapping executable (the other way to load code without an exec).
 */
ENTER(setxattr)     { return stash_two(SC_SETXATTR, FOP_XATTR, AT_FDCWD_, (const char *)ARG(0),
				       AT_FDCWD_, (const char *)ARG(1), 0); }
ENTER(lsetxattr)    { return stash_two(SC_LSETXATTR, FOP_XATTR, AT_FDCWD_, (const char *)ARG(0),
				       AT_FDCWD_, (const char *)ARG(1), 0); }
ENTER(removexattr)  { return stash_two(SC_REMOVEXATTR, FOP_XATTR, AT_FDCWD_, (const char *)ARG(0),
				       AT_FDCWD_, (const char *)ARG(1), 1); }
ENTER(lremovexattr) { return stash_two(SC_LREMOVEXATTR, FOP_XATTR, AT_FDCWD_, (const char *)ARG(0),
				       AT_FDCWD_, (const char *)ARG(1), 1); }
/* By fd: the record has the file, not the attribute name. */
ENTER(fsetxattr)    { return stash_fdop(SC_FSETXATTR, FOP_XATTR, ARG(0), 0, 0); }
ENTER(fremovexattr) { return stash_fdop(SC_FREMOVEXATTR, FOP_XATTR, ARG(0), 1, 0); }
EXIT(setxattr, SC_SETXATTR)
EXIT(lsetxattr, SC_LSETXATTR)
EXIT(removexattr, SC_REMOVEXATTR)
EXIT(lremovexattr, SC_LREMOVEXATTR)
EXIT_FD(fsetxattr, SC_FSETXATTR)
EXIT_FD(fremovexattr, SC_FREMOVEXATTR)

ENTER(mknod)   { return stash_path(SC_MKNOD, FOP_MKNOD, AT_FDCWD_, (const char *)ARG(0), ARG(2), ARG(1)); }
ENTER(mknodat) { return stash_path(SC_MKNODAT, FOP_MKNOD, ARG(0), (const char *)ARG(1), ARG(3), ARG(2)); }
EXIT(mknod, SC_MKNOD)
EXIT(mknodat, SC_MKNODAT)

/* The first message's destination stands for the batch. */
ENTER(sendmmsg)
{
	struct {
		void *name;
		int namelen;
	} mh = {};
	if (bpf_probe_read_user(&mh, sizeof(mh), (void *)ARG(1)) || !mh.name || mh.namelen <= 0)
		return 0;
	return stash_addr(SC_SENDMMSG, ARG(0), mh.name, mh.namelen);
}
EXIT(sendmmsg, SC_SENDMMSG)

/* mprotect(PROT_EXEC): the address is kept in flags (low) and mode (high). */
ENTER(mprotect)
{
	if (!(ARG(2) & PROT_EXEC_))
		return 0;
	struct pending_op *p = begin(SC_MPROTECT, FOP_EXEC_MAP);
	if (!p)
		return 0;
	p->flags = (__u32)ARG(0);
	p->mode = (__u32)(ARG(0) >> 32);
	return 0;
}

struct vma_ctx {
	struct file *file;
};

static long vma_file_cb(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	struct vma_ctx *c = data;
	c->file = vma->vm_file;
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_mprotect")
int tp_exit_mprotect(struct trace_event_raw_sys_exit *ctx)
{
	if (ctx->ret != 0 || !in_sandbox())
		return 0;
	struct pending_op *p = tid_get(&op_store);
	if (!p || !p->active || p->sc != SC_MPROTECT)
		return 0;
	p->active = 0;
	struct task_struct *task = bpf_get_current_task_btf();
	__u64 addr = p->flags | ((__u64)p->mode << 32);
	struct vma_ctx c = {};
	bpf_find_vma(task, addr, vma_file_cb, &c, 0);
	/* Anonymous memory (every JIT does this) has no file: not a record. */
	struct file *f = c.file;
	if (!f)
		return 0;
	int mflags = BPF_CORE_READ(f, f_path.mnt, mnt_flags);
	if (mflags & MNT_READONLY_)
		return 0;
	union scratch *s = scratch();
	if (!s)
		return 0;
	struct file_event *e = &s->file;
	fill_header(&e->h, EV_FILE);
	e->op = FOP_EXEC_MAP;
	e->dirfd = -1;
	e->dirfd2 = AT_FDCWD_;
	e->flags = 0;
	e->mode = 1; /* via mprotect */
	e->req_flags = 0;
	e->ret = 0;
	e->watched = 0;
	e->path[0] = 0;
	e->path2[0] = 0;
	e->dir_off = PATHBUF;
	e->dir2_off = PATHBUF;
	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->actual_off = resolve_file(e->actual, f, &root);
	submit(e, sizeof(*e));
	return 0;
}

/* ------------------------------------------------------ process lifecycle */

/* One record per process, when its last thread exits. */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(void *ctx)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, signal, live.counter) != 0)
		return 0;
	struct exit_event e = {};
	fill_header(&e.h, EV_EXIT);
	bpf_get_current_comm(e.comm, sizeof(e.comm));
	e.exit_code = BPF_CORE_READ(task, exit_code);
	e.start_boot_ns = BPF_CORE_READ(task, start_boottime);
	submit(&e, sizeof(e));
	return 0;
}

/* New processes (threads are skipped), so the tree has no gaps between
 * execs. Runs in the parent. */
SEC("raw_tracepoint/sched_process_fork")
int rtp_sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	__u32 pid = BPF_CORE_READ(child, pid), tgid = BPF_CORE_READ(child, tgid);
	if (pid != tgid)
		return 0;
	struct fork_event e = {};
	fill_header(&e.h, EV_FORK);
	e.child_pid = tgid;
	struct pid *p = BPF_CORE_READ(child, thread_pid);
	unsigned int level = BPF_CORE_READ(p, level);
	struct upid up = {};
	bpf_core_read(&up, sizeof(up), &p->numbers[level & 31]);
	e.child_ns_pid = up.nr;
	submit(&e, sizeof(e));
	return 0;
}

/* Privileged syscalls (mount, ptrace, bpf, setuid, ...) that the sandbox
 * refused: an agent probing its limits. Cheap for everything else: the
 * return value is checked before anything is looked up. */
SEC("tracepoint/raw_syscalls/sys_exit")
int tp_sys_denied(struct trace_event_raw_sys_exit *ctx)
{
	long ret = ctx->ret;
	if (ret != -1 /* EPERM */ && ret != -13 /* EACCES */ && ret != -38 /* ENOSYS */)
		return 0;
	if (!in_sandbox())
		return 0;
	__u32 nr = ctx->id;
	if (!bpf_map_lookup_elem(&watch_sys, &nr))
		return 0;
	struct sys_denied_event e = {};
	fill_header(&e.h, EV_SYS_DENIED);
	bpf_get_current_comm(e.comm, sizeof(e.comm));
	e.nr = nr;
	e.ret = ret;
	submit(&e, sizeof(e));
	return 0;
}

/* ===================================================================== LSM
 *
 * Preferred file/network audit. LSM hooks fire inside the VFS and socket
 * layers on kernel-resolved objects, whatever the entry path: plain
 * syscalls, io_uring (inline in io_uring_enter or on io-wq worker threads),
 * or anything else. Arguments are kernel copies, so there's nothing for the
 * caller to race.
 *
 * Hooks run *before* the operation completes, so the outcome is reported
 * separately: the hook marks the task, and the next raw sys_exit on that
 * task emits an EV_OP_RESULT. io_uring work is flagged async (the syscall's
 * return value isn't the op's result).
 *
 * LSM programs can be preempted on PREEMPT kernels, so all scratch here is
 * per-task, never per-CPU.
 */

#define PF_IO_WORKER_ 0x00000010
#define NR_IO_URING_ENTER 426 /* same on x86_64 and asm-generic (arm64) */
#define FMODE_WRITE_ 0x2

union lsm_scratch {
	struct lsm_file_event file;
	struct lsm_net_event net;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, union lsm_scratch);
} lsm_store SEC(".maps");

struct lsm_pending {
	__u32 pending;
	__u32 nr;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lsm_pending);
} lsm_pend SEC(".maps");

static __always_inline __u32 current_syscall(struct task_struct *task, __u32 *async)
{
	unsigned int tflags = BPF_CORE_READ(task, flags);
	if (tflags & PF_IO_WORKER_) {
		*async = 1;
		return SYSCALL_NONE;
	}
	struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
#if defined(__TARGET_ARCH_arm64)
	__u64 nr = BPF_CORE_READ(regs, syscallno);
#else
	__u64 nr = BPF_CORE_READ(regs, orig_ax);
#endif
	*async = nr == NR_IO_URING_ENTER;
	return (__u32)nr;
}

static __always_inline void mark_pending(struct task_struct *task, __u32 async, __u32 nr)
{
	if (async)
		return;
	struct lsm_pending *pd = bpf_task_storage_get(&lsm_pend, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (pd) {
		pd->pending = 1;
		pd->nr = nr;
	}
}

static __always_inline struct lsm_file_event *file_begin(struct task_struct *task, __u32 op)
{
	union lsm_scratch *s = bpf_task_storage_get(&lsm_store, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return NULL;
	struct lsm_file_event *e = &s->file;
	fill_header(&e->h, EV_LSM_FILE);
	e->op = op;
	e->async = 0;
	e->syscall_nr = current_syscall(task, &e->async);
	e->flags = 0;
	e->fmode = 0;
	e->mode = 0;
	e->uid = 0;
	e->gid = 0;
	e->has_request = 0;
	e->path_off = PATHBUF;
	e->path2_off = PATHBUF;
	e->req_dir_off = PATHBUF;
	e->req_path[0] = 0;
	return e;
}

/* Path of (mnt, dentry): works for negative dentries too (mkdir, rename target). */
static __always_inline __u32 resolve_dentry(char buf[PATH_ARR], struct vfsmount *mnt,
					    struct dentry *dentry, struct path *root)
{
	struct path p = { .mnt = mnt, .dentry = dentry };
	return resolve_path(buf, &p, root);
}

/* If this hook runs inside a syscall whose entry we stashed, attach what the
 * caller asked for (name + what its dirfd/cwd resolved to). */
static __always_inline void attach_request(struct lsm_file_event *e, struct task_struct *task,
					   struct path *pwd, struct path *root)
{
	if (e->async)
		return;
	struct pending_op *p = tid_get(&op_store);
	if (!p || !p->active || p->op != e->op)
		return;
	e->has_request = 1;
	bpf_probe_read_kernel_str(e->req_path, sizeof(e->req_path), p->path);
	e->req_dir_off = resolve_dirfd(e->req_dir, task, p->dirfd, pwd, root);
}

static __always_inline int file_end(struct lsm_file_event *e, struct task_struct *task)
{
	submit(e, sizeof(*e));
	mark_pending(task, e->async, e->syscall_nr);
	return 0;
}

/* Common shape for hooks on (dir, dentry). */
static __always_inline int dir_dentry_hook(__u32 op, const struct path *dir, struct dentry *dentry,
					   __u32 mode)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct lsm_file_event *e = file_begin(task, op);
	if (!e)
		return 0;
	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->mode = mode;
	e->path_off = resolve_dentry(e->path, BPF_CORE_READ(dir, mnt), dentry, &root);
	attach_request(e, task, &pwd, &root);
	return file_end(e, task);
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
	if (!in_sandbox())
		return 0;
	__u32 fmode = BPF_CORE_READ(file, f_mode);
	if (!log_reads && !(fmode & FMODE_WRITE_))
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct lsm_file_event *e = file_begin(task, FOP_OPEN);
	if (!e)
		return 0;
	struct path root = {}, pwd = {}, fp = {};
	task_paths(task, &root, &pwd);
	e->fmode = fmode;
	e->flags = BPF_CORE_READ(file, f_flags);
	bpf_core_read(&fp, sizeof(fp), &file->f_path);
	e->path_off = resolve_path(e->path, &fp, &root);
	attach_request(e, task, &pwd, &root);
	return file_end(e, task);
}

SEC("lsm/path_unlink")
int BPF_PROG(lsm_path_unlink, const struct path *dir, struct dentry *dentry)
{
	return dir_dentry_hook(FOP_UNLINK, dir, dentry, 0);
}

SEC("lsm/path_rmdir")
int BPF_PROG(lsm_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	return dir_dentry_hook(FOP_RMDIR, dir, dentry, 0);
}

SEC("lsm/path_mkdir")
int BPF_PROG(lsm_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	return dir_dentry_hook(FOP_MKDIR, dir, dentry, mode);
}

SEC("lsm/path_rename")
int BPF_PROG(lsm_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct lsm_file_event *e = file_begin(task, FOP_RENAME);
	if (!e)
		return 0;
	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->flags = flags;
	e->path_off = resolve_dentry(e->path, BPF_CORE_READ(old_dir, mnt), old_dentry, &root);
	e->path2_off = resolve_dentry(e->path2, BPF_CORE_READ(new_dir, mnt), new_dentry, &root);
	attach_request(e, task, &pwd, &root);
	return file_end(e, task);
}

SEC("lsm/path_link")
int BPF_PROG(lsm_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct lsm_file_event *e = file_begin(task, FOP_LINK);
	if (!e)
		return 0;
	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	/* Hard links can't cross mounts, so the old dentry is on new_dir's mount. */
	struct vfsmount *mnt = BPF_CORE_READ(new_dir, mnt);
	e->path_off = resolve_dentry(e->path, mnt, old_dentry, &root);
	e->path2_off = resolve_dentry(e->path2, mnt, new_dentry, &root);
	return file_end(e, task);
}

SEC("lsm/path_symlink")
int BPF_PROG(lsm_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct lsm_file_event *e = file_begin(task, FOP_SYMLINK);
	if (!e)
		return 0;
	struct path root = {}, pwd = {};
	task_paths(task, &root, &pwd);
	e->path_off = resolve_dentry(e->path, BPF_CORE_READ(dir, mnt), dentry, &root);
	/* The link body, as the kernel will store it. */
	e->path2_off = PATH2_CSTR;
	bpf_probe_read_kernel_str(e->path2, PATHBUF, old_name);
	return file_end(e, task);
}

static __always_inline int path_attr_hook(__u32 op, const struct path *path, __u32 mode,
					  __u32 uid, __u32 gid)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct lsm_file_event *e = file_begin(task, op);
	if (!e)
		return 0;
	struct path root = {}, p = {};
	struct path pwd = {};
	task_paths(task, &root, &pwd);
	bpf_core_read(&p, sizeof(p), path);
	e->mode = mode;
	e->uid = uid;
	e->gid = gid;
	e->path_off = resolve_path(e->path, &p, &root);
	return file_end(e, task);
}

SEC("lsm/path_chmod")
int BPF_PROG(lsm_path_chmod, const struct path *path, umode_t mode)
{
	return path_attr_hook(FOP_CHMOD, path, mode, 0, 0);
}

/* kuid_t/kgid_t are one-word structs passed by value. */
SEC("lsm/path_chown")
int BPF_PROG(lsm_path_chown, const struct path *path, __u64 uid, __u64 gid)
{
	return path_attr_hook(FOP_CHOWN, path, 0, (__u32)uid, (__u32)gid);
}

SEC("lsm/path_truncate")
int BPF_PROG(lsm_path_truncate, const struct path *path)
{
	return path_attr_hook(FOP_TRUNCATE, path, 0, 0, 0);
}

/* ------------------------------------------------------------- LSM: net */

static __always_inline int net_hook(__u32 op, struct socket *sock, const void *addr, int addrlen)
{
	if (!in_sandbox() || !addr || addrlen <= 0)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	union lsm_scratch *s = bpf_task_storage_get(&lsm_store, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return 0;
	struct lsm_net_event *e = &s->net;
	fill_header(&e->h, EV_LSM_NET);
	e->op = op;
	e->async = 0;
	e->syscall_nr = current_syscall(task, &e->async);
	e->sock_type = BPF_CORE_READ(sock, type);
	e->addrlen = addrlen;
	e->_pad = 0;
	__u64 len = (__u32)addrlen; /* 64-bit clamp: see tp_enter_connect */
	barrier_var(len);
	if (len > SOCKADDR_MAX)
		len = SOCKADDR_MAX;
	__builtin_memset(e->addr, 0, sizeof(e->addr));
	bpf_probe_read_kernel(e->addr, len, addr);
	submit(e, sizeof(*e));
	mark_pending(task, e->async, e->syscall_nr);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	return net_hook(NOP_CONNECT, sock, address, addrlen);
}

SEC("lsm/socket_bind")
int BPF_PROG(lsm_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
	return net_hook(NOP_BIND, sock, address, addrlen);
}

/* Only sends that name a destination (unconnected UDP etc.); a plain TCP
 * send has msg_name == NULL and costs one cgroup check. */
SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	if (!in_sandbox())
		return 0;
	void *name = BPF_CORE_READ(msg, msg_name);
	int namelen = BPF_CORE_READ(msg, msg_namelen);
	return net_hook(NOP_SENDTO, sock, name, namelen);
}

/* ----------------------------------------------------- LSM: op results */

SEC("tracepoint/raw_syscalls/sys_exit")
int tp_raw_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!in_sandbox())
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	/* The syscall-entry stash only lives for one syscall. */
	struct pending_op *op = tid_get(&op_store);
	if (op)
		op->active = 0;
	struct lsm_pending *pd = bpf_task_storage_get(&lsm_pend, task, 0, 0);
	if (!pd || !pd->pending)
		return 0;
	pd->pending = 0;
	struct op_result_event r = {};
	fill_header(&r.h, EV_OP_RESULT);
	r.syscall_nr = ctx->id;
	r.ret = ctx->ret;
	submit(&r, sizeof(r));
	return 0;
}
