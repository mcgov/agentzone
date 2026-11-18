/* Event layouts shared between the BPF program and userspace (src/events.rs).
 * Every field is naturally aligned and padded explicitly so the Rust mirror
 * is a straight #[repr(C)] copy. Keep the two files in sync. */
#ifndef AGENTBOX_EVENTS_H
#define AGENTBOX_EVENTS_H

#define TASK_COMM_LEN 16
#define FILENAME_LEN 4096      /* requested path as passed to execve       */
#define ARGBUF 8192            /* argv / envp bytes captured per exec       */
#define ARG_MAX_ONE 4096       /* max bytes read for one argv element       */
#define PATHBUF 4096           /* resolved path (cwd, exe) region            */
#define NAME_MAX_ 255
#define MAX_ARGS 128
#define MAX_PATH_DEPTH 64

/* exec_request_event.req_flags */
#define REQ_TRUNCATED  0x1 /* argv longer than captured                   */
#define REQ_UNREADABLE 0x2 /* a user page could not be read (fallback mode) */
#define REQ_SLEEPABLE  0x4 /* captured by the sleepable (faulting) path     */

enum event_kind {
	EV_EXEC_REQUEST = 1, /* sys_enter_execve/execveat: what the caller asked for */
	EV_EXEC = 2,         /* sched_process_exec: what the kernel actually loaded   */
	EV_EXEC_RESULT = 3,  /* sys_exit_execve/execveat with ret < 0                 */
	EV_FILE = 4,         /* file op: request at entry + resolved target at exit   */
	EV_CONNECT = 5,      /* connect: requested sockaddr + socket's actual peer    */
	EV_LSM_FILE = 6,     /* LSM hook: file op on kernel-resolved objects          */
	EV_LSM_NET = 7,      /* LSM hook: connect/bind/sendto with kernel sockaddr    */
	EV_OP_RESULT = 8,    /* syscall return for the LSM events just emitted        */
	EV_EXEC_DENIED = 9,  /* bprm_check_security refused a --deny'd binary        */
	EV_EXIT = 10,        /* sched_process_exit: a process (last thread) ended     */
	EV_FORK = 11,        /* sched_process_fork: a new process (not thread)        */
	EV_SYS_DENIED = 12,  /* a privileged syscall failed (EPERM/EACCES/ENOSYS)     */
};

/* --deny enforcement (rodata deny_mode) */
#define DENY_OFF 0
#define DENY_LSM 1  /* lsm/bprm_check_security returns -EACCES: execve fails   */
#define DENY_KILL 2 /* sched_process_exec sends SIGKILL before any user code   */

/* Which rule matched (exec_event.denied, exec_denied_event.rule) */
#define DENY_BY_INODE 1
#define DENY_BY_NAME 2

struct deny_ino_key {
	__u64 dev; /* super_block->s_dev (kernel dev_t encoding) */
	__u64 ino;
};

enum file_op {
	FOP_OPEN = 1,
	FOP_UNLINK = 2,
	FOP_RMDIR = 3,
	FOP_RENAME = 4,
	FOP_MKDIR = 5,
	FOP_LINK = 6,
	FOP_SYMLINK = 7,
	FOP_CHMOD = 8,
	FOP_CHOWN = 9,
	FOP_TRUNCATE = 10,
	FOP_EXEC_MAP = 11, /* mmap(PROT_EXEC) of a file on a writable mount; mode = 1
			    * when it became executable through mprotect instead */
	FOP_XATTR = 12,    /* path2 = attribute name; flags = 1 for remove      */
	FOP_MKNOD = 13,    /* mode = type + permissions, flags = device number  */
};

#define DROP_KINDS 16 /* drop counters, indexed by event kind */

enum net_op {
	NOP_CONNECT = 1,
	NOP_BIND = 2,
	NOP_SENDTO = 3, /* sendmsg/sendto with an explicit destination */
	NOP_LISTEN = 4,
	NOP_ACCEPT = 5,
	NOP_SENDMMSG = 6, /* like NOP_SENDTO, but ret counts messages, not bytes */
};

#define SYSCALL_NONE 0xffffffffu /* not in a syscall (io_uring worker thread)  */
#define PATH2_CSTR 0xffffffffu   /* path2 holds a plain C string (symlink body) */

#define PATH_ARR (PATHBUF + NAME_MAX_ + 1)
#define SOCKADDR_MAX 128

/* Common 40-byte header at the start of every event. */
struct ev_header {
	__u32 kind;
	__u32 tid;       /* host tid of the task that emitted the event       */
	__u32 pid;       /* host tgid                                          */
	__u32 ppid;      /* host tgid of real parent                           */
	__u32 ns_pid;    /* pid as seen inside the sandbox's pid namespace     */
	__u32 uid;
	__u32 gid;
	__u32 _pad0;
	__u64 ts_boot_ns;/* bpf_ktime_get_boot_ns()                            */
};

struct exec_request_event {
	struct ev_header h;
	char comm[TASK_COMM_LEN];
	__s32 dirfd;         /* execveat dirfd, AT_FDCWD (-100) for execve     */
	__u32 flags;         /* execveat flags                                  */
	__u32 is_execveat;
	__u32 argc;          /* number of argv elements captured               */
	__u32 argv_len;      /* bytes used in argv[], NUL separated            */
	__u32 req_flags;      /* REQ_* bits */
	__u32 cwd_off;
	__u32 _pad1;
	char filename[FILENAME_LEN];
	char argv[ARGBUF + ARG_MAX_ONE];
	char cwd[PATHBUF + NAME_MAX_ + 1];
};

struct exec_event {
	struct ev_header h;
	char comm[TASK_COMM_LEN];
	__u32 old_tid;       /* tid that called execve (pre-exec)              */
	__u32 argv_len;
	__u32 argv_truncated;
	__u32 env_len;
	__u32 env_truncated;
	__u32 exe_off;       /* exe path lives at exe[exe_off .. PATHBUF)      */
	__u32 cwd_off;       /* cwd path lives at cwd[cwd_off .. PATHBUF)      */
	__u32 denied;        /* DENY_BY_*: killed by --deny (DENY_KILL mode)    */
	char filename[FILENAME_LEN]; /* bprm->filename                          */
	char argv[ARGBUF];   /* copied from the NEW mm: arg_start..arg_end      */
	char env[ARGBUF];    /* new mm env_start..env_end (only if capture_env) */
	char exe[PATH_ARR];
	char cwd[PATH_ARR];
};

struct exec_result_event {
	struct ev_header h;
	__s64 ret;
};

struct file_event {
	struct ev_header h;
	__u32 op;            /* enum file_op                                     */
	__s32 dirfd;         /* as passed; AT_FDCWD (-100) for non-*at syscalls  */
	__s32 dirfd2;        /* rename: new dirfd                                */
	__u32 flags;         /* open flags / rename flags                        */
	__u32 mode;          /* open(O_CREAT) / mkdir mode                       */
	__u32 req_flags;     /* REQ_UNREADABLE                                    */
	__s64 ret;
	__u32 dir_off;       /* dir[]: what dirfd (or cwd) resolved to           */
	__u32 dir2_off;      /* dir2[]: same for rename's new dirfd              */
	__u32 actual_off;    /* actual[]: open only, path of the fd returned     */
	__u32 watched;       /* read-only open reported because of the watch list */
	char path[PATHBUF];  /* requested path (old path for rename)             */
	char path2[PATHBUF]; /* rename: requested new path                       */
	char dir[PATH_ARR];
	char dir2[PATH_ARR];
	char actual[PATH_ARR];
};

struct connect_event {
	struct ev_header h;
	__s32 fd;
	__u32 req_flags;
	__s64 ret;
	__u32 addrlen;
	__u16 peer_family;   /* from the kernel socket after connect             */
	__u16 peer_port;     /* network byte order                               */
	__u32 sock_type;     /* SOCK_STREAM / SOCK_DGRAM / ...                    */
	__u16 op;            /* enum net_op (0 = connect)                        */
	__u16 local_port;    /* socket's local port, host byte order             */
	__u8 peer_addr[16];  /* v4 in first 4 bytes, or v6                       */
	__u8 req_addr[SOCKADDR_MAX]; /* sockaddr as passed by the caller         */
};

struct lsm_file_event {
	struct ev_header h;
	__u32 op;            /* enum file_op                                     */
	__u32 syscall_nr;    /* syscall the hook fired under, or SYSCALL_NONE    */
	__u32 flags;         /* open: f_flags; rename: flags                     */
	__u32 fmode;         /* open: f_mode (FMODE_WRITE, FMODE_CREATED, ...)    */
	__u32 mode;          /* mkdir/chmod                                      */
	__u32 uid;           /* chown                                            */
	__u32 gid;
	__u32 async;         /* io_uring: no syscall result will follow          */
	__u32 path_off;      /* path[]: the object, resolved by the kernel        */
	__u32 path2_off;     /* path2[]: rename/link destination, or PATH2_CSTR  */
	__u32 req_dir_off;   /* req_dir[]: dirfd/cwd of the request              */
	__u32 has_request;   /* req_path/req_dir valid (syscall-entry stash hit)  */
	char path[PATH_ARR];
	char path2[PATH_ARR];
	char req_path[PATHBUF];
	char req_dir[PATH_ARR];
};

struct lsm_net_event {
	struct ev_header h;
	__u32 op;            /* enum net_op                                      */
	__u32 syscall_nr;
	__u32 async;
	__u32 sock_type;
	__u32 addrlen;
	__u32 _pad;
	__u8 addr[SOCKADDR_MAX]; /* kernel's copy of the sockaddr               */
};

struct op_result_event {
	struct ev_header h;
	__u32 syscall_nr;
	__u32 _pad;
	__s64 ret;
};

/* An exec refused by --deny (DENY_LSM mode). Emitted once per binary the
 * kernel tried to load: for a #! script that may be the script or its
 * interpreter. */
struct exec_denied_event {
	struct ev_header h;
	char comm[TASK_COMM_LEN];
	__u32 rule;          /* DENY_BY_*                                        */
	__u32 exe_off;       /* exe[]: path of the refused file                  */
	char name[NAME_MAX_ + 1]; /* its dentry name (what name rules match)     */
	char exe[PATH_ARR];
};

struct exit_event {
	struct ev_header h;
	char comm[TASK_COMM_LEN];
	__u32 exit_code;     /* wait status: (status << 8) | signal              */
	__u32 _pad;
	__u64 start_boot_ns; /* when the process started (boot clock)            */
};

struct fork_event {
	struct ev_header h;  /* the parent                                       */
	__u32 child_pid;     /* host tgid of the new process                     */
	__u32 child_ns_pid;
};

struct sys_denied_event {
	struct ev_header h;
	char comm[TASK_COMM_LEN];
	__u32 nr;            /* syscall number                                   */
	__u32 _pad;
	__s64 ret;
};

#endif
