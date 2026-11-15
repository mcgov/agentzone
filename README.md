# agentbox

Run an agent harness in a copy-on-write view of a project, with the kernel
recording what it does: every `execve` (what ran, from where, and the argv the
kernel *actually loaded*, not just the shell string), every file it writes,
deletes, renames or creates, and every `connect`.

```
sudo agentbox run -p ~/src/myrepo -- claude
sudo agentbox run -p . --no-network -- sh -c 'make test'
agentbox diff /var/tmp/agentbox/myrepo-1763172750-4242
```

## What it does

**Filesystem view.** The agent gets a fresh mount namespace whose root is a
read-only tmpfs containing:

| path | what |
|---|---|
| `/usr /bin /lib* /etc /opt …` | read-only (recursive) binds of the host |
| project (at its host path, or `--mount-at`) | **overlayfs**: reads hit the real tree, every write lands in `<state>/upper` |
| `/tmp`, `/dev/shm` | private tmpfs |
| `$HOME` | `/home/agent`, a private tmpfs owned by the agent uid; or with `--home-from DIR` an **overlay** of `DIR` at its host path (or `--home-at`), writes landing in `<state>/home/upper` |
| `/dev` | `null zero full random urandom tty`, own devpts |
| `/proc` | for the sandbox's own pid namespace |
| `/sys` | read-only |

Everything else on the host (`/root`, `/var`, other users' homes…) simply
doesn't exist. The agent runs as an unprivileged uid (`$SUDO_UID` by default)
with `no_new_privs`, so setuid binaries like `sudo` can't escalate. It also gets
its own pid/ipc/uts/cgroup namespaces and, with `--no-network`, an empty network
namespace. When the agent exits, the pid namespace and cgroup are torn down, so
background daemons it started die with it.

Nothing else under `/home` is visible, so tools installed in your home
(`~/.local/bin/claude`, its login in `~/.claude*`) aren't there by default.
`--home-from ~` mounts a copy-on-write view of your home at its real path
(so absolute symlinks like `~/.local/bin/claude -> ~/.local/share/...` still
resolve) and points `$HOME` there: the agent can
read your dotfiles and run what's installed there, and anything it writes
(sessions, config, a fresh login) goes to the state dir, not your real home.
That includes your secrets (`~/.ssh`, cloud credentials), so a trimmed template
dir is safer. Note that `$PATH` comes from the caller and `sudo` usually resets
it, so give the full path, e.g. `-- ~/.local/bin/claude`.

The real project is never modified. `agentbox diff <state>` lists what the
agent changed:

```
M a.txt        content changed
m b.txt        metadata only (chmod/chown/touch)
A new.txt      added
D gone.txt     deleted
R sub          directory removed and recreated (everything below is new)
M ~/.claude.json   with --home-from: changes in $HOME, shown as ~/path
```

**Exec auditing.** The sandbox lives in its own cgroup; eBPF programs filtered
to that cgroup id record each exec at two points:

1. **Request** (syscall entry): what the caller passed to `execve`/`execveat`.
   This is read from the caller's memory, so another thread can rewrite it
   before the kernel copies it. It's a claim, not a fact.
2. **Actual** (`sched_process_exec`): fires after the new image is loaded and
   before any of its code runs. argv/envp are read from the *new* process's
   memory (the copy the kernel itself made; the old process's other threads
   are already dead), and `exe`/`cwd` are resolved by walking dentries in the
   kernel, relative to the process's own root. This is the authoritative
   record.

Each successful exec becomes one JSON line holding both, plus how they relate:

```json
{"type":"exec","time":"2026-11-15T02:10:15.2Z","pid":7315,"ppid":7314,"sandbox_pid":9,
 "uid":1000,"exe":"/usr/bin/echo","cwd":"/home/claude/demo","argv":["echo","EVIL!!"],
 "filename":"/bin/echo","exec_from_tid":7317,
 "argv_vs_request":"different",
 "requested":{"syscall":"execve","filename":"/bin/echo","argv":["echo","benign"],"cwd":"/home/claude/demo"}}
```

That record is real. It's the `tests/race.c` test (one thread flips argv[1] while
another execs it) caught in the act: the syscall hook saw `benign`, the kernel
loaded `EVIL!!`.

`argv_vs_request` is one of:

| value | meaning |
|---|---|
| `identical` | normal |
| `interpreter_prefixed` | a `#!` script: the kernel prepended the interpreter, as it should |
| `truncated_prefix_match` | argv too long to capture fully; the captured parts agree |
| `unknown` | the request couldn't be read (fallback mode, see below) |
| `different` | **the argv changed between the syscall and the exec. Investigate.** |

Other record types: `exec_failed` (errno, plus the request), and a final
`summary` (counts, dropped events, exit code). Failures that are just `execvp`
walking `$PATH` (ENOENT on each directory before the real hit) are folded into
the successful exec as `path_search_misses` instead of filling the log.

Note that `exe` is the resolved binary (`sh` → `/usr/bin/dash`), and that
fexecve-style tricks don't hide anything: an `execveat(fd, "", AT_EMPTY_PATH)`
with `argv[0]="totally-not-uname"` still logs `exe: /usr/bin/uname`.

`--capture-env` adds each process's environment as the kernel placed it in the
new image, i.e. exactly what the process was handed. `--capture-env` (or
`=names`) logs variable names only, which shows *that* `AWS_SECRET_ACCESS_KEY`
was passed without writing its value to disk. `--capture-env=full` logs values
too. Whether a process then *reads* a variable is invisible to the kernel
(`getenv` is a plain memory read), so the honest guarantee is "this is what it
was given".

### File operations

`open`/`openat`/`openat2`/`creat` with write intent (`O_WRONLY`, `O_RDWR`,
`O_CREAT`, `O_TRUNC`; add `--log-reads` for everything), `unlink`/`unlinkat`,
`rmdir`, `rename`/`renameat`/`renameat2`, `mkdir`/`mkdirat`. Same two-sided
pattern: the requested path is captured at syscall entry, and at exit the
kernel resolves what it actually meant:

```json
{"type":"file","op":"open","path":"sneaky.txt","relative_to":"/home/claude/demo",
 "target":"/home/claude/demo/sneaky.txt","resolved":"/tmp/elsewhere","resolved_differs":true,
 "flags":["O_WRONLY","O_CREAT","O_TRUNC"],"mode":"0666","fd":3, ...}
```

- `relative_to` is what the dirfd (or cwd) resolved to, in the kernel.
- `target` is the name joined to that dir and normalised lexically: what the
  name *says*.
- `resolved` (open only) is the path of the fd the kernel returned: where it
  *went*. `resolved_differs: true` means a symlink (or a race) redirected the
  write. This record is real, from a test that wrote through a symlink.

Failures carry `errno`/`error` (e.g. `EROFS` for writes outside the project).
The overlay diff still says *what* changed; these records say *who* (pid) and
*when*.

### Network

```json
{"type":"connect","family":"inet","socket":"stream","fd":3,
 "requested":"10.255.255.1:80","peer":"10.255.255.1:80","peer_vs_request":"identical","in_progress":true}
```

`requested` is the sockaddr the caller passed. `peer` is read from the kernel
socket afterwards. `peer_vs_request` is `identical`, `different` (sockaddr
rewritten mid-call), `failed` (connect failed, nothing to compare), `no_peer`
(e.g. unix sockets) or `unknown` (unreadable request). Unix sockets show their
path, or `@name` for abstract ones.

### HTTP(S) traffic: `--log-http`

```
sudo agentbox run -p . --home-from ~ --log-http -- ~/.local/bin/claude
```

Kernel hooks only see `connect()` to an IP; the content is inside TLS. With
`--log-http` the sandbox gets its own network namespace whose only exit is a
logging proxy run by agentbox:

- The helper opens the listening socket on `127.0.0.1:3128` *inside* the new
  namespace and passes the fd to agentbox, which accepts on it and makes the
  outbound connections from the host side. There is no veth, no iptables
  setup, and no other route out (abstract unix sockets are per-namespace too).
- HTTPS (`CONNECT`) is intercepted with a CA generated for the run. Its
  private key exists only in agentbox's memory. The certificate is mounted
  read-only at `/run/agentbox/ca.pem` (plus `ca-bundle.pem` = system roots + CA).
- The agent's environment points the usual stacks at both:
  `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` (and lower-case), `NO_PROXY`,
  `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
  `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, `AWS_CA_BUNDLE`.
- The upstream certificate is verified against the host's roots *before* the
  agent is shown a certificate, so interception never vouches for a server
  that wouldn't verify on its own.

Bytes are relayed unchanged; a passive HTTP/1.1 parser on each direction
produces one record per exchange:

```json
{"type":"http","time":"...","conn":14,"pid":231877,"comm":"claude","method":"POST",
 "url":"https://api.anthropic.com/v1/messages?beta=true","status":200,"duration_ms":2140,
 "request":{"headers":{"authorization":"Bearer <redacted 108 bytes>", ...},
            "body":{"model":"...","messages":[...]},"body_bytes":67717},
 "response":{"reason":"OK","headers":{...},"body_bytes":713,
             "events":[{"event":"message_start","data":{...}}, ...]}}
```

- `pid`/`comm` are the sandboxed process holding the client socket (found
  through the namespace's `/proc/<pid>/net/tcp` and the cgroup's fd tables).
- Bodies are decoded (`gzip`, `deflate`, `br`, `zstd`). JSON is embedded as
  JSON, `text/event-stream` is split into `events`, and binary data goes to
  `body_base64`. Each body is capped at `--http-body-max` (8 MiB), with
  `body_truncated` set when the cap is hit.
- Credential headers (`Authorization`, `x-api-key`, cookies, `*token*`,
  `*secret*`, `*-key`) are redacted; `--http-log-secrets` keeps them.
- `http_tunnel` records show each CONNECT: target, upstream address, and
  errors such as a client that refused the CA.

`--http-pcap [FILE]` also writes the decrypted traffic to a classic libpcap
file (default `<state>/http.pcap`). The proxy handles sockets, not packets, so
each connection is a synthesized TCP stream: handshake, data segments with
consistent seq/ack and checksums, and a FIN per direction. The server is the
real upstream address and port; the client is loopback with the agent's real
source port. Intercepted HTTPS keeps port 443, so tell the dissector it's
HTTP:

```
tshark -r http.pcap -d tcp.port==443,http -Y http
```

(or Wireshark: Analyze → Decode As → TCP port 443 → HTTP). The pcap is not
redacted, so it holds whatever credentials were sent. It's created with mode
0600.

`agentbox proxy --listen 127.0.0.1:3128 --dir DIR` runs the same proxy without
a sandbox or root and prints the variables to export.

Limits: only HTTP/1.1 is parsed, and the proxy offers only `http/1.1` over
ALPN. A client that pins certificates, or keeps its own trust store and
ignores these variables, fails with an `http_tunnel` error instead of being
logged. Tools that ignore `*_PROXY` can't reach the network at all, and DNS
isn't available in the namespace (with a proxy, clients don't need it).

### Denying commands: `--deny`

```
sudo agentbox run --deny curl --deny wget --deny /usr/bin/ssh -- claude
```

- `--deny NAME` refuses any binary whose file name is `NAME`, plus (by
  identity) whatever `NAME` resolves to on `$PATH`. Startup prints the
  resolution; e.g. `--deny sh` on Fedora also blocks `bash`, the same file.
- `--deny /abs/path` refuses that file by device + inode, so symlinks, hard
  links and bind mounts of it are refused too. The device is the superblock's
  (via `statx` mount id and mountinfo), since `stat` reports a different
  per-subvolume device on btrfs.

The check runs on the file the kernel is about to load, never on argv or on
the name the caller used, so `argv[0]` tricks, `fexecve`, and symlink farms
don't get around it. For `#!` scripts both the script and its interpreter
are checked.

Enforcement:

- With BPF LSM (`bpf` in `/sys/kernel/security/lsm`), `lsm/bprm_check_security`
  fails the exec with `EACCES` and logs an `exec_denied` record (with the
  request and any PATH-search misses).
- Otherwise `sched_process_exec` sends `SIGKILL` after the image is loaded and
  before any of its code runs. The `exec` record then carries `"denied": true,
  "enforcement": "killed"`, and the parent sees the process die by SIGKILL.

`summary.deny_enforcement` says which mode ran.

This is a guard rail, not a boundary. A renamed copy of a denied binary only
matches if it keeps the name, and an interpreter that's allowed (python,
node, bash) can do the same work itself.

## Requirements

- Linux ≥ 5.17 with BTF (`/sys/kernel/btf/vmlinux`), cgroup v2 mounted (pure or
  hybrid), overlayfs. Tested on 6.18 x86_64.
- Root to run (namespaces, overlay mounts, BPF). The agent itself runs
  unprivileged.
- Build: Rust ≥ 1.80, clang, libelf, zlib, pkg-config
  (`apt install clang libelf-dev zlib1g-dev pkg-config`).

```
cargo build --release
sudo ./target/release/agentbox run -- bash
```

`src/bpf/vmlinux.h` is checked in. Thanks to CO-RE the binary runs on other
kernels anyway. To regenerate: `bpftool btf dump file /sys/kernel/btf/vmlinux
format c > src/bpf/vmlinux.h`.

### Request capture modes

The preferred capture is a **sleepable** `fentry.s` program on
`__x64_sys_execve`. It can fault in pages, so it reads argv strings even when
they sit in pages the process never touched. That needs
`CONFIG_FUNCTION_ERROR_INJECTION` (standard on Ubuntu/Fedora/Debian kernels).
`bpf_copy_from_user_str` (6.12+) is used when present.

If the kernel or a BPF-LSM policy refuses fentry, agentbox falls back to the
`sys_enter_execve` tracepoint, which can't fault in pages. Requests that hit an
untouched page are marked `"unreadable": true` and compared as `unknown`, never
as a false `different`. The *actual* record is unaffected in both modes.
`summary.request_capture` says which mode ran. Set `AGENTBOX_BPF_DEBUG=1` for
libbpf's debug log.

## Layout

```
src/bpf/exec.bpf.c   kernel side: exec, file-op and connect hooks, in-kernel path resolution
src/bpf/events.h     event layouts shared with Rust
src/events.rs        Rust mirror (sizes/offsets asserted at compile time) + decoding
src/tracer.rs        load/attach (with fallback), ring buffer pump, supervision
src/log.rs           request↔actual correlation, flag/sockaddr decoding, JSONL
src/sandbox.rs       cgroup, namespaces, overlay + read-only root, pivot_root, privilege drop
src/proxy.rs         --log-http: CA, CONNECT/TLS interception, relay, process attribution
src/http.rs          passive HTTP/1.1 parser, body decoding, header redaction
src/deny.rs          --deny rule resolution (names, paths -> superblock dev + inode)
src/diff.rs          reads the overlay upper layer
```

Process tree: `agentbox` (tracer) → helper (joins the cgroup *before* it
unshares, so the very first exec is traced) → init (pid 1: builds the
filesystem view and reaps children) → agent (drops privileges and execs).

## Limits and known gaps

- **Not a kernel boundary.** The agent shares the host kernel, so a kernel
  exploit escapes. This is containment for misbehaving agents, not hostile
  code. A microVM is the next layer if you need that.
- **Network is shared by default.** `--no-network` gives loopback only;
  `--log-http` allows only proxied HTTP(S). There's no per-host egress policy yet.
- **Environment is inherited** from the caller (minus `HOME`/`PWD`/`TMPDIR`),
  secrets included. Wrap with `env -i` or add an allowlist.
- **io_uring bypasses syscall hooks.** File and network operations submitted
  through io_uring don't pass through these tracepoints. The overlay still
  contains every write, but the per-process records won't. Either disable it
  host-wide (`sysctl kernel.io_uring_disabled=2`) or block `io_uring_setup` in
  the sandbox with seccomp (not done yet).
- **Not every syscall is covered.** Missing so far: `link`/`symlink`,
  `chmod`/`chown`, `truncate`, `bind`/`listen`, and UDP `sendto`/`sendmsg`
  without a prior `connect`. All follow the same enter/exit pattern.
- **Connect sees IPs, not hostnames.** DNS isn't decoded, and with a proxy
  every connection goes to the proxy.
- **Abstract unix sockets** (`@name`) are scoped by *network* namespace, so
  with networking shared the agent can reach host daemons that listen on them.
  `--no-network` closes that.
- argv/envp capture is capped at 8 KiB and 128 elements (flagged when
  truncated). Paths are resolved up to 64 components.
- `/proc/1/cmdline` inside the sandbox shows the `agentbox` command line (init
  is a fork, not an exec).
- A reused `--state` dir continues on top of the earlier run's changes.
- There's no `apply` command yet. Use `diff` to review, then copy from
  `<state>/upper`.

## Work in progress: BPF LSM auditing

The kernel half of an LSM-based file/network audit is in `src/bpf/exec.bpf.c`
(section "LSM") with layouts in `src/bpf/events.h` (`lsm_file_event`,
`lsm_net_event`, `op_result_event`). It compiles, but the loader keeps these
programs **disabled** (`src/tracer.rs`) until userspace decoding exists.

Design:

- Hooks: `file_open`, `path_unlink/rmdir/mkdir/rename/link/symlink/chmod/chown/truncate`,
  `socket_connect/bind/sendmsg` (sendmsg only when a destination is named).
- They fire in the VFS/socket layers on kernel-resolved objects, so io_uring
  (inline or on io-wq workers) is covered, and there's no argument race.
- `syscall_nr` records the syscall the hook ran under, from the task's saved
  registers. io_uring work is flagged `async`.
- Results: the hook marks the task, and the next `raw_syscalls/sys_exit` on
  that task emits `op_result_event` with the return value. Async work gets no
  result.
- The existing syscall-entry stash is reused, so records can carry the
  requested name and dirfd next to the resolved path.
- Scratch is per-task (task storage), since LSM programs can be preempted.

Remaining:

1. Decode the three events in `src/events.rs` and `src/log.rs`, holding LSM
   records per thread until their `op_result_event` arrives.
2. Mode selection: try LSM and enable these programs; on failure fall back to
   the syscall tracepoints and add a seccomp filter returning `ENOSYS` for
   `io_uring_setup/enter/register`.
3. Test in a kernel booted with `bpf` in `lsm=`. This VM refuses LSM programs,
   but `vng -r /boot/vmlinuz-<ubuntu> --append "lsm=...,bpf"` (virtme-ng +
   QEMU) works here, as does the sleepable fentry path inside it.
4. `lsm_store`/`lsm_pend` are still task storage. Values over 8 KiB fail to
   allocate on 6.19+ kernels (see `req_store` in exec.bpf.c), so move them to
   tid-keyed LRU hashes like the syscall stashes.
5. Check `FMODE_CREATED`'s bit value on the target kernels before using it
   (it's a #define, not in BTF).
