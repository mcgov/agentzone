//! Builds the sandbox: a cgroup to tag every process for the tracer, fresh
//! mount/pid/ipc/uts (+ optional net) namespaces, a tmpfs root holding
//! read-only binds of the host system, the project mounted as a copy-on-write
//! overlay, and an unprivileged uid for the agent.
//!
//! Process tree:
//!   agentbox (tracer, host)
//!     └─ helper           joins cgroup, unshares namespaces, waits
//!          └─ init (pid 1) builds the filesystem view, reaps
//!               └─ agent   drops privileges, execs the command

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{signal, SigHandler, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{
    chdir, fork, pipe2, pivot_root, read, setresgid, setresuid, sethostname, setgroups, ForkResult,
    Gid, Pid, Uid,
};

use crate::tracer::Supervised;

/// Host paths exposed read-only inside the sandbox (when they exist).
const SYSTEM_DIRS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/nix",
];
/// Resolver state under /run, exposed read-only when networking is shared.
const RESOLVER_DIRS: &[&str] = &["/run/systemd/resolve"];
const DEV_NODES:&[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

#[derive(Clone, Debug)]
pub struct Bind {
    pub src: PathBuf,
    pub dst: PathBuf,
    pub writable: bool,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub project: PathBuf,
    pub mount_at: PathBuf,
    pub state: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub network: bool,
    pub binds: Vec<Bind>,
    pub command: Vec<String>,
    pub hostname: String,
    /// Template for $HOME, mounted copy-on-write (else an empty tmpfs).
    pub home_from: Option<PathBuf>,
    /// Where $HOME is inside the sandbox.
    pub home_at: PathBuf,
    /// --log-http: private network namespace whose only exit is the proxy.
    pub proxy: bool,
    /// Host dir with the proxy CA files, mounted read-only at TRUST_DIR.
    pub trust_dir: Option<PathBuf>,
}

/// Where the proxy's CA files appear inside the sandbox.
pub const TRUST_DIR: &str = "/run/agentbox";

impl Config {
    fn new_netns(&self) -> bool {
        !self.network || self.proxy
    }
}

impl Config {
    pub fn upper(&self) -> PathBuf { self.state.join("upper") }
    fn work(&self) -> PathBuf { self.state.join("work") }
    fn root(&self) -> PathBuf { self.state.join("root") }
    pub fn home_upper(&self) -> PathBuf { self.state.join("home/upper") }
    fn home_work(&self) -> PathBuf { self.state.join("home/work") }
}

// ------------------------------------------------------------------ cgroup

pub struct Cgroup {
    pub path: PathBuf,
    pub id: u64,
}

fn cgroup2_mount() -> Result<PathBuf> {
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    for line in info.lines() {
        // ... mountpoint ... - fstype source opts
        let (pre, post) = line.split_once(" - ").unwrap_or((line, ""));
        if post.split_whitespace().next() == Some("cgroup2") {
            if let Some(mp) = pre.split_whitespace().nth(4) {
                return Ok(PathBuf::from(mp));
            }
        }
    }
    bail!("no cgroup2 hierarchy mounted (needed to scope the tracer to the sandbox)")
}

impl Cgroup {
    pub fn create(name: &str) -> Result<Self> {
        let base = cgroup2_mount()?.join("agentbox");
        fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
        let path = base.join(name);
        fs::create_dir(&path).with_context(|| format!("creating cgroup {}", path.display()))?;
        // On 64-bit kernels the cgroup id is the kernfs inode number.
        let id = fs::metadata(&path)?.ino();
        Ok(Self { path, id })
    }

    fn add(&self, pid: Pid) -> Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())
            .context("moving sandbox into its cgroup")
    }

    /// Kill anything left (daemons the agent started) and remove the cgroup.
    pub fn destroy(&self) {
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
        for _ in 0..50 {
            if fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        eprintln!("agentbox: warning: could not remove {}", self.path.display());
    }
}

// ------------------------------------------------------------ state dir

pub fn prepare_state(cfg: &Config) -> Result<()> {
    if cfg.state.starts_with(&cfg.project) {
        bail!("state dir {} must not be inside the project", cfg.state.display());
    }
    for d in [cfg.upper(), cfg.work(), cfg.root()] {
        fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    }
    if fs::read_dir(cfg.upper())?.next().is_some() {
        eprintln!(
            "agentbox: note: {} already has changes; this run continues on top of them",
            cfg.state.display()
        );
    }
    // The overlay's top directory takes the upper dir's owner and mode, so
    // make it look exactly like the project directory.
    let meta = fs::metadata(&cfg.project)?;
    std::os::unix::fs::chown(cfg.upper(), Some(meta.uid()), Some(meta.gid()))?;
    fs::set_permissions(cfg.upper(), fs::Permissions::from_mode(meta.mode() & 0o7777))?;
    fs::set_permissions(cfg.work(), fs::Permissions::from_mode(0o700))?;

    if let Some(home) = &cfg.home_from {
        if cfg.state.starts_with(home) {
            bail!("state dir {} must not be inside --home-from {}", cfg.state.display(), home.display());
        }
        for d in [cfg.home_upper(), cfg.home_work()] {
            fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
        }
        // $HOME belongs to the agent regardless of who owns the template.
        std::os::unix::fs::chown(cfg.home_upper(), Some(cfg.uid), Some(cfg.gid))?;
        fs::set_permissions(cfg.home_upper(), fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(cfg.home_work(), fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

// ------------------------------------------------------------ supervision

pub struct Running {
    pub helper: Pid,
    /// --log-http: the proxy's listening socket, opened inside the sandbox's
    /// network namespace.
    pub listener: Option<std::net::TcpListener>,
}

fn exit_code(ws: WaitStatus) -> Option<i32> {
    match ws {
        WaitStatus::Exited(_, c) => Some(c),
        WaitStatus::Signaled(_, s, _) => Some(128 + s as i32),
        _ => None,
    }
}

impl Supervised for Running {
    fn try_wait(&mut self) -> Result<Option<i32>> {
        Ok(exit_code(waitpid(self.helper, Some(WaitPidFlag::WNOHANG))?))
    }
}

/// Fork the sandbox. The helper blocks until it has been placed in the
/// cgroup, so the tracer sees every exec from the first one.
pub fn spawn(cfg: &Config, cgroup: &Cgroup) -> Result<Running> {
    // Everything the children need is computed before fork.
    let argv: Vec<CString> = cfg
        .command
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()
        .context("command contains a NUL byte")?;
    let env = agent_env(cfg)?;
    let (rd, wr) = pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
    // For handing the proxy listener back from inside the new netns.
    let fd_chan = if cfg.proxy {
        use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
        Some(socketpair(AddressFamily::Unix, SockType::Stream, None, SockFlag::SOCK_CLOEXEC)?)
    } else {
        None
    };

    match unsafe { fork() }? {
        ForkResult::Child => {
            drop(wr);
            let chan = fd_chan.map(|(_, c)| c);
            let code = match helper(cfg, rd, chan, &argv, &env) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("agentbox: sandbox setup failed: {e:#}");
                    126
                }
            };
            unsafe { libc::_exit(code) }
        }
        ForkResult::Parent { child } => {
            drop(rd);
            if let Err(e) = cgroup.add(child) {
                let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);
                return Err(e);
            }
            // Ctrl-C reaches the agent directly (same process group); the
            // tracer must survive it to drain and write the summary.
            unsafe {
                let _ = signal(Signal::SIGINT, SigHandler::SigIgn);
                let _ = signal(Signal::SIGQUIT, SigHandler::SigIgn);
            }
            let mut w = fs::File::from(wr);
            w.write_all(b"g")?;
            let listener = match fd_chan {
                Some((ours, theirs)) => {
                    drop(theirs);
                    match recv_fd(&ours) {
                        Ok(fd) => Some(std::net::TcpListener::from(fd)),
                        Err(e) => {
                            let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
                            let _ = waitpid(child, None);
                            return Err(e.context("setting up the proxy in the sandbox's network namespace"));
                        }
                    }
                }
                None => None,
            };
            Ok(Running { helper: child, listener })
        }
    }
}

fn agent_env(cfg: &Config) -> Result<Vec<CString>> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| !matches!(k.as_str(), "HOME" | "PWD" | "OLDPWD" | "TMPDIR"))
        .filter(|(k, _)| !(cfg.proxy && crate::proxy::is_proxy_env(k)))
        .collect();
    if cfg.proxy {
        let url = format!("http://127.0.0.1:{}", crate::proxy::PORT);
        env.extend(crate::proxy::agent_env(&url, Path::new(TRUST_DIR)));
    }
    env.push(("HOME".into(), cfg.home_at.display().to_string()));
    env.push(("PWD".into(), cfg.mount_at.display().to_string()));
    env.push(("TMPDIR".into(), "/tmp".into()));
    env.into_iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).context("env contains NUL"))
        .collect()
}

fn die_with_parent() {
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
}

fn send_fd(chan: &OwnedFd, fd: i32) -> Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    let iov = [std::io::IoSlice::new(b"L")];
    let fds = [fd];
    sendmsg::<()>(chan.as_raw_fd(), &iov, &[ControlMessage::ScmRights(&fds)], MsgFlags::empty(), None)
        .context("passing the proxy socket to agentbox")?;
    Ok(())
}

fn recv_fd(chan: &OwnedFd) -> Result<OwnedFd> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    let mut b = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut b)];
    let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    let msg = recvmsg::<()>(chan.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_CMSG_CLOEXEC)?;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            if let Some(&fd) = fds.first() {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    bail!("sandbox exited before opening the proxy socket")
}

/// A fresh network namespace starts with `lo` down.
fn loopback_up() -> Result<()> {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            bail!("socket: {}", std::io::Error::last_os_error());
        }
        let s = OwnedFd::from_raw_fd(s);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (d, c) in ifr.ifr_name.iter_mut().zip(b"lo\0") {
            *d = *c as libc::c_char;
        }
        if libc::ioctl(s.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr) < 0 {
            bail!("SIOCGIFFLAGS lo: {}", std::io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(s.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) < 0 {
            bail!("SIOCSIFFLAGS lo: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn helper(cfg: &Config, go: OwnedFd, chan: Option<OwnedFd>, argv: &[CString], env: &[CString]) -> Result<i32> {
    die_with_parent();
    unsafe {
        let _ = signal(Signal::SIGINT, SigHandler::SigIgn);
        let _ = signal(Signal::SIGQUIT, SigHandler::SigIgn);
    }
    let mut b = [0u8; 1];
    if read(&go, &mut b)? != 1 {
        bail!("tracer went away before start");
    }
    drop(go);

    let mut flags = CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWCGROUP;
    if cfg.new_netns() {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(flags).context("unshare namespaces")?;
    if cfg.new_netns() {
        if let Err(e) = loopback_up() {
            if cfg.proxy {
                return Err(e);
            }
            eprintln!("agentbox: warning: loopback unavailable: {e:#}");
        }
    }
    if let Some(chan) = chan {
        // Bound here, inside the new namespace; accepted by agentbox outside.
        let l = std::net::TcpListener::bind(("127.0.0.1", crate::proxy::PORT))
            .context("binding the proxy port inside the sandbox")?;
        send_fd(&chan, l.as_raw_fd())?;
    }

    match unsafe { fork() }? {
        ForkResult::Child => {
            let code = match init(cfg, argv, env) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("agentbox: sandbox setup failed: {e:#}");
                    126
                }
            };
            unsafe { libc::_exit(code) }
        }
        ForkResult::Parent { child } => loop {
            match waitpid(child, None) {
                Ok(ws) => {
                    if let Some(c) = exit_code(ws) {
                        return Ok(c);
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
        },
    }
}

/// PID 1 of the sandbox.
fn init(cfg: &Config, argv: &[CString], env: &[CString]) -> Result<i32> {
    die_with_parent();
    unsafe {
        let _ = signal(Signal::SIGINT, SigHandler::SigDfl);
        let _ = signal(Signal::SIGQUIT, SigHandler::SigDfl);
    }
    let _ = sethostname(&cfg.hostname);
    build_root(cfg)?;

    let agent = match unsafe { fork() }? {
        ForkResult::Child => {
            let e = exec_agent(cfg, argv, env);
            eprintln!("agentbox: {e:#}");
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => child,
    };

    // Reap everything; leave when the agent itself exits. Leaving tears down
    // the pid namespace, which kills anything the agent left behind.
    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(ws) if ws.pid() == Some(agent) => {
                if let Some(c) = exit_code(ws) {
                    return Ok(c);
                }
            }
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn exec_agent(cfg: &Config, argv: &[CString], env: &[CString]) -> anyhow::Error {
    let r: Result<std::convert::Infallible> = (|| {
        let (uid, gid) = (Uid::from_raw(cfg.uid), Gid::from_raw(cfg.gid));
        setgroups(&[gid]).context("setgroups")?;
        setresgid(gid, gid, gid).context("setresgid")?;
        setresuid(uid, uid, uid).context("setresuid")?;
        // setuid binaries (sudo, su, ...) can no longer raise privileges.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            bail!("PR_SET_NO_NEW_PRIVS: {}", std::io::Error::last_os_error());
        }
        chdir(&cfg.mount_at).with_context(|| format!("chdir {}", cfg.mount_at.display()))?;
        nix::unistd::execvpe(&argv[0], argv, env)
            .with_context(|| format!("exec {}", cfg.command[0]))
    })();
    match r {
        Err(e) => e,
        Ok(never) => match never {},
    }
}

// -------------------------------------------------------------- mounts

fn inside(root: &Path, p: &Path) -> PathBuf {
    root.join(p.strip_prefix("/").unwrap_or(p))
}

fn mnt(src: Option<&Path>, dst: &Path, fstype: Option<&str>, flags: MsFlags, data: Option<&str>) -> Result<()> {
    mount(src, dst, fstype, flags, data).with_context(|| {
        format!(
            "mount {} on {} ({})",
            src.map(|s| s.display().to_string()).unwrap_or_else(|| "-".into()),
            dst.display(),
            fstype.unwrap_or("bind")
        )
    })
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;

/// Make a mount tree read-only, including submounts (mount_setattr, 5.12+).
fn make_readonly(target: &Path, nodev: bool) -> Result<()> {
    let c = CString::new(target.as_os_str().as_encoded_bytes())?;
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | if nodev { MOUNT_ATTR_NODEV } else { 0 },
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::AT_RECURSIVE as libc::c_uint,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if r == 0 {
        return Ok(());
    }
    // Older kernel: top-level remount only.
    let mut f = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID;
    if nodev {
        f |= MsFlags::MS_NODEV;
    }
    mnt(None, target, None, f, None)
}

fn bind(src: &Path, dst: &Path, writable: bool, nodev: bool) -> Result<()> {
    let meta = fs::metadata(src).with_context(|| format!("bind source {}", src.display()))?;
    if meta.is_dir() {
        fs::create_dir_all(dst)?;
    } else {
        if let Some(p) = dst.parent() {
            fs::create_dir_all(p)?;
        }
        fs::OpenOptions::new().create(true).truncate(false).write(true).open(dst)?;
    }
    mnt(Some(src), dst, None, MsFlags::MS_BIND | MsFlags::MS_REC, None)?;
    if !writable {
        make_readonly(dst, nodev)?;
    }
    Ok(())
}

fn tmpfs(dst: &Path, opts: &str) -> Result<()> {
    fs::create_dir_all(dst)?;
    mnt(
        Some(Path::new("tmpfs")),
        dst,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(opts),
    )
}

fn overlay_escape(p: &Path) -> Result<String> {
    let s = p.to_str().context("overlay paths must be UTF-8")?;
    if s.contains([',', ':']) {
        bail!("overlay path {s} contains ',' or ':' (unsupported)");
    }
    Ok(s.to_owned())
}

fn build_root(cfg: &Config) -> Result<()> {
    // Nothing we mount from here on leaks back to the host.
    mnt(None, Path::new("/"), None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)?;

    let root = cfg.root();
    tmpfs(&root, "mode=0755,size=16m")?;

    // Read-only host system. Symlinks (e.g. /bin -> usr/bin) are recreated.
    for d in SYSTEM_DIRS {
        let host = Path::new(d);
        let Ok(meta) = fs::symlink_metadata(host) else { continue };
        let dst = inside(&root, host);
        if meta.file_type().is_symlink() {
            symlink(fs::read_link(host)?, &dst)?;
        } else if meta.is_dir() {
            bind(host, &dst, false, true)?;
        }
    }
    bind(Path::new("/sys"), &inside(&root, Path::new("/sys")), false, true)?;

    // Name resolution. On systemd-resolved hosts /etc/resolv.conf is a symlink
    // into /run/systemd/resolve, and nss-resolve talks to the varlink socket
    // there; without it the symlink dangles and every lookup fails.
    if !cfg.new_netns() {
        for d in RESOLVER_DIRS {
            let host = Path::new(d);
            if host.is_dir() {
                bind(host, &inside(&root, host), false, true)?;
            }
        }
    }

    // /proc for the new pid namespace.
    let proc_ = inside(&root, Path::new("/proc"));
    fs::create_dir_all(&proc_)?;
    mnt(
        Some(Path::new("proc")),
        &proc_,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None,
    )?;

    // Minimal /dev.
    let dev = inside(&root, Path::new("/dev"));
    fs::create_dir_all(&dev)?;
    mnt(Some(Path::new("tmpfs")), &dev, Some("tmpfs"), MsFlags::MS_NOSUID, Some("mode=0755,size=1m"))?;
    for n in DEV_NODES {
        let host = Path::new("/dev").join(n);
        if host.exists() {
            bind(&host, &dev.join(n), true, false)?;
        }
    }
    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
        ("ptmx", "pts/ptmx"),
    ] {
        symlink(target, dev.join(name))?;
    }
    let pts = dev.join("pts");
    fs::create_dir_all(&pts)?;
    mnt(
        Some(Path::new("devpts")),
        &pts,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )?;
    tmpfs(&dev.join("shm"), "mode=1777")?;

    tmpfs(&inside(&root, Path::new("/tmp")), "mode=1777")?;
    // Mounted before the project, which may sit inside it.
    let home = inside(&root, &cfg.home_at);
    match &cfg.home_from {
        // Copy-on-write home: reads come from the template, writes land in
        // state/home/upper.
        Some(src) => {
            fs::create_dir_all(&home)?;
            let opts = format!(
                "lowerdir={},upperdir={},workdir={}",
                overlay_escape(src)?,
                overlay_escape(&cfg.home_upper())?,
                overlay_escape(&cfg.home_work())?
            );
            mnt(Some(Path::new("overlay")), &home, Some("overlay"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some(&opts))?;
        }
        None => tmpfs(&home, &format!("mode=0700,uid={},gid={}", cfg.uid, cfg.gid))?,
    }

    // The project, copy-on-write: reads come from the real tree, every write
    // lands in state/upper.
    let ws = inside(&root, &cfg.mount_at);
    fs::create_dir_all(&ws)?;
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        overlay_escape(&cfg.project)?,
        overlay_escape(&cfg.upper())?,
        overlay_escape(&cfg.work())?
    );
    mnt(Some(Path::new("overlay")), &ws, Some("overlay"), MsFlags::MS_NOSUID, Some(&opts))?;

    for b in &cfg.binds {
        bind(&b.src, &inside(&root, &b.dst), b.writable, true)?;
    }
    if let Some(t) = &cfg.trust_dir {
        bind(t, &inside(&root, Path::new(TRUST_DIR)), false, true)?;
    }

    // Swap roots and drop the host filesystem from this namespace entirely.
    chdir(&root)?;
    pivot_root(".", ".").context("pivot_root")?;
    umount2(".", MntFlags::MNT_DETACH).context("detaching old root")?;
    chdir("/")?;
    // The tmpfs root itself becomes read-only (its submounts keep their modes).
    mnt(None, Path::new("/"), None, MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY, None)?;
    Ok(())
}
