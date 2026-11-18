//! Loads the BPF exec tracer, runs the sandbox, and streams events to the logger.

use std::cell::RefCell;
use std::io::Write;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};

use serde_json::{Map, Value};

use crate::deny::Rules;
use crate::events::{self, DENY_KILL, DENY_LSM, DENY_OFF};
use crate::log::Logger;

mod skel {
    #![allow(clippy::all, non_camel_case_types, non_snake_case, dead_code, unused)]
    include!(concat!(env!("OUT_DIR"), "/exec.skel.rs"));
}
use skel::ExecSkelBuilder;

pub trait Supervised {
    /// Non-blocking: Some(exit code) once the sandbox has finished.
    fn try_wait(&mut self) -> Result<Option<i32>>;
    /// Records from other sources (the HTTP proxy) to merge into the log.
    /// `last` is set once after the sandbox exited: flush everything.
    fn side_records(&mut self, _last: bool) -> Vec<Map<String, Value>> {
        Vec::new()
    }
}

pub struct Settings<'a> {
    pub cgroup_id: u64,
    pub capture_env: bool,
    pub log_reads: bool,
    pub deny: &'a Rules,
    pub watch: &'a crate::watch::Watch,
}

/// Hooks added after the core set: process exit/fork, privileged-syscall
/// failures, link/symlink/chmod/chown/truncate, bind/listen/accept/sendto.
/// They load as a group; if this kernel rejects any of them the tracer
/// falls back to the core set (and says so) instead of failing.
const OPTIONAL_PROGS: &[&str] = &[
    "tp_sched_process_exit", "rtp_sched_process_fork", "tp_sys_denied",
    "tp_enter_link", "tp_exit_link", "tp_enter_linkat", "tp_exit_linkat",
    "tp_enter_symlink", "tp_exit_symlink", "tp_enter_symlinkat", "tp_exit_symlinkat",
    "tp_enter_chmod", "tp_exit_chmod", "tp_enter_fchmodat", "tp_exit_fchmodat",
    "tp_enter_chown", "tp_exit_chown", "tp_enter_lchown", "tp_exit_lchown",
    "tp_enter_fchownat", "tp_exit_fchownat", "tp_enter_truncate", "tp_exit_truncate",
    "tp_enter_bind", "tp_exit_bind", "tp_enter_listen", "tp_exit_listen",
    "tp_enter_accept", "tp_exit_accept", "tp_enter_accept4", "tp_exit_accept4",
    "tp_enter_sendto", "tp_exit_sendto",
];

/// Second tier, loaded only on top of the first: fd-based fchmod/fchown/
/// ftruncate, executable file mappings, sendmsg with a destination.
const OPTIONAL_PROGS_2: &[&str] = &[
    "tp_enter_fchmod", "tp_exit_fchmod", "tp_enter_fchown", "tp_exit_fchown",
    "tp_enter_ftruncate", "tp_exit_ftruncate", "tp_enter_mmap", "tp_exit_mmap",
    "tp_enter_sendmsg", "tp_exit_sendmsg",
];

/// Third tier: xattrs, mknod, sendmmsg, mprotect(PROT_EXEC) of file mappings.
const OPTIONAL_PROGS_3: &[&str] = &[
    "tp_enter_setxattr", "tp_exit_setxattr", "tp_enter_lsetxattr", "tp_exit_lsetxattr",
    "tp_enter_fsetxattr", "tp_exit_fsetxattr", "tp_enter_removexattr", "tp_exit_removexattr",
    "tp_enter_lremovexattr", "tp_exit_lremovexattr", "tp_enter_fremovexattr", "tp_exit_fremovexattr",
    "tp_enter_mknod", "tp_exit_mknod", "tp_enter_mknodat", "tp_exit_mknodat",
    "tp_enter_sendmmsg", "tp_exit_sendmmsg", "tp_enter_mprotect", "tp_exit_mprotect",
];

/// What the log lacks when a tier didn't load.
const TIER_RECORDS: [&str; 3] = [
    "exit/fork, sys_denied, bind/listen/accept/sendto, link/symlink/chmod/chown/truncate, watched reads",
    "fchmod/fchown/ftruncate, exec_map, sendmsg",
    "xattr, mknod, sendmmsg, exec_map via mprotect",
];

/// Attach the tracer for `cgroup_id`, call `start` to launch the sandbox, and
/// pump events until it exits. Returns the sandbox's exit code.
pub fn trace<W, S, F>(set: &Settings, mut logger: Logger<W>, start: F) -> Result<i32>
where
    W: Write,
    S: Supervised,
    F: FnOnce() -> Result<S>,
{
    bump_memlock();
    ensure_tracefs()?;
    let debug = std::env::var_os("AGENTBOX_BPF_DEBUG").is_some();
    let warn = || libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Warn, |_, m| eprint!("{m}"))));
    if debug {
        libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Debug, |_, msg| eprint!("{msg}"))));
    } else {
        // Failed attempts below are expected on some kernels; stay quiet.
        libbpf_rs::set_print(None);
    }

    // Request capture: sleepable fentry preferred, tracepoint fallback.
    // --deny: BPF LSM preferred (exec fails with EACCES), else kill on exec.
    let deny_modes: &[u32] = if set.deny.is_empty() { &[DENY_OFF] } else { &[DENY_LSM, DENY_KILL] };
    let mut objs: Vec<MaybeUninit<libbpf_rs::OpenObject>> = Vec::new();
    for _ in 0..8 * deny_modes.len() {
        objs.push(MaybeUninit::uninit());
    }
    let mut errors = Vec::new();
    let mut loaded = None;
    let mut slots = objs.iter_mut();
    'outer: for extras in [3u8, 2, 1, 0] {
        for capture in [Capture::Sleepable, Capture::Fallback] {
            for &deny in deny_modes {
                let slot = slots.next().expect("one slot per attempt");
                match open_load_attach(slot, set, matches!(capture, Capture::Sleepable), deny, extras) {
                    Ok(s) => {
                        loaded = Some((s, capture, deny, extras));
                        break 'outer;
                    }
                    Err(e) => errors.push(format!(
                        "{}{} + deny {}: {e:#}",
                        capture.name(),
                        format!(" + optional tiers 1..={extras}"),
                        deny_name(deny).unwrap_or("off")
                    )),
                }
            }
        }
    }
    if !debug {
        warn();
    }
    let Some((skel, capture, deny_mode, extras)) = loaded else {
        anyhow::bail!("could not load the BPF tracer:\n  {}", errors.join("\n  "));
    };
    logger.extras = extras >= 1;
    logger.hook_level = extras;
    if extras < 3 {
        eprintln!(
            "agentbox: WARNING: this kernel rejected some optional hooks; the log will have no \
             records for: {}. First error: {}",
            TIER_RECORDS[extras as usize..].join("; "),
            errors.first().map(String::as_str).unwrap_or("?")
        );
    }
    if matches!(capture, Capture::Fallback) {
        eprintln!(
            "agentbox: note: sleepable fentry unavailable; using tracepoint fallback \
             (requested argv may be marked unreadable). AGENTBOX_BPF_DEBUG=1 shows why."
        );
    }
    if deny_mode == DENY_KILL {
        eprintln!(
            "agentbox: note: BPF LSM unavailable; --deny falls back to killing denied \
             processes at exec (before they run any code)"
        );
    }

    let logger = Rc::new(RefCell::new(logger));
    let mut rb = RingBufferBuilder::new();
    {
        let logger = logger.clone();
        rb.add(&skel.maps.events, move |data: &[u8]| {
            if let Some(ev) = events::decode(data) {
                logger.borrow_mut().handle(ev);
            }
            0
        })?;
    }
    let rb = rb.build()?;

    // Tracer is live before the first sandboxed instruction runs.
    let mut child = start()?;

    let code = loop {
        rb.poll(Duration::from_millis(100))?;
        for r in child.side_records(false) {
            logger.borrow_mut().record(r);
        }
        logger.borrow_mut().flush();
        if let Some(code) = child.try_wait()? {
            break code;
        }
    };
    // Drain whatever arrived after the last poll.
    rb.consume()?;
    for r in child.side_records(true) {
        logger.borrow_mut().record(r);
    }

    let by_kind = read_drops(&skel);
    let drops: u64 = by_kind.iter().map(|(_, n)| n).sum();
    if drops > 0 {
        let what: Vec<String> = by_kind.iter().map(|(k, n)| format!("{n} {k}")).collect();
        eprintln!("agentbox: WARNING: {drops} events dropped (ring buffer full): {}", what.join(", "));
    }
    logger.borrow_mut().summary(&by_kind, code, capture.name(), deny_name(deny_mode));
    Ok(code)
}

#[derive(Clone, Copy)]
enum Capture {
    Sleepable,
    Fallback,
}

impl Capture {
    fn name(self) -> &'static str {
        match self {
            Capture::Sleepable => "sleepable",
            Capture::Fallback => "tracepoint_fallback",
        }
    }
}

fn deny_name(mode: u32) -> Option<&'static str> {
    match mode {
        DENY_LSM => Some("lsm"),
        DENY_KILL => Some("kill"),
        _ => None,
    }
}

fn open_load_attach<'obj>(
    obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    set: &Settings,
    sleepable: bool,
    deny_mode: u32,
    level: u8,
) -> Result<skel::ExecSkel<'obj>> {
    let extras = level >= 1;
    let mut open = ExecSkelBuilder::default().open(obj).context("opening BPF object")?;
    let ro = open.maps.rodata_data.as_deref_mut().context("BPF rodata missing")?;
    ro.target_cgid = set.cgroup_id;
    ro.capture_env = set.capture_env;
    ro.log_reads = set.log_reads;
    ro.deny_mode = deny_mode;
    let watch_reads = extras && !set.watch.is_empty();
    ro.watch_reads = watch_reads;
    let off = [OPTIONAL_PROGS, OPTIONAL_PROGS_2, OPTIONAL_PROGS_3][level.min(3) as usize..].concat();
    {
        for name in &off {
            if let Some(mut p) = open.open_object_mut().progs_mut().find(|p| p.name() == *name) {
                p.set_autoload(false);
            }
        }
    }
    open.progs.lsm_bprm_check.set_autoload(deny_mode == DENY_LSM);
    open.progs.fe_execve.set_autoload(sleepable);
    open.progs.fe_execveat.set_autoload(sleepable);
    open.progs.tp_enter_execve.set_autoload(!sleepable);
    open.progs.tp_enter_execveat.set_autoload(!sleepable);
    // BPF LSM hooks (src/bpf/exec.bpf.c, "LSM" section) are written but the
    // userspace decoding isn't yet, so they stay off for now.
    for name in [
        "lsm_file_open", "lsm_path_unlink", "lsm_path_rmdir", "lsm_path_mkdir",
        "lsm_path_rename", "lsm_path_link", "lsm_path_symlink", "lsm_path_chmod",
        "lsm_path_chown", "lsm_path_truncate", "lsm_socket_connect", "lsm_socket_bind",
        "lsm_socket_sendmsg", "tp_raw_sys_exit",
    ] {
        if let Some(mut p) = open.open_object_mut().progs_mut().find(|p| p.name() == name) {
            p.set_autoload(false);
        }
    }

    let mut skel = open.load().context(
        "loading BPF program (needs root/CAP_BPF+CAP_PERFMON and a kernel with BTF)",
    )?;
    // Rules go in before anything is attached.
    for k in set.deny.inode_keys() {
        let key = unsafe { std::slice::from_raw_parts(&k as *const _ as *const u8, size_of_val(&k)) };
        skel.maps.deny_ino.update(key, &1u32.to_ne_bytes(), MapFlags::ANY).context("deny_ino")?;
    }
    for k in set.deny.name_keys() {
        skel.maps.deny_name.update(&k, &1u32.to_ne_bytes(), MapFlags::ANY).context("deny_name")?;
    }
    if watch_reads {
        for k in set.watch.kernel_keys() {
            skel.maps.watch_name.update(&k, &1u32.to_ne_bytes(), MapFlags::ANY).context("watch_name")?;
        }
    }
    if extras {
        for (nr, _) in crate::watch::PRIVILEGED_SYSCALLS {
            let k = (*nr as u32).to_ne_bytes();
            skel.maps.watch_sys.update(&k, &1u32.to_ne_bytes(), MapFlags::ANY).context("watch_sys")?;
        }
    }
    skel.attach().context("attaching BPF programs")?;
    Ok(skel)
}

/// Dropped events per record type (only the non-zero ones).
fn read_drops(skel: &skel::ExecSkel) -> Vec<(&'static str, u64)> {
    let mut out: Vec<(&'static str, u64)> = Vec::new();
    for kind in 0..events::DROP_KINDS {
        let n: u64 = match skel.maps.drops.lookup_percpu(&kind.to_ne_bytes(), MapFlags::ANY) {
            Ok(Some(vals)) => vals
                .iter()
                .filter_map(|v| v.get(..8).map(|b| u64::from_ne_bytes(b.try_into().unwrap())))
                .sum(),
            _ => 0,
        };
        if n == 0 {
            continue;
        }
        let name = events::kind_name(kind);
        match out.iter_mut().find(|(k, _)| *k == name) {
            Some((_, t)) => *t += n,
            None => out.push((name, n)),
        }
    }
    out
}

/// libbpf resolves tracepoint ids through tracefs; minimal systems may not
/// have it mounted.
fn ensure_tracefs() -> Result<()> {
    use std::path::Path;
    if Path::new("/sys/kernel/tracing/events").exists()
        || Path::new("/sys/kernel/debug/tracing/events").exists()
    {
        return Ok(());
    }
    nix::mount::mount(
        Some("tracefs"),
        "/sys/kernel/tracing",
        Some("tracefs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV | nix::mount::MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mounting tracefs at /sys/kernel/tracing")
}

fn bump_memlock() {
    // Only matters on kernels < 5.11 (before memcg-based BPF accounting).
    let r = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) };
}
