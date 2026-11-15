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
}

/// Attach the tracer for `cgroup_id`, call `start` to launch the sandbox, and
/// pump events until it exits. Returns the sandbox's exit code.
pub fn trace<W, S, F>(set: &Settings, logger: Logger<W>, start: F) -> Result<i32>
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
    for _ in 0..2 * deny_modes.len() {
        objs.push(MaybeUninit::uninit());
    }
    let mut errors = Vec::new();
    let mut loaded = None;
    let mut slots = objs.iter_mut();
    'outer: for capture in [Capture::Sleepable, Capture::Fallback] {
        for &deny in deny_modes {
            let slot = slots.next().expect("one slot per attempt");
            match open_load_attach(slot, set, matches!(capture, Capture::Sleepable), deny) {
                Ok(s) => {
                    loaded = Some((s, capture, deny));
                    break 'outer;
                }
                Err(e) => errors.push(format!("{} + deny {}: {e:#}", capture.name(), deny_name(deny).unwrap_or("off"))),
            }
        }
    }
    if !debug {
        warn();
    }
    let Some((skel, capture, deny_mode)) = loaded else {
        anyhow::bail!("could not load the BPF tracer:\n  {}", errors.join("\n  "));
    };
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

    let drops = read_drops(&skel);
    if drops > 0 {
        eprintln!("agentbox: warning: {drops} events dropped (ring buffer full)");
    }
    logger.borrow_mut().summary(drops, code, capture.name(), deny_name(deny_mode));
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
) -> Result<skel::ExecSkel<'obj>> {
    let mut open = ExecSkelBuilder::default().open(obj).context("opening BPF object")?;
    let ro = open.maps.rodata_data.as_deref_mut().context("BPF rodata missing")?;
    ro.target_cgid = set.cgroup_id;
    ro.capture_env = set.capture_env;
    ro.log_reads = set.log_reads;
    ro.deny_mode = deny_mode;
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
    skel.attach().context("attaching BPF programs")?;
    Ok(skel)
}

fn read_drops(skel: &skel::ExecSkel) -> u64 {
    let key = 0u32.to_ne_bytes();
    match skel.maps.drops.lookup_percpu(&key, MapFlags::ANY) {
        Ok(Some(vals)) => vals
            .iter()
            .filter_map(|v| v.get(..8).map(|b| u64::from_ne_bytes(b.try_into().unwrap())))
            .sum(),
        _ => 0,
    }
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
