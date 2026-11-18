//! What gets logged beyond the defaults: reads of credential files, and
//! privileged syscalls that the sandbox refused.
//!
//! Read-only opens are too numerous to log wholesale (`--log-reads` does
//! that). The watch list names the files and directories whose reads always
//! are: `--home-from ~` puts real credentials in front of the agent, and
//! without this a read of `~/.ssh/id_ed25519` leaves no trace.
//!
//! Matching is two-stage. The kernel reports a read-only open when the file
//! or one of its (up to 8) parent directories has a watched *name*; this
//! module then checks the resolved path against the actual list, so a
//! directory that merely shares a name (`src/gh/`) is dropped.

use std::path::Path;

/// Relative to $HOME.
const HOME_DEFAULTS: &[&str] = &[
    ".ssh",
    ".aws",
    ".azure",
    ".gnupg",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".password-store",
    ".config/gh",
    ".config/gcloud",
    ".config/op",
    ".docker/config.json",
    ".local/share/keyrings",
    ".claude/.credentials.json",
];

/// File names watched wherever they are.
const NAME_DEFAULTS: &[&str] = &[".env"];

#[derive(Default, Clone)]
pub struct Watch {
    /// Absolute paths (as seen in the sandbox): the path itself and
    /// everything below it.
    prefixes: Vec<String>,
    /// Path components that match anywhere.
    names: Vec<String>,
}

impl Watch {
    pub fn defaults(home: &Path) -> Self {
        let mut w = Self::default();
        for p in HOME_DEFAULTS {
            w.prefixes.push(home.join(p).display().to_string());
        }
        w.names = NAME_DEFAULTS.iter().map(|s| s.to_string()).collect();
        w
    }

    /// `--watch-read`: an absolute path, or a bare name matched anywhere.
    pub fn add(&mut self, spec: &str) -> Result<(), String> {
        let t = spec.trim_end_matches('/');
        if t.is_empty() {
            return Err(format!("--watch-read {spec:?}: empty"));
        }
        if t.starts_with('/') {
            self.prefixes.push(t.to_owned());
        } else if t.contains('/') {
            return Err(format!("--watch-read {spec}: use an absolute path or a bare file name"));
        } else {
            self.names.push(t.to_owned());
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.names.is_empty()
    }

    pub fn matches(&self, path: &str) -> bool {
        self.prefixes
            .iter()
            .any(|p| path.strip_prefix(p.as_str()).is_some_and(|r| r.is_empty() || r.starts_with('/')))
            || path.split('/').any(|c| self.names.iter().any(|n| n == c))
    }

    /// Names for the kernel's coarse filter: the last component of each
    /// prefix (every file below it has that directory as an ancestor) and
    /// the bare names. NUL-padded to the BPF key size.
    pub fn kernel_keys(&self) -> Vec<[u8; 256]> {
        let last = self.prefixes.iter().filter_map(|p| p.rsplit('/').next());
        let mut names: Vec<&str> = last.chain(self.names.iter().map(String::as_str)).collect();
        names.sort();
        names.dedup();
        names
            .into_iter()
            .filter(|n| !n.is_empty() && n.len() < 256)
            .map(|n| {
                let mut k = [0u8; 256];
                k[..n.len()].copy_from_slice(n.as_bytes());
                k
            })
            .collect()
    }
}

/// Syscalls an unprivileged, sandboxed agent has no business succeeding at.
/// A failure (EPERM/EACCES/ENOSYS) of one of these is logged as `sys_denied`.
pub const PRIVILEGED_SYSCALLS: &[(libc::c_long, &str)] = &[
    (libc::SYS_mount, "mount"),
    (libc::SYS_umount2, "umount2"),
    (libc::SYS_pivot_root, "pivot_root"),
    (libc::SYS_chroot, "chroot"),
    (libc::SYS_open_tree, "open_tree"),
    (libc::SYS_move_mount, "move_mount"),
    (libc::SYS_fsopen, "fsopen"),
    (libc::SYS_fsmount, "fsmount"),
    (libc::SYS_mount_setattr, "mount_setattr"),
    (libc::SYS_unshare, "unshare"),
    (libc::SYS_setns, "setns"),
    (libc::SYS_ptrace, "ptrace"),
    (libc::SYS_process_vm_readv, "process_vm_readv"),
    (libc::SYS_process_vm_writev, "process_vm_writev"),
    (libc::SYS_bpf, "bpf"),
    (libc::SYS_perf_event_open, "perf_event_open"),
    (libc::SYS_userfaultfd, "userfaultfd"),
    (libc::SYS_io_uring_setup, "io_uring_setup"),
    (libc::SYS_keyctl, "keyctl"),
    (libc::SYS_add_key, "add_key"),
    (libc::SYS_request_key, "request_key"),
    (libc::SYS_init_module, "init_module"),
    (libc::SYS_finit_module, "finit_module"),
    (libc::SYS_delete_module, "delete_module"),
    (libc::SYS_kexec_load, "kexec_load"),
    (libc::SYS_reboot, "reboot"),
    (libc::SYS_swapon, "swapon"),
    (libc::SYS_swapoff, "swapoff"),
    (libc::SYS_setuid, "setuid"),
    (libc::SYS_setgid, "setgid"),
    (libc::SYS_setreuid, "setreuid"),
    (libc::SYS_setregid, "setregid"),
    (libc::SYS_setresuid, "setresuid"),
    (libc::SYS_setresgid, "setresgid"),
    (libc::SYS_setgroups, "setgroups"),
    (libc::SYS_capset, "capset"),
    (libc::SYS_mknodat, "mknodat"),
    (libc::SYS_sethostname, "sethostname"),
    (libc::SYS_setdomainname, "setdomainname"),
    (libc::SYS_settimeofday, "settimeofday"),
    (libc::SYS_clock_settime, "clock_settime"),
    (libc::SYS_open_by_handle_at, "open_by_handle_at"),
];

pub fn syscall_name(nr: u32) -> Option<&'static str> {
    PRIVILEGED_SYSCALLS.iter().find(|(n, _)| *n == nr as libc::c_long).map(|(_, s)| *s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let mut w = Watch::defaults(Path::new("/home/u"));
        assert!(w.matches("/home/u/.ssh/id_ed25519"));
        assert!(w.matches("/home/u/.ssh"));
        assert!(w.matches("/home/u/.config/gh/hosts.yml"));
        assert!(w.matches("/home/u/proj/.env"));
        assert!(!w.matches("/home/u/.sshx/key"));
        assert!(!w.matches("/home/u/proj/src/gh/main.go"));
        assert!(!w.matches("/home/u/proj/.env.example"));
        w.add("/srv/secrets/").unwrap();
        w.add("token.json").unwrap();
        assert!(w.matches("/srv/secrets/a"));
        assert!(w.matches("/x/token.json"));
        assert!(w.add("rel/path").is_err());
        // Coarse kernel names cover every prefix.
        let keys = w.kernel_keys();
        let has = |n: &str| keys.iter().any(|k| &k[..n.len()] == n.as_bytes() && k[n.len()] == 0);
        assert!(has(".ssh") && has("gh") && has(".env") && has("secrets") && has("config.json"));
    }
}
