//! `--deny` rules: binaries the sandbox may not execute.
//!
//! A rule is either a path (`/usr/bin/curl`) or a bare name (`curl`).
//!
//! - A path denies that file by identity (device + inode, as the kernel sees
//!   them), so symlinks, hard links and bind mounts of it are denied too.
//! - A bare name denies any binary whose file name is that name, and also
//!   (by identity) whatever the name resolves to on `$PATH`.
//!
//! The kernel checks the file it is about to load, not the argv or the path
//! the caller used. A renamed *copy* of a denied binary still gets through,
//! as does an interpreter running the same code from a script. This stops an
//! agent from casually reaching for a tool; it is not a sandbox boundary.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::events::DenyInoKey;

#[derive(Default)]
pub struct Rules {
    /// (dev, ino) -> file it was resolved from
    pub inodes: BTreeMap<(u64, u64), PathBuf>,
    pub names: Vec<String>,
    /// How each rule was resolved, printed at startup.
    pub notes: Vec<String>,
}

impl Rules {
    pub fn is_empty(&self) -> bool {
        self.inodes.is_empty() && self.names.is_empty()
    }

    pub fn inode_keys(&self) -> impl Iterator<Item = DenyInoKey> + '_ {
        self.inodes.keys().map(|&(dev, ino)| DenyInoKey { dev, ino })
    }

    /// Name as the BPF map key: NUL-padded to 256 bytes.
    pub fn name_keys(&self) -> impl Iterator<Item = [u8; 256]> + '_ {
        self.names.iter().map(|n| {
            let mut k = [0u8; 256];
            k[..n.len()].copy_from_slice(n.as_bytes());
            k
        })
    }
}

/// Kernel-internal dev_t (MKDEV: major << 20 | minor) of the superblock
/// holding `p`. On btrfs `stat` reports a per-subvolume device that differs
/// from the superblock's, so this goes through the mount instead:
/// statx(STATX_MNT_ID) -> /proc/self/mountinfo "major:minor".
fn sb_dev(p: &Path) -> Result<u64> {
    let c = CString::new(p.as_os_str().as_encoded_bytes())?;
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    const STATX_MNT_ID: u32 = 0x1000;
    let r = unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), 0, STATX_MNT_ID, &mut sx) };
    if r != 0 {
        bail!("statx {}: {}", p.display(), std::io::Error::last_os_error());
    }
    if sx.stx_mask & STATX_MNT_ID == 0 {
        bail!("kernel did not report a mount id for {}", p.display());
    }
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    for line in info.lines() {
        let mut f = line.split_whitespace();
        if f.next().and_then(|id| id.parse::<u64>().ok()) != Some(sx.stx_mnt_id) {
            continue;
        }
        let mm = f.nth(1).context("mountinfo: no major:minor")?;
        let (maj, min) = mm.split_once(':').context("mountinfo: bad major:minor")?;
        return Ok((maj.parse::<u64>()? << 20) | min.parse::<u64>()?);
    }
    bail!("mount {} of {} not in mountinfo", sx.stx_mnt_id, p.display())
}

fn identity(p: &Path) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((sb_dev(p)?, std::fs::metadata(p)?.ino()))
}

/// Sandbox path -> host path, for the few places that differ (the project
/// and $HOME mounts). Paths under those are overlays inside the sandbox, so
/// they can only be matched by name.
pub struct PathMap<'a> {
    pub overlays: Vec<(&'a Path, &'a Path)>, // (inside, host)
}

impl PathMap<'_> {
    fn overlay_of(&self, p: &Path) -> Option<PathBuf> {
        self.overlays.iter().find_map(|(inside, host)| {
            p.strip_prefix(inside).ok().map(|rest| host.join(rest))
        })
    }
}

fn add_name(r: &mut Rules, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
        bail!("--deny {name:?}: not a valid file name");
    }
    if !r.names.iter().any(|n| n == name) {
        r.names.push(name.to_owned());
    }
    Ok(())
}

pub fn build(specs: &[String], path_env: &str, map: &PathMap) -> Result<Rules> {
    let mut r = Rules::default();
    for spec in specs {
        if spec.contains('/') {
            let p = Path::new(spec);
            if !p.is_absolute() {
                bail!("--deny {spec}: paths must be absolute (as seen inside the sandbox)");
            }
            if let Some(host) = map.overlay_of(p) {
                // Overlay files have overlay inodes; fall back to the name.
                let name = p.file_name().and_then(|n| n.to_str()).context("--deny path has no file name")?;
                add_name(&mut r, name)?;
                r.notes.push(format!(
                    "{spec}: on a copy-on-write mount ({}), denied by name {name:?}",
                    host.display()
                ));
                continue;
            }
            let real = std::fs::canonicalize(p).with_context(|| format!("--deny {spec}"))?;
            let id = identity(&real)?;
            r.notes.push(if real != p {
                format!("{spec} -> {}", real.display())
            } else {
                spec.clone()
            });
            r.inodes.insert(id, real);
        } else {
            add_name(&mut r, spec)?;
            let mut found = Vec::new();
            for dir in path_env.split(':').filter(|d| d.starts_with('/')) {
                let cand = Path::new(dir).join(spec);
                if map.overlay_of(&cand).is_some() {
                    continue; // matched by name inside the sandbox
                }
                let Ok(real) = std::fs::canonicalize(&cand) else { continue };
                let Ok(meta) = std::fs::metadata(&real) else { continue };
                if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
                    continue;
                }
                let id = identity(&real)?;
                if r.inodes.insert(id, real.clone()).is_none() {
                    let other = real.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    found.push(if other != spec {
                        format!("{} (same file as {other}, which is denied too)", real.display())
                    } else {
                        real.display().to_string()
                    });
                }
            }
            r.notes.push(if found.is_empty() {
                format!("{spec}: by name (not found on $PATH)")
            } else {
                format!("{spec}: by name, and {}", found.join(", "))
            });
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_and_paths() {
        let map = PathMap { overlays: vec![(Path::new("/proj"), Path::new("/tmp"))] };
        let r = build(&["sh".into(), "/proj/build/tool".into()], "/usr/bin:/bin", &map).unwrap();
        assert!(r.names.contains(&"sh".to_string()));
        assert!(r.names.contains(&"tool".to_string()));
        assert!(!r.inodes.is_empty(), "sh should resolve on PATH");
        assert!(build(&["rel/path".into()], "", &map).is_err());
    }

    #[test]
    fn superblock_dev_matches_mountinfo() {
        // Must not be stat()'s st_dev on btrfs; just check it resolves.
        assert!(sb_dev(Path::new("/usr")).is_ok());
    }
}
