//! Summarise what the agent changed by reading the overlay's upper layer.
//!
//!   A  added (no counterpart in the project)
//!   M  modified (content differs, or type changed)
//!   m  metadata only (copied up for a chmod/chown/touch; content identical)
//!   D  deleted (overlay whiteout)
//!   R  directory replaced (opaque dir: everything below came from the agent)

use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use anyhow::Result;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    pub path: PathBuf,
    pub code: char,
}

fn is_opaque(p: &Path) -> bool {
    let Ok(c) = CString::new(p.as_os_str().as_encoded_bytes()) else { return false };
    let mut buf = [0u8; 4];
    for name in [c"trusted.overlay.opaque", c"user.overlay.opaque"] {
        let n = unsafe {
            libc::lgetxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len())
        };
        if n > 0 && buf[0] == b'y' {
            return true;
        }
    }
    false
}

fn same_content(a: &Path, b: &Path) -> bool {
    let (Ok(ma), Ok(mb)) = (fs::symlink_metadata(a), fs::symlink_metadata(b)) else { return false };
    if ma.file_type().is_symlink() || mb.file_type().is_symlink() {
        return ma.file_type().is_symlink()
            && mb.file_type().is_symlink()
            && fs::read_link(a).ok() == fs::read_link(b).ok();
    }
    if !ma.is_file() || !mb.is_file() || ma.len() != mb.len() {
        return false;
    }
    let (Ok(mut fa), Ok(mut fb)) = (fs::File::open(a), fs::File::open(b)) else { return false };
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let (Ok(na), Ok(nb)) = (fa.read(&mut ba), fb.read(&mut bb)) else { return false };
        if na != nb || ba[..na] != bb[..nb] {
            return false;
        }
        if na == 0 {
            return true;
        }
    }
}

fn walk(upper: &Path, lower: &Path, rel: &Path, out: &mut Vec<Change>) -> Result<()> {
    for entry in fs::read_dir(upper.join(rel))? {
        let entry = entry?;
        let r = rel.join(entry.file_name());
        let up = upper.join(&r);
        let low = lower.join(&r);
        let meta = fs::symlink_metadata(&up)?;
        let ft = meta.file_type();
        let low_meta = fs::symlink_metadata(&low).ok();

        if ft.is_char_device() && meta.rdev() == 0 {
            if low_meta.is_some() {
                out.push(Change { path: r, code: 'D' });
            }
            continue;
        }
        if ft.is_dir() {
            match &low_meta {
                Some(lm) if lm.is_dir() && !is_opaque(&up) => {}
                Some(_) => out.push(Change { path: r.clone(), code: 'R' }),
                None => out.push(Change { path: r.clone(), code: 'A' }),
            }
            walk(upper, lower, &r, out)?;
            continue;
        }
        let code = match &low_meta {
            None => 'A',
            Some(_) if same_content(&up, &low) => 'm',
            Some(_) => 'M',
        };
        out.push(Change { path: r, code });
    }
    Ok(())
}

pub fn changes(upper: &Path, project: &Path) -> Result<Vec<Change>> {
    let mut out = Vec::new();
    walk(upper, project, Path::new(""), &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}
