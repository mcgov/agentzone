//! Mirrors of the event structs in `src/bpf/events.h`, plus decoding helpers.
//! Sizes and offsets are asserted against the values the C compiler produces.

use std::mem::{offset_of, size_of};

pub const FILENAME_LEN: usize = 4096;
pub const ARGBUF: usize = 8192;
pub const ARG_MAX_ONE: usize = 4096;
pub const PATHBUF: usize = 4096;
pub const PATH_ARR: usize = PATHBUF + 255 + 1;

pub const REQ_TRUNCATED: u32 = 0x1;
pub const REQ_UNREADABLE: u32 = 0x2;

pub const EV_EXEC_REQUEST: u32 = 1;
pub const EV_EXEC: u32 = 2;
pub const EV_EXEC_RESULT: u32 = 3;
pub const EV_FILE: u32 = 4;
pub const EV_CONNECT: u32 = 5;
pub const EV_EXEC_DENIED: u32 = 9;

pub const DENY_OFF: u32 = 0;
pub const DENY_LSM: u32 = 1;
pub const DENY_KILL: u32 = 2;
pub const DENY_BY_INODE: u32 = 1;
pub const DENY_BY_NAME: u32 = 2;

pub const FOP_OPEN: u32 = 1;
pub const FOP_UNLINK: u32 = 2;
pub const FOP_RMDIR: u32 = 3;
pub const FOP_RENAME: u32 = 4;
pub const FOP_MKDIR: u32 = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    pub kind: u32,
    pub tid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub ns_pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad0: u32,
    pub ts_boot_ns: u64,
}

#[repr(C)]
pub struct ExecRequest {
    pub h: Header,
    pub comm: [u8; 16],
    pub dirfd: i32,
    pub flags: u32,
    pub is_execveat: u32,
    pub argc: u32,
    pub argv_len: u32,
    pub req_flags: u32,
    pub cwd_off: u32,
    pub _pad1: u32,
    pub filename: [u8; FILENAME_LEN],
    pub argv: [u8; ARGBUF + ARG_MAX_ONE],
    pub cwd: [u8; PATH_ARR],
}

#[repr(C)]
pub struct Exec {
    pub h: Header,
    pub comm: [u8; 16],
    pub old_tid: u32,
    pub argv_len: u32,
    pub argv_truncated: u32,
    pub env_len: u32,
    pub env_truncated: u32,
    pub exe_off: u32,
    pub cwd_off: u32,
    pub denied: u32,
    pub filename: [u8; FILENAME_LEN],
    pub argv: [u8; ARGBUF],
    pub env: [u8; ARGBUF],
    pub exe: [u8; PATH_ARR],
    pub cwd: [u8; PATH_ARR],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecResult {
    pub h: Header,
    pub ret: i64,
}

#[repr(C)]
pub struct FileEvent {
    pub h: Header,
    pub op: u32,
    pub dirfd: i32,
    pub dirfd2: i32,
    pub flags: u32,
    pub mode: u32,
    pub req_flags: u32,
    pub ret: i64,
    pub dir_off: u32,
    pub dir2_off: u32,
    pub actual_off: u32,
    pub _pad: u32,
    pub path: [u8; PATHBUF],
    pub path2: [u8; PATHBUF],
    pub dir: [u8; PATH_ARR],
    pub dir2: [u8; PATH_ARR],
    pub actual: [u8; PATH_ARR],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub h: Header,
    pub fd: i32,
    pub req_flags: u32,
    pub ret: i64,
    pub addrlen: u32,
    pub peer_family: u16,
    pub peer_port: u16, // network byte order
    pub sock_type: u32,
    pub _pad: u32,
    pub peer_addr: [u8; 16],
    pub req_addr: [u8; 128],
}

#[repr(C)]
pub struct ExecDenied {
    pub h: Header,
    pub comm: [u8; 16],
    pub rule: u32,
    pub exe_off: u32,
    pub name: [u8; 256],
    pub exe: [u8; PATH_ARR],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DenyInoKey {
    pub dev: u64,
    pub ino: u64,
}

// Values printed by compiling events.h with gcc (see README).
const _: () = {
    assert!(size_of::<Header>() == 40);
    assert!(size_of::<ExecRequest>() == 20824);
    assert!(offset_of!(ExecRequest, filename) == 88);
    assert!(offset_of!(ExecRequest, argv) == 4184);
    assert!(offset_of!(ExecRequest, cwd) == 16472);
    assert!(size_of::<Exec>() == 29272);
    assert!(offset_of!(Exec, filename) == 88);
    assert!(offset_of!(Exec, argv) == 4184);
    assert!(offset_of!(Exec, env) == 12376);
    assert!(offset_of!(Exec, exe) == 20568);
    assert!(offset_of!(Exec, cwd) == 24920);
    assert!(size_of::<ExecResult>() == 48);
    assert!(size_of::<FileEvent>() == 21336);
    assert!(offset_of!(FileEvent, ret) == 64);
    assert!(offset_of!(FileEvent, path) == 88);
    assert!(offset_of!(FileEvent, path2) == 4184);
    assert!(offset_of!(FileEvent, dir) == 8280);
    assert!(offset_of!(FileEvent, dir2) == 12632);
    assert!(offset_of!(FileEvent, actual) == 16984);
    assert!(size_of::<ConnectEvent>() == 216);
    assert!(offset_of!(ConnectEvent, ret) == 48);
    assert!(offset_of!(ConnectEvent, peer_family) == 60);
    assert!(offset_of!(ConnectEvent, peer_addr) == 72);
    assert!(offset_of!(ConnectEvent, req_addr) == 88);
    assert!(size_of::<ExecDenied>() == 4672);
    assert!(offset_of!(ExecDenied, name) == 64);
    assert!(offset_of!(ExecDenied, exe) == 320);
};

pub enum Event {
    Request(Box<ExecRequest>),
    Exec(Box<Exec>),
    Result(ExecResult),
    File(Box<FileEvent>),
    Connect(ConnectEvent),
    Denied(Box<ExecDenied>),
}

fn read_boxed<T>(data: &[u8]) -> Option<Box<T>> {
    if data.len() < size_of::<T>() {
        return None;
    }
    // These structs are tens of KB, so build them on the heap.
    let layout = std::alloc::Layout::new::<T>();
    unsafe {
        let p = std::alloc::alloc(layout) as *mut T;
        if p.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), p as *mut u8, size_of::<T>());
        Some(Box::from_raw(p))
    }
}

pub fn decode(data: &[u8]) -> Option<Event> {
    if data.len() < 4 {
        return None;
    }
    let kind = u32::from_ne_bytes(data[..4].try_into().ok()?);
    match kind {
        EV_EXEC_REQUEST => read_boxed::<ExecRequest>(data).map(Event::Request),
        EV_EXEC => read_boxed::<Exec>(data).map(Event::Exec),
        EV_EXEC_RESULT => read_boxed::<ExecResult>(data).map(|b| Event::Result(*b)),
        EV_FILE => read_boxed::<FileEvent>(data).map(Event::File),
        EV_CONNECT => read_boxed::<ConnectEvent>(data).map(|b| Event::Connect(*b)),
        EV_EXEC_DENIED => read_boxed::<ExecDenied>(data).map(Event::Denied),
        _ => None,
    }
}

/// Render bytes as a string. Invalid UTF-8 bytes become `\xNN`; the bool says
/// whether that happened, so the log can flag the value as not byte-exact.
pub fn render(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_owned(), false),
        Err(_) => {
            let mut out = String::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                match std::str::from_utf8(rest) {
                    Ok(s) => {
                        out.push_str(s);
                        break;
                    }
                    Err(e) => {
                        let (good, bad) = rest.split_at(e.valid_up_to());
                        out.push_str(std::str::from_utf8(good).unwrap());
                        let n = e.error_len().unwrap_or(bad.len());
                        for b in &bad[..n] {
                            out.push_str(&format!("\\x{b:02x}"));
                        }
                        rest = &bad[n..];
                    }
                }
            }
            (out, true)
        }
    }
}

/// NUL-terminated C string out of a fixed buffer.
pub fn cstr(buf: &[u8]) -> (String, bool) {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    render(&buf[..end])
}

/// Split a NUL-separated block (argv/envp layout) into strings.
pub fn split_nul(buf: &[u8]) -> (Vec<String>, bool) {
    let mut lossy = false;
    let mut v = Vec::new();
    let body = buf.strip_suffix(&[0]).unwrap_or(buf);
    if body.is_empty() && buf.is_empty() {
        return (v, false);
    }
    for part in body.split(|&b| b == 0) {
        let (s, l) = render(part);
        lossy |= l;
        v.push(s);
    }
    (v, lossy)
}

/// Path written backwards by the BPF resolver: lives at buf[off..PATHBUF].
pub fn path_at(buf: &[u8], off: u32) -> (String, bool) {
    let off = (off as usize).min(PATHBUF);
    render(&buf[off..PATHBUF])
}
