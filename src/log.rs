//! Turns raw BPF events into JSONL records.
//!
//! Each successful exec produces one `exec` record holding the authoritative
//! post-exec view (from the new process image) plus, under `requested`, what
//! the caller passed to execve. A failed exec produces an `exec_failed` record
//! with the request and the errno.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use serde_json::{json, Map, Value};

use crate::events::{
    cstr, path_at, split_nul, ConnectEvent, Event, Exec, ExecDenied, ExecRequest, ExecResult, FileEvent,
    Header, DENY_BY_INODE, DENY_BY_NAME, FOP_MKDIR, FOP_OPEN, FOP_RENAME, FOP_RMDIR, FOP_UNLINK, REQ_TRUNCATED, REQ_UNREADABLE,
};

struct Pending {
    syscall: &'static str,
    filename: String,
    argv: Vec<String>,
    argv_truncated: bool,
    unreadable: bool,
    dirfd: i32,
    flags: u32,
    cwd: String,
    lossy: bool,
}

/// ENOENT/EACCES failures held back per thread: if the same thread then
/// execs the same argv successfully, they were just PATH-search misses
/// (execvp trying each directory) and get folded into that exec record.
struct Held {
    argv: Vec<String>,
    records: Vec<Map<String, Value>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum EnvMode {
    /// Variable names only (shows what was passed without storing secrets)
    Names,
    /// Names and values
    Full,
}

pub struct Logger<W: Write> {
    out: W,
    env_mode: Option<EnvMode>,
    pub files: u64,
    pub connects: u64,
    pending: HashMap<u32, Pending>,
    held: HashMap<u32, Held>,
    boot_to_unix_ns: i128,
    pub execs: u64,
    pub failed: u64,
    pub mismatches: u64,
    pub denied: u64,
    pub http: u64,
    /// Threads whose exec was just refused by --deny: the EACCES that the
    /// syscall then returns is already reported by the exec_denied record.
    denied_tids: HashSet<u32>,
}

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// RFC 3339 UTC timestamp with microseconds.
pub(crate) fn rfc3339(unix_ns: i128) -> String {
    let secs = unix_ns.div_euclid(1_000_000_000) as i64;
    let micros = (unix_ns.rem_euclid(1_000_000_000) / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        sod / 3600,
        (sod / 60) % 60,
        sod % 60
    )
}

fn strerror(errno: i64) -> String {
    let p = unsafe { libc::strerror(errno as i32) };
    if p.is_null() {
        return format!("errno {errno}");
    }
    unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// How the argv the kernel loaded relates to the argv the caller asked for.
fn argv_relation(req: &Pending, actual: &[String], actual_truncated: bool) -> &'static str {
    if req.argv == actual {
        return "identical";
    }
    if req.unreadable {
        return "unknown";
    }
    if req.argv_truncated || actual_truncated {
        // The two sides cut off at different points (element count vs bytes),
        // and the last element on either side may be partial: compare only
        // the complete elements both sides have.
        let n = (req.argv.len() - req.argv_truncated as usize)
            .min(actual.len() - actual_truncated as usize);
        return if req.argv[..n] == actual[..n] { "truncated_prefix_match" } else { "different" };
    }
    // #! scripts: kernel drops argv[0], prepends interpreter [+ optional arg]
    // and the script path. So actual == [interp, (arg)?, filename, req[1..]...]
    let tail = req.argv.get(1..).unwrap_or(&[]);
    if actual.len() > tail.len() && actual.ends_with(tail) {
        let head = &actual[..actual.len() - tail.len()];
        if head.len() >= 2 && head.len() <= 3 && head.last() == Some(&req.filename) {
            return "interpreter_prefixed";
        }
    }
    "different"
}

impl<W: Write> Logger<W> {
    pub fn new(out: W, env_mode: Option<EnvMode>) -> Self {
        let boot_to_unix_ns = clock_ns(libc::CLOCK_REALTIME) - clock_ns(libc::CLOCK_BOOTTIME);
        Self { out, env_mode, files: 0, connects: 0, pending: HashMap::new(), held: HashMap::new(), boot_to_unix_ns, execs: 0, failed: 0, mismatches: 0, denied: 0, http: 0, denied_tids: HashSet::new() }
    }

    fn base(&self, kind: &str, h: &Header, comm: Option<&[u8]>) -> Map<String, Value> {
        let unix = self.boot_to_unix_ns + h.ts_boot_ns as i128;
        let mut m = Map::new();
        m.insert("type".into(), json!(kind));
        m.insert("time".into(), json!(rfc3339(unix)));
        m.insert("pid".into(), json!(h.pid));
        m.insert("tid".into(), json!(h.tid));
        m.insert("ppid".into(), json!(h.ppid));
        m.insert("sandbox_pid".into(), json!(h.ns_pid));
        m.insert("uid".into(), json!(h.uid));
        m.insert("gid".into(), json!(h.gid));
        if let Some(c) = comm {
            m.insert("comm".into(), json!(cstr(c).0));
        }
        m
    }

    fn emit(&mut self, m: Map<String, Value>) {
        let _ = serde_json::to_writer(&mut self.out, &Value::Object(m));
        let _ = self.out.write_all(b"\n");
    }

    pub fn flush(&mut self) {
        let _ = self.out.flush();
    }

    pub fn handle(&mut self, ev: Event) {
        match ev {
            Event::Request(r) => self.on_request(&r),
            Event::Exec(e) => self.on_exec(&e),
            Event::Result(r) => self.on_result(&r),
            Event::File(f) => self.on_file(&f),
            Event::Connect(c) => self.on_connect(&c),
            Event::Denied(d) => self.on_denied(&d),
        }
    }

    /// A record from outside the BPF stream (the HTTP proxy).
    pub fn record(&mut self, m: Map<String, Value>) {
        if m.get("type").and_then(Value::as_str) == Some("http") {
            self.http += 1;
        }
        self.emit(m);
    }

    fn deny_rule(rule: u32) -> &'static str {
        match rule {
            DENY_BY_INODE => "file",
            DENY_BY_NAME => "name",
            _ => "unknown",
        }
    }

    fn on_denied(&mut self, d: &ExecDenied) {
        self.denied += 1;
        let (exe, l1) = path_at(&d.exe, d.exe_off);
        let (name, l2) = cstr(&d.name);
        let mut m = self.base("exec_denied", &d.h, Some(&d.comm));
        m.insert("exe".into(), json!(exe));
        m.insert("deny_rule".into(), json!(Self::deny_rule(d.rule)));
        m.insert("deny_name".into(), json!(name));
        m.insert("enforcement".into(), json!("refused"));
        m.insert("errno".into(), json!(libc::EACCES));
        if l1 || l2 {
            m.insert("non_utf8".into(), json!(true));
        }
        // PATH-search misses before the denied attempt belong to it.
        if let Some(h) = self.held.remove(&d.h.tid) {
            let misses: Vec<Value> = h.records.iter().map(|r| r["requested"]["filename"].clone()).collect();
            self.failed -= misses.len() as u64;
            m.insert("path_search_misses".into(), Value::Array(misses));
        }
        let req = self.pending.remove(&d.h.tid);
        m.insert("requested".into(), req.as_ref().map(Self::requested_json).unwrap_or(Value::Null));
        self.denied_tids.insert(d.h.tid);
        self.emit(m);
    }

    fn on_request(&mut self, r: &ExecRequest) {
        self.denied_tids.remove(&r.h.tid);
        let (filename, l1) = cstr(&r.filename);
        let n = (r.argv_len as usize).min(r.argv.len());
        let (argv, l2) = split_nul(&r.argv[..n]);
        let (cwd, l3) = path_at(&r.cwd, r.cwd_off);
        if self.held.get(&r.h.tid).is_some_and(|h| h.argv != argv) {
            self.flush_held(r.h.tid);
        }
        // A thread that calls execve again (after a failure) replaces its entry.
        self.pending.insert(
            r.h.tid,
            Pending {
                syscall: if r.is_execveat != 0 { "execveat" } else { "execve" },
                filename,
                argv,
                argv_truncated: r.req_flags & REQ_TRUNCATED != 0,
                unreadable: r.req_flags & REQ_UNREADABLE != 0,
                dirfd: r.dirfd,
                flags: r.flags,
                cwd,
                lossy: l1 || l2 || l3,
            },
        );
    }

    fn requested_json(p: &Pending) -> Value {
        let mut m = Map::new();
        m.insert("syscall".into(), json!(p.syscall));
        m.insert("filename".into(), json!(p.filename));
        m.insert("argv".into(), json!(p.argv));
        m.insert("cwd".into(), json!(p.cwd));
        if p.syscall == "execveat" {
            m.insert("dirfd".into(), json!(p.dirfd));
            m.insert("flags".into(), json!(p.flags));
        }
        if p.argv_truncated {
            m.insert("argv_truncated".into(), json!(true));
        }
        if p.unreadable {
            // Fallback capture couldn't read some of the caller's memory;
            // argv above is incomplete. The exec record is unaffected.
            m.insert("unreadable".into(), json!(true));
        }
        if p.lossy {
            m.insert("non_utf8".into(), json!(true));
        }
        Value::Object(m)
    }

    fn on_exec(&mut self, e: &Exec) {
        self.execs += 1;
        let (filename, l1) = cstr(&e.filename);
        let an = (e.argv_len as usize).min(e.argv.len());
        let (argv, l2) = split_nul(&e.argv[..an]);
        let (exe, l3) = path_at(&e.exe, e.exe_off);
        let (cwd, l4) = path_at(&e.cwd, e.cwd_off);

        let mut m = self.base("exec", &e.h, Some(&e.comm));
        m.insert("exe".into(), json!(exe));
        m.insert("cwd".into(), json!(cwd));
        m.insert("argv".into(), json!(argv));
        m.insert("filename".into(), json!(filename));
        if e.argv_truncated != 0 {
            m.insert("argv_truncated".into(), json!(true));
        }
        let mut lossy = l1 || l2 || l3 || l4;
        if e.env_len > 0 {
            let en = (e.env_len as usize).min(e.env.len());
            let (mut env, l5) = split_nul(&e.env[..en]);
            lossy |= l5;
            if self.env_mode == Some(EnvMode::Names) {
                for v in env.iter_mut() {
                    if let Some(i) = v.find('=') {
                        v.truncate(i);
                    }
                }
            }
            m.insert("env".into(), json!(env));
            if e.env_truncated != 0 {
                m.insert("env_truncated".into(), json!(true));
            }
        }
        if lossy {
            m.insert("non_utf8".into(), json!(true));
        }
        if e.old_tid != e.h.tid {
            m.insert("exec_from_tid".into(), json!(e.old_tid));
        }
        if e.denied != 0 {
            // Kill mode (no BPF LSM): loaded, then SIGKILLed before running.
            self.denied += 1;
            m.insert("denied".into(), json!(true));
            m.insert("deny_rule".into(), json!(Self::deny_rule(e.denied)));
            m.insert("enforcement".into(), json!("killed"));
        }
        self.denied_tids.remove(&e.old_tid);

        let req = self.pending.remove(&e.old_tid);
        if let Some(h) = self.held.remove(&e.old_tid) {
            if req.as_ref().is_some_and(|p| p.argv == h.argv) {
                let misses: Vec<Value> = h
                    .records
                    .iter()
                    .map(|r| r["requested"]["filename"].clone())
                    .collect();
                self.failed -= misses.len() as u64;
                m.insert("path_search_misses".into(), Value::Array(misses));
            } else {
                for r in h.records {
                    self.emit(r);
                }
            }
        }
        match req {
            Some(p) => {
                let rel = argv_relation(&p, &argv, e.argv_truncated != 0);
                if rel == "different" {
                    self.mismatches += 1;
                }
                m.insert("argv_vs_request".into(), json!(rel));
                m.insert("requested".into(), Self::requested_json(&p));
            }
            None => {
                // Request event lost (ring buffer full) or exec'd before the
                // tracer attached. The exec record itself is still complete.
                m.insert("requested".into(), Value::Null);
            }
        }
        self.emit(m);
    }

    fn on_result(&mut self, r: &ExecResult) {
        if self.denied_tids.remove(&r.h.tid) && r.ret == -(libc::EACCES as i64) {
            return;
        }
        self.failed += 1;
        let errno = -r.ret;
        let mut m = self.base("exec_failed", &r.h, None);
        m.insert("errno".into(), json!(errno));
        m.insert("error".into(), json!(strerror(errno)));
        let req = self.pending.remove(&r.h.tid);
        let holdable = matches!(errno as i32, libc::ENOENT | libc::EACCES | libc::ENOTDIR);
        m.insert("requested".into(), req.as_ref().map(Self::requested_json).unwrap_or(Value::Null));
        match req {
            Some(p) if holdable => {
                let h = self.held.entry(r.h.tid).or_insert_with(|| Held { argv: p.argv.clone(), records: vec![] });
                if h.argv != p.argv {
                    let old = std::mem::replace(h, Held { argv: p.argv, records: vec![] });
                    for rec in old.records {
                        self.emit(rec);
                    }
                }
                self.held.get_mut(&r.h.tid).unwrap().records.push(m);
            }
            _ => {
                self.flush_held(r.h.tid);
                self.emit(m);
            }
        }
    }

    fn flush_held(&mut self, tid: u32) {
        if let Some(h) = self.held.remove(&tid) {
            for r in h.records {
                self.emit(r);
            }
        }
    }

    fn result_fields(m: &mut Map<String, Value>, ret: i64) {
        if ret < 0 {
            m.insert("errno".into(), json!(-ret));
            m.insert("error".into(), json!(strerror(-ret)));
        }
    }

    fn on_file(&mut self, f: &FileEvent) {
        // pid 1 in the sandbox is agentbox's own init building the root.
        if f.h.ns_pid == 1 {
            return;
        }
        self.files += 1;
        let op = match f.op {
            FOP_OPEN => "open",
            FOP_UNLINK => "unlink",
            FOP_RMDIR => "rmdir",
            FOP_RENAME => "rename",
            FOP_MKDIR => "mkdir",
            _ => "unknown",
        };
        let (path, l1) = cstr(&f.path);
        let (dir, l2) = path_at(&f.dir, f.dir_off);
        let mut m = self.base("file", &f.h, None);
        m.insert("op".into(), json!(op));
        m.insert("path".into(), json!(path));
        m.insert("target".into(), json!(lexical_target(&dir, &path)));
        if !path.starts_with('/') {
            m.insert("relative_to".into(), json!(dir));
        }
        let mut lossy = l1 || l2;
        match f.op {
            FOP_OPEN => {
                m.insert("flags".into(), json!(open_flags(f.flags)));
                if f.flags & (O_CREAT | O_TMPFILE) != 0 {
                    m.insert("mode".into(), json!(format!("{:04o}", f.mode & 0o7777)));
                }
                if f.ret >= 0 {
                    let (actual, l3) = path_at(&f.actual, f.actual_off);
                    lossy |= l3;
                    m.insert("fd".into(), json!(f.ret));
                    // Where the kernel says the fd points, after symlinks and
                    // mounts. A mismatch with `target` means the name led
                    // somewhere else (symlink, a rename race, O_TMPFILE...).
                    let redirected = actual != lexical_target(&dir, &path);
                    m.insert("resolved".into(), json!(actual));
                    m.insert("resolved_differs".into(), json!(redirected));
                }
            }
            FOP_MKDIR => {
                m.insert("mode".into(), json!(format!("{:04o}", f.mode & 0o7777)));
            }
            FOP_RENAME => {
                let (new, l3) = cstr(&f.path2);
                let (dir2, l4) = path_at(&f.dir2, f.dir2_off);
                lossy |= l3 || l4;
                m.insert("new_path".into(), json!(new));
                m.insert("new_target".into(), json!(lexical_target(&dir2, &new)));
                if f.flags != 0 {
                    m.insert("rename_flags".into(), json!(rename_flags(f.flags)));
                }
            }
            _ => {}
        }
        Self::result_fields(&mut m, f.ret);
        if f.req_flags & REQ_UNREADABLE != 0 {
            m.insert("unreadable".into(), json!(true));
        }
        if lossy {
            m.insert("non_utf8".into(), json!(true));
        }
        self.emit(m);
    }

    fn on_connect(&mut self, c: &ConnectEvent) {
        if c.h.ns_pid == 1 {
            return;
        }
        self.connects += 1;
        let mut m = self.base("connect", &c.h, None);
        m.insert("fd".into(), json!(c.fd));
        let (family, requested) = decode_sockaddr(&c.req_addr, c.addrlen as usize);
        m.insert("family".into(), json!(family));
        m.insert("socket".into(), json!(sock_type(c.sock_type)));
        m.insert("requested".into(), requested.clone().map(Value::from).unwrap_or(Value::Null));
        let in_progress = c.ret == -(libc::EINPROGRESS as i64);
        let failed = c.ret < 0 && !in_progress;
        // After a failed connect the socket's peer fields are leftovers
        // (port reset to 0, etc.), so there's nothing meaningful to compare.
        let peer = if failed { None } else { kernel_peer(c) };
        m.insert("peer".into(), peer.clone().map(Value::from).unwrap_or(Value::Null));
        let rel = if failed {
            "failed"
        } else if c.req_flags & REQ_UNREADABLE != 0 {
            "unknown"
        } else {
            match (&peer, &requested) {
                (None, _) => "no_peer",
                (Some(p), Some(r)) if p == r => "identical",
                _ => "different",
            }
        };
        m.insert("peer_vs_request".into(), json!(rel));
        if in_progress {
            m.insert("in_progress".into(), json!(true));
        } else {
            Self::result_fields(&mut m, c.ret);
        }
        if c.req_flags & REQ_UNREADABLE != 0 {
            m.insert("unreadable".into(), json!(true));
        }
        self.emit(m);
    }

    pub fn summary(&mut self, drops: u64, exit_code: i32, capture: &str, deny: Option<&str>) {
        let tids: Vec<u32> = self.held.keys().copied().collect();
        for t in tids {
            self.flush_held(t);
        }
        let mut m = Map::new();
        m.insert("type".into(), json!("summary"));
        m.insert("time".into(), json!(rfc3339(clock_ns(libc::CLOCK_REALTIME))));
        m.insert("exit_code".into(), json!(exit_code));
        m.insert("execs".into(), json!(self.execs));
        m.insert("failed_execs".into(), json!(self.failed));
        m.insert("argv_mismatches".into(), json!(self.mismatches));
        m.insert("dropped_events".into(), json!(drops));
        m.insert("request_capture".into(), json!(capture));
        m.insert("file_ops".into(), json!(self.files));
        m.insert("connects".into(), json!(self.connects));
        if let Some(d) = deny {
            m.insert("deny_enforcement".into(), json!(d));
            m.insert("denied_execs".into(), json!(self.denied));
        }
        m.insert("http_requests".into(), json!(self.http));
        self.emit(m);
        self.flush();
    }
}

// ------------------------------------------------------------- formatting

const O_CREAT: u32 = 0o100;
const O_TMPFILE: u32 = 0o20000000;

fn open_flags(f: u32) -> Vec<&'static str> {
    let mut v = vec![match f & 3 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "O_ACCMODE?",
    }];
    for (bit, name) in [
        (0o100, "O_CREAT"),
        (0o200, "O_EXCL"),
        (0o1000, "O_TRUNC"),
        (0o2000, "O_APPEND"),
        (0o4000, "O_NONBLOCK"),
        (0o200000, "O_DIRECTORY"),
        (0o400000, "O_NOFOLLOW"),
        (0o2000000, "O_CLOEXEC"),
        (0o10000000, "O_PATH"),
    ] {
        if f & bit != 0 {
            v.push(name);
        }
    }
    if f & O_TMPFILE == O_TMPFILE {
        v.push("O_TMPFILE");
    }
    v
}

fn rename_flags(f: u32) -> Vec<&'static str> {
    [(1, "RENAME_NOREPLACE"), (2, "RENAME_EXCHANGE"), (4, "RENAME_WHITEOUT")]
        .into_iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| n)
        .collect()
}

/// `path` interpreted relative to `dir`, with `.` and `..` folded lexically.
/// This is what the name *says*; compare with what the kernel resolved.
fn lexical_target(dir: &str, path: &str) -> String {
    let joined = if path.starts_with('/') || dir.is_empty() {
        path.to_owned()
    } else {
        format!("{dir}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in joined.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

fn sock_type(t: u32) -> Value {
    match t {
        0 => Value::Null,
        1 => json!("stream"),
        2 => json!("dgram"),
        3 => json!("raw"),
        5 => json!("seqpacket"),
        n => json!(n),
    }
}

fn fmt_inet(family: u16, addr: &[u8], port: u16) -> Option<String> {
    match family {
        2 => Some(format!("{}:{port}", std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))),
        10 => {
            let a: [u8; 16] = addr[..16].try_into().ok()?;
            Some(format!("[{}]:{port}", std::net::Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// The sockaddr exactly as the caller passed it.
fn decode_sockaddr(b: &[u8], len: usize) -> (&'static str, Option<String>) {
    let len = len.min(b.len());
    if len < 2 {
        return ("unknown", None);
    }
    let family = u16::from_ne_bytes([b[0], b[1]]);
    match family {
        0 => ("unspec", None),
        1 => {
            let p = &b[2..len];
            let s = if p.first() == Some(&0) {
                format!("@{}", String::from_utf8_lossy(&p[1..]))
            } else {
                cstr(p).0
            };
            ("unix", Some(s))
        }
        2 if len >= 8 => ("inet", fmt_inet(2, &b[4..8], u16::from_be_bytes([b[2], b[3]]))),
        10 if len >= 24 => ("inet6", fmt_inet(10, &b[8..24], u16::from_be_bytes([b[2], b[3]]))),
        2 => ("inet", None),
        10 => ("inet6", None),
        16 => ("netlink", None),
        _ => ("other", None),
    }
}

/// The peer as the kernel's socket holds it after connect().
fn kernel_peer(c: &ConnectEvent) -> Option<String> {
    let port = u16::from_be(c.peer_port);
    let zero = c.peer_addr.iter().all(|&b| b == 0);
    if port == 0 && zero {
        return None;
    }
    fmt_inet(c.peer_family, &c.peer_addr, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical() {
        assert_eq!(lexical_target("/a/b", "c"), "/a/b/c");
        assert_eq!(lexical_target("/a/b", "../c/./d"), "/a/c/d");
        assert_eq!(lexical_target("/a", "/x/y"), "/x/y");
        assert_eq!(lexical_target("/", "x"), "/x");
    }

    #[test]
    fn sockaddrs() {
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&2u16.to_ne_bytes());
        v4[2..4].copy_from_slice(&443u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(decode_sockaddr(&v4, 16), ("inet", Some("1.2.3.4:443".into())));
        let mut un = [0u8; 20];
        un[..2].copy_from_slice(&1u16.to_ne_bytes());
        un[2..10].copy_from_slice(b"/run/x\0\0");
        assert_eq!(decode_sockaddr(&un, 20), ("unix", Some("/run/x".into())));
        un[2] = 0;
        un[3..6].copy_from_slice(b"abc");
        assert_eq!(decode_sockaddr(&un, 6), ("unix", Some("@abc".into())));
    }
}
