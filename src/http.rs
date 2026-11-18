//! Passive HTTP/1.1 parsing for the logging proxy.
//!
//! The proxy relays bytes unchanged; a `Parser` per direction watches the
//! stream and reports message heads, body bytes and message ends to a `Sink`.
//! Nothing here can alter what is sent: a parse failure only stops logging
//! for that connection.

use std::io::Read;

use base64::Engine;
use serde_json::{json, Map, Value};

#[derive(Clone, Debug, Default)]
pub struct Head {
    /// Requests: method and request-target.
    pub method: String,
    pub target: String,
    /// Responses: status code and reason phrase.
    pub status: u16,
    pub reason: String,
    pub version: u8,
    pub headers: Vec<(String, Vec<u8>)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    fn header_str(&self, name: &str) -> Option<String> {
        self.header(name)
            .map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase())
    }

    pub fn chunked(&self) -> bool {
        self.header_str("transfer-encoding")
            .is_some_and(|v| v.split(',').any(|t| t.trim() == "chunked"))
    }

    pub fn content_length(&self) -> Option<u64> {
        self.header_str("content-length").and_then(|v| v.parse().ok())
    }
}

/// How the body following a head is delimited (decided by the sink, which
/// knows e.g. whether the request was HEAD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body: the message ends with its head.
    Empty,
    Length(u64),
    Chunked,
    /// Response body runs until the connection closes.
    UntilClose,
    /// End the message and stop parsing (101 Switching Protocols).
    Stop,
}

pub trait Sink {
    fn head(&mut self, h: Head) -> Framing;
    fn data(&mut self, d: &[u8]);
    fn end(&mut self);
    fn error(&mut self, why: String);
}

#[derive(Clone, Copy, Debug)]
enum St {
    Head,
    Body(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkCrlf,
    Trailer,
    UntilClose,
    Dead,
}

const MAX_HEAD: usize = 256 * 1024;

pub struct Parser {
    response: bool,
    buf: Vec<u8>,
    st: St,
}

fn find_crlf(b: &[u8]) -> Option<usize> {
    b.windows(2).position(|w| w == b"\r\n")
}

impl Parser {
    pub fn new(response: bool) -> Self {
        Self { response, buf: Vec::new(), st: St::Head }
    }

    pub fn stop(&mut self) {
        self.st = St::Dead;
        self.buf = Vec::new();
    }

    /// Bytes received after the point where parsing stopped (the first
    /// frames of an upgraded connection can arrive with the 101 itself).
    pub fn take_rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn feed(&mut self, data: &[u8], sink: &mut impl Sink) {
        match self.st {
            St::Dead => return,
            St::UntilClose => return sink.data(data),
            _ => {}
        }
        self.buf.extend_from_slice(data);
        let mut pos = 0;
        loop {
            let rest = &self.buf[pos..];
            match self.st {
                St::Dead => break,
                St::Head => {
                    // Stray CRLFs between messages are allowed.
                    let skip = rest.iter().take_while(|&&b| b == b'\r' || b == b'\n').count();
                    pos += skip;
                    let rest = &self.buf[pos..];
                    if rest.is_empty() {
                        break;
                    }
                    match self.parse_head(rest) {
                        Ok(Some((n, head))) => {
                            pos += n;
                            self.st = match sink.head(head) {
                                Framing::Empty | Framing::Length(0) => {
                                    sink.end();
                                    St::Head
                                }
                                Framing::Length(n) => St::Body(n),
                                Framing::Chunked => St::ChunkSize,
                                Framing::UntilClose => St::UntilClose,
                                Framing::Stop => {
                                    sink.end();
                                    St::Dead
                                }
                            };
                        }
                        Ok(None) => {
                            if rest.len() > MAX_HEAD {
                                sink.error(format!("message head larger than {MAX_HEAD} bytes"));
                                self.st = St::Dead;
                            }
                            break;
                        }
                        Err(e) => {
                            sink.error(e);
                            self.st = St::Dead;
                            break;
                        }
                    }
                }
                St::Body(n) | St::ChunkData(n) => {
                    if rest.is_empty() {
                        break;
                    }
                    let k = (n as usize).min(rest.len());
                    sink.data(&rest[..k]);
                    pos += k;
                    let left = n - k as u64;
                    self.st = match (self.st, left) {
                        (St::Body(_), 0) => {
                            sink.end();
                            St::Head
                        }
                        (St::Body(_), l) => St::Body(l),
                        (_, 0) => St::ChunkCrlf,
                        (_, l) => St::ChunkData(l),
                    };
                }
                St::ChunkSize => {
                    let Some(i) = find_crlf(rest) else {
                        if rest.len() > 4096 {
                            sink.error("chunk size line too long".into());
                            self.st = St::Dead;
                        }
                        break;
                    };
                    let line = String::from_utf8_lossy(&rest[..i]);
                    let hex = line.split(';').next().unwrap_or("").trim();
                    match u64::from_str_radix(hex, 16) {
                        Ok(0) => self.st = St::Trailer,
                        Ok(n) => self.st = St::ChunkData(n),
                        Err(_) => {
                            sink.error(format!("bad chunk size {hex:?}"));
                            self.st = St::Dead;
                            break;
                        }
                    }
                    pos += i + 2;
                }
                St::ChunkCrlf => {
                    if rest.len() < 2 {
                        break;
                    }
                    if &rest[..2] != b"\r\n" {
                        sink.error("missing CRLF after chunk".into());
                        self.st = St::Dead;
                        break;
                    }
                    pos += 2;
                    self.st = St::ChunkSize;
                }
                St::Trailer => {
                    let Some(i) = find_crlf(rest) else { break };
                    pos += i + 2;
                    if i == 0 {
                        sink.end();
                        self.st = St::Head;
                    }
                }
                St::UntilClose => {
                    sink.data(rest);
                    pos = self.buf.len();
                    break;
                }
            }
        }
        self.buf.drain(..pos);
    }

    /// The direction closed.
    pub fn eof(&mut self, sink: &mut impl Sink) {
        match self.st {
            St::UntilClose => sink.end(),
            St::Head if self.buf.iter().all(|&b| b == b'\r' || b == b'\n') => {}
            St::Dead => {}
            _ => sink.error("connection closed in the middle of a message".into()),
        }
        self.stop();
    }

    fn parse_head(&self, b: &[u8]) -> Result<Option<(usize, Head)>, String> {
        let mut hdrs = [httparse::EMPTY_HEADER; 256];
        let mut h = Head::default();
        let n = if self.response {
            let mut r = httparse::Response::new(&mut hdrs);
            match r.parse(b) {
                Ok(httparse::Status::Complete(n)) => {
                    h.status = r.code.unwrap_or(0);
                    h.reason = r.reason.unwrap_or("").to_owned();
                    h.version = r.version.unwrap_or(1);
                    collect(&mut h, r.headers);
                    n
                }
                Ok(httparse::Status::Partial) => return Ok(None),
                Err(e) => return Err(format!("not an HTTP/1.x response ({e})")),
            }
        } else {
            let mut r = httparse::Request::new(&mut hdrs);
            match r.parse(b) {
                Ok(httparse::Status::Complete(n)) => {
                    h.method = r.method.unwrap_or("").to_owned();
                    h.target = r.path.unwrap_or("").to_owned();
                    h.version = r.version.unwrap_or(1);
                    collect(&mut h, r.headers);
                    n
                }
                Ok(httparse::Status::Partial) => return Ok(None),
                Err(e) => return Err(format!("not an HTTP/1.x request ({e})")),
            }
        };
        Ok(Some((n, h)))
    }
}

fn collect(h: &mut Head, hdrs: &[httparse::Header]) {
    h.headers = hdrs.iter().map(|x| (x.name.to_owned(), x.value.to_vec())).collect();
}

/// Parse a complete request head from the start of a buffer (the proxy's
/// own CONNECT / absolute-form handling). Returns head length and the head.
pub fn parse_request_head(b: &[u8]) -> Result<Option<(usize, Head)>, String> {
    Parser::new(false).parse_head(b)
}

// ------------------------------------------------------------------ bodies

/// A message body, kept up to `cap` bytes; `total` counts everything seen.
pub struct Body {
    pub data: Vec<u8>,
    pub total: u64,
    cap: usize,
}

impl Body {
    pub fn new(cap: usize) -> Self {
        Self { data: Vec::new(), total: 0, cap }
    }

    pub fn push(&mut self, d: &[u8]) {
        self.total += d.len() as u64;
        let room = self.cap.saturating_sub(self.data.len());
        self.data.extend_from_slice(&d[..room.min(d.len())]);
    }

    pub fn truncated(&self) -> bool {
        self.total > self.data.len() as u64
    }
}

/// Header names whose values are credentials.
fn secret_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key" | "api-key"
    ) || n.contains("token")
        || n.contains("secret")
        || n.contains("password")
        || n.ends_with("-key")
}

fn redact(name: &str, v: &str) -> String {
    // Keep the auth scheme ("Bearer", "Basic"): it says what kind of
    // credential was sent without revealing it.
    if name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("proxy-authorization") {
        if let Some((scheme, rest)) = v.split_once(' ') {
            return format!("{scheme} <redacted {} bytes>", rest.len());
        }
    }
    format!("<redacted {} bytes>", v.len())
}

/// Headers as an object (lower-cased names; repeated headers become arrays).
pub fn headers_json(h: &Head, keep_secrets: bool) -> Value {
    let mut m = Map::new();
    for (k, v) in &h.headers {
        let k = k.to_ascii_lowercase();
        let s = String::from_utf8_lossy(v).into_owned();
        let s = if !keep_secrets && secret_header(&k) { redact(&k, &s) } else { s };
        match m.get_mut(&k) {
            None => {
                m.insert(k, Value::String(s));
            }
            Some(Value::Array(a)) => a.push(Value::String(s)),
            Some(prev) => {
                let p = prev.take();
                *prev = Value::Array(vec![p, Value::String(s)]);
            }
        }
    }
    Value::Object(m)
}

/// Undo Content-Encoding. Output is capped at `cap`; a truncated or corrupt
/// input yields what could be decoded plus an error note.
fn decode(enc: &str, data: &[u8], cap: usize) -> (Vec<u8>, Option<String>) {
    fn read_all(r: impl Read, cap: usize) -> (Vec<u8>, Option<String>) {
        let mut out = Vec::new();
        let r = r.take(cap as u64 + 1).read_to_end(&mut out);
        let mut note = r.err().map(|e| format!("decode error: {e}"));
        if out.len() > cap {
            out.truncate(cap);
            note.get_or_insert_with(|| "decoded body truncated".into());
        }
        (out, note)
    }
    match enc {
        "gzip" | "x-gzip" => read_all(flate2::read::MultiGzDecoder::new(data), cap),
        "deflate" => {
            // "deflate" is meant to be zlib-wrapped, but raw deflate is common.
            let (out, note) = read_all(flate2::read::ZlibDecoder::new(data), cap);
            if note.is_some() && out.is_empty() {
                read_all(flate2::read::DeflateDecoder::new(data), cap)
            } else {
                (out, note)
            }
        }
        "br" => read_all(brotli::Decompressor::new(data, 4096), cap),
        "zstd" => match zstd::stream::read::Decoder::new(data) {
            Ok(d) => read_all(d, cap),
            Err(e) => (Vec::new(), Some(format!("decode error: {e}"))),
        },
        _ => (data.to_vec(), None),
    }
}

/// Server-sent events as [{event, data, id}], `data` parsed as JSON when it is.
fn parse_sse(text: &str) -> Value {
    let text = text.replace("\r\n", "\n");
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let mut ev = Map::new();
        let mut data: Vec<&str> = Vec::new();
        for line in block.lines() {
            if line.starts_with(':') {
                continue;
            }
            let (k, v) = line.split_once(':').unwrap_or((line, ""));
            let v = v.strip_prefix(' ').unwrap_or(v);
            match k {
                "data" => data.push(v),
                "event" | "id" | "retry" => {
                    ev.insert(k.into(), json!(v));
                }
                _ => {}
            }
        }
        if data.is_empty() && ev.is_empty() {
            continue;
        }
        if !data.is_empty() {
            let d = data.join("\n");
            let v = serde_json::from_str::<Value>(&d).unwrap_or(Value::String(d));
            ev.insert("data".into(), v);
        }
        out.push(Value::Object(ev));
    }
    Value::Array(out)
}

/// Add a body to a request/response record: decoded per Content-Encoding,
/// JSON parsed, event streams split into events, binary as base64.
pub fn body_json(h: &Head, body: &Body, out: &mut Map<String, Value>) {
    out.insert("body_bytes".into(), json!(body.total));
    if body.total == 0 {
        return;
    }
    if body.truncated() {
        out.insert("body_truncated".into(), json!(true));
    }
    let enc = h.header_str("content-encoding").unwrap_or_default();
    let (bytes, note) = if enc.contains(',') {
        (body.data.clone(), Some(format!("stacked content-encoding {enc:?} left as is")))
    } else {
        decode(&enc, &body.data, body.cap)
    };
    if !matches!(enc.as_str(), "" | "identity") {
        out.insert("content_encoding".into(), json!(enc));
    }
    if let Some(n) = note {
        out.insert("body_note".into(), json!(n));
    }
    let ct = h.header_str("content-type").unwrap_or_default();
    match std::str::from_utf8(&bytes) {
        Ok(text) if ct.contains("event-stream") => {
            out.insert("events".into(), parse_sse(text));
        }
        Ok(text) => {
            let v = if ct.contains("json") {
                serde_json::from_str::<Value>(text).ok()
            } else {
                None
            };
            out.insert("body".into(), v.unwrap_or_else(|| json!(text)));
        }
        Err(_) => {
            out.insert(
                "body_base64".into(),
                json!(base64::engine::general_purpose::STANDARD.encode(&bytes)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec {
        heads: Vec<Head>,
        bodies: Vec<Vec<u8>>,
        cur: Vec<u8>,
        errors: Vec<String>,
        head_req: bool,
    }
    impl Sink for Rec {
        fn head(&mut self, h: Head) -> Framing {
            let f = if h.chunked() {
                Framing::Chunked
            } else if let Some(n) = h.content_length() {
                Framing::Length(n)
            } else if self.head_req || h.method.is_empty() && h.status == 204 {
                Framing::Empty
            } else if h.method.is_empty() {
                Framing::UntilClose
            } else {
                Framing::Empty
            };
            self.heads.push(h);
            f
        }
        fn data(&mut self, d: &[u8]) {
            self.cur.extend_from_slice(d);
        }
        fn end(&mut self) {
            self.bodies.push(std::mem::take(&mut self.cur));
        }
        fn error(&mut self, why: String) {
            self.errors.push(why);
        }
    }

    fn feed_bytewise(p: &mut Parser, s: &[u8], r: &mut Rec) {
        for b in s {
            p.feed(std::slice::from_ref(b), r);
        }
    }

    #[test]
    fn pipelined_requests_split_anywhere() {
        let wire = b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut p = Parser::new(false);
        let mut r = Rec::default();
        feed_bytewise(&mut p, wire, &mut r);
        assert_eq!(r.heads.len(), 2);
        assert_eq!(r.heads[0].method, "POST");
        assert_eq!(r.bodies, vec![b"hello".to_vec(), vec![]]);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn chunked_response_with_trailer() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\n";
        let mut p = Parser::new(true);
        let mut r = Rec::default();
        feed_bytewise(&mut p, wire, &mut r);
        assert_eq!(r.heads[0].status, 200);
        assert_eq!(r.bodies, vec![b"Wikipedia".to_vec()]);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn body_until_close() {
        let mut p = Parser::new(true);
        let mut r = Rec::default();
        p.feed(b"HTTP/1.0 200 OK\r\n\r\nabc", &mut r);
        p.feed(b"def", &mut r);
        p.eof(&mut r);
        assert_eq!(r.bodies, vec![b"abcdef".to_vec()]);
    }

    #[test]
    fn garbage_stops_parsing() {
        let mut p = Parser::new(false);
        let mut r = Rec::default();
        p.feed(b"\x16\x03\x01garbage\r\n\r\n", &mut r);
        assert_eq!(r.errors.len(), 1);
        p.feed(b"GET / HTTP/1.1\r\n\r\n", &mut r);
        assert!(r.heads.is_empty());
    }

    #[test]
    fn sse_and_json_bodies() {
        let mut h = Head::default();
        h.headers.push(("Content-Type".into(), b"text/event-stream".to_vec()));
        let mut b = Body::new(1 << 20);
        b.push(b"event: message_start\ndata: {\"a\":1}\n\nevent: ping\ndata: hi\n\n");
        let mut m = Map::new();
        body_json(&h, &b, &mut m);
        assert_eq!(m["events"][0]["event"], "message_start");
        assert_eq!(m["events"][0]["data"]["a"], 1);
        assert_eq!(m["events"][1]["data"], "hi");

        let mut h = Head::default();
        h.headers.push(("content-type".into(), b"application/json".to_vec()));
        h.headers.push(("content-encoding".into(), b"gzip".to_vec()));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#).unwrap();
        let mut b = Body::new(1 << 20);
        b.push(&gz.finish().unwrap());
        let mut m = Map::new();
        body_json(&h, &b, &mut m);
        assert_eq!(m["body"]["messages"][0]["content"], "hi");
    }

    #[test]
    fn redaction() {
        let mut h = Head::default();
        h.headers.push(("Authorization".into(), b"Bearer sk-ant-secret".to_vec()));
        h.headers.push(("x-api-key".into(), b"sk-ant-xyz".to_vec()));
        h.headers.push(("anthropic-version".into(), b"2023-06-01".to_vec()));
        let v = headers_json(&h, false);
        assert_eq!(v["authorization"], "Bearer <redacted 13 bytes>");
        assert_eq!(v["x-api-key"], "<redacted 10 bytes>");
        assert_eq!(v["anthropic-version"], "2023-06-01");
        assert_eq!(headers_json(&h, true)["x-api-key"], "sk-ant-xyz");
    }
}
