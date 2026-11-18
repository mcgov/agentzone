//! Passive WebSocket parsing for the logging proxy (RFC 6455, plus
//! permessage-deflate from RFC 7692). After a `101 Switching Protocols`
//! the connection carries frames instead of HTTP messages; one `Dir` per
//! direction reassembles them into messages for the log. Like the HTTP
//! parser, it only observes: anything it can't follow stops the logging,
//! never the traffic.

use flate2::{Decompress, FlushDecompress, Status};

pub struct Message {
    pub opcode: u8,
    /// Payload (unmasked, decompressed), up to the cap.
    pub data: Vec<u8>,
    /// Payload bytes on the wire.
    pub wire_bytes: u64,
    pub truncated: bool,
    /// Compressed, and it couldn't be inflated: `data` is empty.
    pub undecoded: bool,
}

pub fn opcode_name(op: u8) -> &'static str {
    match op {
        1 => "text",
        2 => "binary",
        8 => "close",
        9 => "ping",
        10 => "pong",
        _ => "other",
    }
}

struct Frame {
    fin: bool,
    opcode: u8,
    rsv1: bool,
    mask: Option<[u8; 4]>,
    remaining: u64,
    /// Payload bytes consumed so far (mask position).
    off: usize,
}

pub struct Dir {
    buf: Vec<u8>,
    cur: Option<Frame>,
    /// Data message being assembled across fragments.
    msg: Vec<u8>,
    msg_op: u8,
    msg_wire: u64,
    msg_compressed: bool,
    msg_open: bool,
    /// Control frame payload (control frames may interleave fragments).
    ctl: Vec<u8>,
    inflater: Option<Decompress>,
    /// permessage-deflate without context takeover: fresh window per message.
    reset_each: bool,
    cap: usize,
    dead: bool,
}

impl Dir {
    /// `deflate`: permessage-deflate was negotiated; `no_takeover`: this
    /// direction's sender resets its compression context for every message.
    pub fn new(cap: usize, deflate: bool, no_takeover: bool) -> Self {
        Self {
            buf: Vec::new(),
            cur: None,
            msg: Vec::new(),
            msg_op: 0,
            msg_wire: 0,
            msg_compressed: false,
            msg_open: false,
            ctl: Vec::new(),
            inflater: deflate.then(|| Decompress::new(false)),
            reset_each: no_takeover,
            cap,
            dead: false,
        }
    }

    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Message>) {
        if self.dead {
            return;
        }
        self.buf.extend_from_slice(data);
        let mut pos = 0;
        loop {
            if self.cur.is_none() {
                match self.parse_header(&self.buf[pos..]) {
                    Ok(Some((n, f))) => {
                        pos += n;
                        if f.opcode < 8 {
                            if f.opcode != 0 {
                                self.msg.clear();
                                self.msg_op = f.opcode;
                                self.msg_wire = 0;
                                self.msg_compressed = f.rsv1;
                                self.msg_open = true;
                            } else if !self.msg_open {
                                self.dead = true; // continuation of nothing
                                break;
                            }
                        } else {
                            self.ctl.clear();
                        }
                        self.cur = Some(f);
                    }
                    Ok(None) => break,
                    Err(()) => {
                        self.dead = true;
                        break;
                    }
                }
            }
            let f = self.cur.as_mut().expect("frame set above");
            let avail = self.buf.len() - pos;
            let k = (f.remaining.min(avail as u64)) as usize;
            let control = f.opcode >= 8;
            {
                let chunk = &self.buf[pos..pos + k];
                let dst = if control { &mut self.ctl } else { &mut self.msg };
                // Compressed messages are kept whole (bounded) so they can be
                // inflated; plain ones are cut at the cap.
                let limit = if control { 125 } else { self.cap };
                let room = limit.saturating_sub(dst.len()).min(k);
                let start = dst.len();
                dst.extend_from_slice(&chunk[..room]);
                if let Some(m) = f.mask {
                    for (i, b) in dst[start..].iter_mut().enumerate() {
                        *b ^= m[(f.off + i) & 3];
                    }
                }
            }
            if !control {
                self.msg_wire += k as u64;
            }
            f.off += k;
            f.remaining -= k as u64;
            pos += k;
            if f.remaining > 0 {
                break; // need more bytes
            }
            let f = self.cur.take().expect("frame present");
            if control {
                out.push(Message {
                    opcode: f.opcode,
                    wire_bytes: self.ctl.len() as u64,
                    data: std::mem::take(&mut self.ctl),
                    truncated: false,
                    undecoded: false,
                });
            } else if f.fin {
                out.push(self.finish_message());
            }
        }
        self.buf.drain(..pos);
    }

    fn finish_message(&mut self) -> Message {
        self.msg_open = false;
        let raw = std::mem::take(&mut self.msg);
        let truncated = self.msg_wire > raw.len() as u64;
        let mut m = Message {
            opcode: self.msg_op,
            data: raw,
            wire_bytes: self.msg_wire,
            truncated,
            undecoded: false,
        };
        if !self.msg_compressed {
            return m;
        }
        // A cut-off compressed message can't be inflated, and with context
        // takeover it also breaks the window for everything after it.
        let inflated = match (&mut self.inflater, truncated) {
            (Some(z), false) => {
                if self.reset_each {
                    z.reset(false);
                }
                inflate(z, &m.data, self.cap)
            }
            _ => None,
        };
        match inflated {
            Some((data, cut)) => {
                m.data = data;
                m.truncated = cut;
                if cut && !self.reset_each {
                    self.inflater = None;
                }
            }
            None => {
                m.data = Vec::new();
                m.undecoded = true;
                if !self.reset_each {
                    self.inflater = None;
                }
            }
        }
        m
    }

    fn parse_header(&self, b: &[u8]) -> Result<Option<(usize, Frame)>, ()> {
        if b.len() < 2 {
            return Ok(None);
        }
        let (b0, b1) = (b[0], b[1]);
        let opcode = b0 & 0x0f;
        // Reserved opcodes or RSV2/3: this isn't a WebSocket stream we know.
        if matches!(opcode, 3..=7 | 11..=15) || b0 & 0x30 != 0 {
            return Err(());
        }
        let masked = b1 & 0x80 != 0;
        let (len, mut n) = match b1 & 0x7f {
            126 => {
                if b.len() < 4 {
                    return Ok(None);
                }
                (u16::from_be_bytes([b[2], b[3]]) as u64, 4)
            }
            127 => {
                if b.len() < 10 {
                    return Ok(None);
                }
                (u64::from_be_bytes(b[2..10].try_into().unwrap()), 10)
            }
            l => (l as u64, 2),
        };
        if opcode >= 8 && len > 125 {
            return Err(());
        }
        let mask = if masked {
            if b.len() < n + 4 {
                return Ok(None);
            }
            let m = [b[n], b[n + 1], b[n + 2], b[n + 3]];
            n += 4;
            Some(m)
        } else {
            None
        };
        Ok(Some((n, Frame { fin: b0 & 0x80 != 0, opcode, rsv1: b0 & 0x40 != 0, mask, remaining: len, off: 0 })))
    }
}

/// Inflate one permessage-deflate message (the sender strips the trailing
/// 00 00 ff ff, so it's appended back). Returns the data and whether it was
/// cut at `cap`; None if the stream is corrupt.
fn inflate(z: &mut Decompress, data: &[u8], cap: usize) -> Option<(Vec<u8>, bool)> {
    let mut input = Vec::with_capacity(data.len() + 4);
    input.extend_from_slice(data);
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out = Vec::with_capacity((data.len() * 4).clamp(1024, 1 << 20));
    let mut consumed = 0usize;
    loop {
        if out.len() >= cap {
            return Some((out, true));
        }
        if out.capacity() == out.len() {
            out.reserve(out.len().max(4096));
        }
        let (in0, out0) = (z.total_in(), z.total_out());
        let st = z.decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync).ok()?;
        consumed += (z.total_in() - in0) as usize;
        let produced = z.total_out() - out0;
        if consumed >= input.len() && out.len() < out.capacity() {
            break;
        }
        if matches!(st, Status::StreamEnd) || (produced == 0 && consumed >= input.len()) {
            break;
        }
    }
    let cut = out.len() > cap;
    out.truncate(cap);
    Some((out, cut))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn frame(fin: bool, opcode: u8, rsv1: bool, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![(fin as u8) << 7 | (rsv1 as u8) << 6 | opcode];
        let m = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            l if l < 126 => f.push(m | l as u8),
            l if l < 65536 => {
                f.push(m | 126);
                f.extend_from_slice(&(l as u16).to_be_bytes());
            }
            l => {
                f.push(m | 127);
                f.extend_from_slice(&(l as u64).to_be_bytes());
            }
        }
        match mask {
            Some(k) => {
                f.extend_from_slice(&k);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i & 3]));
            }
            None => f.extend_from_slice(payload),
        }
        f
    }

    fn feed_bytewise(d: &mut Dir, wire: &[u8]) -> Vec<Message> {
        let mut out = Vec::new();
        for b in wire {
            d.feed(std::slice::from_ref(b), &mut out);
        }
        out
    }

    #[test]
    fn masked_fragments_with_interleaved_ping() {
        let mut wire = frame(false, 1, false, Some([1, 2, 3, 4]), b"hello ");
        wire.extend(frame(true, 9, false, Some([9, 9, 9, 9]), b"p"));
        wire.extend(frame(true, 0, false, Some([5, 6, 7, 8]), b"world"));
        let big = vec![b'x'; 70000];
        wire.extend(frame(true, 2, false, None, &big));
        let mut d = Dir::new(1 << 20, false, false);
        let out = feed_bytewise(&mut d, &wire);
        assert_eq!(out.len(), 3);
        assert_eq!((out[0].opcode, out[0].data.as_slice()), (9, &b"p"[..]));
        assert_eq!((out[1].opcode, out[1].data.as_slice()), (1, &b"hello world"[..]));
        assert_eq!((out[2].opcode, out[2].data.len(), out[2].wire_bytes), (2, 70000, 70000));
    }

    fn deflate_msg(z: &mut Compress, s: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() + 64);
        z.compress_vec(s, &mut out, FlushCompress::Sync).unwrap();
        assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
        out.truncate(out.len() - 4);
        out
    }

    #[test]
    fn permessage_deflate_with_context_takeover() {
        let mut z = Compress::new(Compression::default(), false);
        let a = br#"{"type":"message","text":"the quick brown fox"}"#;
        let b = br#"{"type":"message","text":"the quick brown fox again"}"#;
        let mut wire = frame(true, 1, true, None, &deflate_msg(&mut z, a));
        // The second message refers back into the first one's window.
        wire.extend(frame(true, 1, true, None, &deflate_msg(&mut z, b)));
        let mut d = Dir::new(1 << 20, true, false);
        let out = feed_bytewise(&mut d, &wire);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].data, a);
        assert_eq!(out[1].data, b);
        assert!(!out[1].undecoded && !out[1].truncated);
    }

    #[test]
    fn cap_and_garbage() {
        let mut d = Dir::new(4, false, false);
        let out = feed_bytewise(&mut d, &frame(true, 1, false, None, b"abcdefgh"));
        assert_eq!(out[0].data, b"abcd");
        assert!(out[0].truncated);
        assert_eq!(out[0].wire_bytes, 8);

        let mut d = Dir::new(64, false, false);
        let mut out = Vec::new();
        d.feed(&[0x83, 0x00], &mut out); // reserved opcode 3
        d.feed(&frame(true, 1, false, None, b"x"), &mut out);
        assert!(out.is_empty());
    }
}
