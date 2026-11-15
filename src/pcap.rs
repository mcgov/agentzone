//! Decrypted proxy traffic as a classic libpcap file (`--http-pcap`).
//!
//! The proxy works on sockets, not packets, so each proxied connection is
//! written as a synthesized TCP stream: a three-way handshake when the relay
//! starts, data segments with consistent seq/ack numbers as bytes pass, and
//! a FIN per direction at close. Payloads are the *plaintext* (TLS already
//! removed), so Wireshark/tshark reassemble and dissect the HTTP directly.
//!
//! Addressing: the server is the real upstream address and port; the client
//! is loopback (127.0.0.1, or ::1 for an IPv6 upstream) with the agent's
//! real source port. Intercepted HTTPS keeps port 443, so tell the dissector
//! it's HTTP: `tshark -d tcp.port==443,http` or Wireshark's "Decode As".

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

const LINKTYPE_RAW: u32 = 101; // bare IPv4/IPv6 packets
const SNAPLEN: u32 = 65535;
/// Payload bytes per synthesized segment.
const SEG: usize = 16 * 1024;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

pub struct Pcap {
    w: Mutex<BufWriter<File>>,
}

impl Pcap {
    pub fn create(path: &Path) -> Result<Arc<Self>> {
        // Holds credentials unredacted (auth headers, cookies): owner-only.
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        let mut w = BufWriter::new(f);
        // Global header: magic, v2.4, tz 0, sigfigs 0, snaplen, linktype.
        w.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&SNAPLEN.to_le_bytes())?;
        w.write_all(&LINKTYPE_RAW.to_le_bytes())?;
        w.flush()?;
        Ok(Arc::new(Self { w: Mutex::new(w) }))
    }

    fn write(&self, pkts: &[Vec<u8>]) {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut w = self.w.lock().unwrap();
        for p in pkts {
            let len = p.len() as u32;
            let _ = w.write_all(&(t.as_secs() as u32).to_le_bytes());
            let _ = w.write_all(&t.subsec_micros().to_le_bytes());
            let _ = w.write_all(&len.min(SNAPLEN).to_le_bytes());
            let _ = w.write_all(&len.to_le_bytes());
            let _ = w.write_all(&p[..p.len().min(SNAPLEN as usize)]);
        }
        let _ = w.flush();
    }
}

/// One proxied connection's synthesized TCP stream.
pub struct Flow {
    pcap: Arc<Pcap>,
    client: SocketAddr,
    server: SocketAddr,
    /// Next sequence number each side will send.
    cseq: u32,
    sseq: u32,
}

impl Flow {
    /// Start a flow (writes the handshake). `client` supplies the source
    /// port; its address is replaced by loopback of the server's family.
    pub fn open(pcap: Arc<Pcap>, client: SocketAddr, server: SocketAddr) -> Self {
        let cip = match server.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        let mut f = Self {
            pcap,
            client: SocketAddr::new(cip, client.port()),
            server,
            cseq: 1_000_000,
            sseq: 2_000_000,
        };
        let syn = f.pkt(true, SYN, &[]);
        f.cseq += 1;
        let synack = f.pkt(false, SYN | ACK, &[]);
        f.sseq += 1;
        let ack = f.pkt(true, ACK, &[]);
        f.pcap.write(&[syn, synack, ack]);
        f
    }

    pub fn data(&mut self, from_client: bool, d: &[u8]) {
        let mut pkts = Vec::new();
        for chunk in d.chunks(SEG) {
            pkts.push(self.pkt(from_client, ACK | PSH, chunk));
            self.advance(from_client, chunk.len() as u32);
        }
        // The other side acknowledges, as a real stack would.
        pkts.push(self.pkt(!from_client, ACK, &[]));
        self.pcap.write(&pkts);
    }

    pub fn fin(&mut self, from_client: bool) {
        let fin = self.pkt(from_client, FIN | ACK, &[]);
        self.advance(from_client, 1);
        let ack = self.pkt(!from_client, ACK, &[]);
        self.pcap.write(&[fin, ack]);
    }

    fn advance(&mut self, from_client: bool, n: u32) {
        if from_client {
            self.cseq = self.cseq.wrapping_add(n);
        } else {
            self.sseq = self.sseq.wrapping_add(n);
        }
    }

    fn pkt(&self, from_client: bool, flags: u8, payload: &[u8]) -> Vec<u8> {
        let (src, dst, seq, ack) = if from_client {
            (self.client, self.server, self.cseq, self.sseq)
        } else {
            (self.server, self.client, self.sseq, self.cseq)
        };
        let ack = if flags & ACK != 0 { ack } else { 0 };
        tcp_packet(src, dst, seq, ack, flags, payload)
    }
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut it = data.chunks_exact(2);
    for c in &mut it {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = it.remainder() {
        acc += (*b as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn tcp_packet(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port().to_be_bytes());
    tcp.extend_from_slice(&dst.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4); // data offset: 20 bytes, no options
    tcp.push(flags);
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent
    tcp.extend_from_slice(payload);
    let tcp_len = tcp.len();

    let mut out = Vec::with_capacity(40 + tcp_len);
    let pseudo = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut ip = [0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = 64; // TTL
            ip[9] = 6; // TCP
            ip[12..16].copy_from_slice(&s.octets());
            ip[16..20].copy_from_slice(&d.octets());
            let c = fold(sum16(&ip, 0));
            ip[10..12].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&ip);
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&[0, 6]);
            p.extend_from_slice(&(tcp_len as u16).to_be_bytes());
            p
        }
        (s, d) => {
            let to6 = |a: IpAddr| match a {
                IpAddr::V6(a) => a,
                IpAddr::V4(a) => a.to_ipv6_mapped(),
            };
            let (s, d) = (to6(s), to6(d));
            let mut ip = [0u8; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            ip[6] = 6; // next header: TCP
            ip[7] = 64; // hop limit
            ip[8..24].copy_from_slice(&s.octets());
            ip[24..40].copy_from_slice(&d.octets());
            out.extend_from_slice(&ip);
            let mut p = Vec::with_capacity(40);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&(tcp_len as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 6]);
            p
        }
    };
    let c = fold(sum16(&tcp, sum16(&pseudo, 0)));
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    out.extend_from_slice(&tcp);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_verify() {
        // A correct checksum makes the one's-complement sum over the
        // header (or pseudo-header + segment) come out as 0xffff.
        let p = tcp_packet("127.0.0.1:5000".parse().unwrap(), "1.2.3.4:443".parse().unwrap(), 7, 9, ACK | PSH, b"hello");
        assert_eq!(fold(sum16(&p[..20], 0)), 0);
        let mut pseudo = vec![127, 0, 0, 1, 1, 2, 3, 4, 0, 6];
        pseudo.extend_from_slice(&((p.len() - 20) as u16).to_be_bytes());
        assert_eq!(fold(sum16(&p[20..], sum16(&pseudo, 0))), 0);

        let p6 = tcp_packet("[::1]:5000".parse().unwrap(), "[2001:db8::1]:443".parse().unwrap(), 1, 2, SYN, b"");
        assert_eq!(p6.len(), 60);
        assert_eq!(p6[0] >> 4, 6);
    }
}
