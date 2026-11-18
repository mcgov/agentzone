//! Logging HTTP(S) proxy for `--log-http`.
//!
//! The sandbox gets its own network namespace whose only way out is this
//! proxy: the helper opens the listening socket on 127.0.0.1 *inside* that
//! namespace and hands the fd to agentbox, which accepts on it from the host
//! side and makes the outbound connections from the host namespace.
//!
//! HTTPS (CONNECT) is intercepted with a CA generated for the run. Its key
//! exists only in this process's memory, and the agent is told to trust the
//! certificate through the usual environment variables. Bytes are relayed
//! unchanged; a passive parser on each direction turns the traffic into one
//! `http` record per request/response exchange.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::http::{self, Body, Framing, Head, Parser, Sink};

/// Port the proxy listens on inside the sandbox's network namespace.
pub const PORT: u16 = 3128;

#[derive(Clone, Copy)]
pub struct Opts {
    /// Bytes of each body kept in the log.
    pub body_max: usize,
    /// Log credential headers verbatim instead of redacting them.
    pub keep_secrets: bool,
}

// ---------------------------------------------------------------------- CA

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub pem: String,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn validity(p: &mut CertificateParams) {
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(30);
}

impl Ca {
    pub fn generate() -> Result<Self> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.distinguished_name.push(DnType::CommonName, "agentbox interception CA (this run only)");
        p.distinguished_name.push(DnType::OrganizationName, "agentbox");
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        validity(&mut p);
        let key = KeyPair::generate()?;
        let cert = p.self_signed(&key)?;
        Ok(Self {
            pem: cert.pem(),
            issuer: Issuer::new(p, key),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// TLS server config presenting a certificate for `name`.
    fn server_config(&self, name: &str) -> Result<Arc<ServerConfig>> {
        if let Some(c) = self.leaves.lock().unwrap().get(name) {
            return Ok(c.clone());
        }
        let mut p = CertificateParams::new(vec![name.to_owned()])?;
        p.distinguished_name.push(DnType::CommonName, name);
        p.use_authority_key_identifier_extension = true;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut p);
        let key = KeyPair::generate()?;
        let cert = p.signed_by(&key, &self.issuer)?;
        let chain = vec![CertificateDer::from(cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        // Only HTTP/1.1 is parsed, so that's all we offer.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves.lock().unwrap().insert(name.to_owned(), cfg.clone());
        Ok(cfg)
    }
}

/// System CA bundles, first match wins.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

/// Write `ca.pem` (just the run's CA) and `ca-bundle.pem` (system roots plus
/// the CA, for tools whose variable replaces the trust store) into `dir`.
pub fn write_trust_files(ca: &Ca, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("ca.pem"), &ca.pem)?;
    let mut bundle = SYSTEM_BUNDLES
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    if !bundle.is_empty() && !bundle.ends_with('\n') {
        bundle.push('\n');
    }
    bundle.push_str(&ca.pem);
    std::fs::write(dir.join("ca-bundle.pem"), bundle)?;
    Ok(())
}

/// Environment that points the usual HTTP stacks at the proxy and CA.
/// `trust_dir` is where the trust files are visible to the agent.
pub fn agent_env(proxy_url: &str, trust_dir: &Path) -> Vec<(String, String)> {
    let ca = trust_dir.join("ca.pem").display().to_string();
    let bundle = trust_dir.join("ca-bundle.pem").display().to_string();
    let mut v = Vec::new();
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        v.push((k.into(), proxy_url.into()));
    }
    for k in ["NO_PROXY", "no_proxy"] {
        v.push((k.into(), "localhost,127.0.0.1,::1".into()));
    }
    v.push(("NODE_EXTRA_CA_CERTS".into(), ca));
    for k in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "AWS_CA_BUNDLE"] {
        v.push((k.into(), bundle.clone()));
    }
    v
}

/// Is `k` an env var that `agent_env` sets (so an inherited value is dropped)?
pub fn is_proxy_env(k: &str) -> bool {
    agent_env("", Path::new("/")).iter().any(|(n, _)| n == k)
}

// ----------------------------------------------------------------- running

/// Which sandboxed process owns a proxy connection.
pub struct Attribution {
    /// `cgroup.procs` of the sandbox cgroup.
    pub cgroup_procs: PathBuf,
    /// A process in the sandbox's network namespace (its /proc/<pid>/net/tcp
    /// shows that namespace's sockets).
    pub netns_pid: i32,
}

pub struct Handle {
    rx: mpsc::Receiver<Map<String, Value>>,
    active: Arc<AtomicUsize>,
}

impl Handle {
    pub fn drain(&self) -> Vec<Map<String, Value>> {
        self.rx.try_iter().collect()
    }

    /// Wait (up to `max`) for open connections to finish, so their last
    /// exchanges are logged.
    pub fn settle(&self, max: Duration) {
        let t = Instant::now();
        while self.active.load(Ordering::SeqCst) > 0 && t.elapsed() < max {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Block until the next record (standalone `agentbox proxy`).
    pub fn recv(&self) -> Option<Map<String, Value>> {
        self.rx.recv().ok()
    }
}

struct Ctx {
    ca: Arc<Ca>,
    client_tls: Arc<ClientConfig>,
    opts: Opts,
    tx: mpsc::Sender<Map<String, Value>>,
    attrib: Option<Attribution>,
    listen_port: u16,
    next_conn: AtomicU64,
    pcap: Option<Arc<crate::pcap::Pcap>>,
}

fn now_ns() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i128).unwrap_or(0)
}

/// Serve `listener` on a background runtime; records arrive on the handle.
pub fn start(
    listener: std::net::TcpListener,
    ca: Arc<Ca>,
    opts: Opts,
    attrib: Option<Attribution>,
    pcap: Option<Arc<crate::pcap::Pcap>>,
) -> Result<Handle> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let (added, _) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        bail!("no system CA certificates found for verifying upstream servers");
    }
    let mut client_tls = ClientConfig::builder_with_provider(ca.provider.clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    let listen_port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;
    let (tx, rx) = mpsc::channel();
    let active = Arc::new(AtomicUsize::new(0));
    let ctx = Arc::new(Ctx {
        ca,
        client_tls: Arc::new(client_tls),
        opts,
        tx,
        attrib,
        listen_port,
        next_conn: AtomicU64::new(1),
        pcap,
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("agentbox-proxy")
        .enable_all()
        .build()?;
    let act = active.clone();
    std::thread::Builder::new().name("agentbox-proxy".into()).spawn(move || {
        rt.block_on(async move {
            let l = match tokio::net::TcpListener::from_std(listener) {
                Ok(l) => l,
                Err(e) => return eprintln!("agentbox: proxy: {e}"),
            };
            loop {
                let Ok((sock, peer)) = l.accept().await else { continue };
                let ctx = ctx.clone();
                let act = act.clone();
                act.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let id = ctx.next_conn.fetch_add(1, Ordering::SeqCst);
                    if let Err(e) = handle(id, sock, peer, &ctx).await {
                        let mut m = record("http_tunnel", id);
                        m.insert("error".into(), json!(format!("{e:#}")));
                        let _ = ctx.tx.send(m);
                    }
                    act.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    })?;
    Ok(Handle { rx, active })
}

fn record(kind: &str, conn: u64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!(kind));
    m.insert("time".into(), json!(crate::log::rfc3339(now_ns())));
    m.insert("conn".into(), json!(conn));
    m
}

/// Find the sandboxed process holding the client end of a connection.
fn attribute(a: &Attribution, client_port: u16, listen_port: u16) -> Option<Map<String, Value>> {
    let want = |field: &str, port: u16| field.rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok()) == Some(port);
    let mut inode = None;
    for table in ["tcp", "tcp6"] {
        let Ok(t) = std::fs::read_to_string(format!("/proc/{}/net/{table}", a.netns_pid)) else { continue };
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 9 && want(f[1], client_port) && want(f[2], listen_port) {
                inode = Some(f[9].to_owned());
            }
        }
    }
    let link = format!("socket:[{}]", inode?);
    for pid in std::fs::read_to_string(&a.cgroup_procs).ok()?.lines() {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == link.as_str()) {
                let mut m = Map::new();
                m.insert("pid".into(), json!(pid.parse::<u32>().unwrap_or(0)));
                if let Ok(c) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                    m.insert("comm".into(), json!(c.trim_end()));
                }
                return Some(m);
            }
        }
    }
    None
}

/// Split "host:port" / "[v6]:port".
fn split_authority(a: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, p) = rest.split_once(']').context("bad IPv6 authority")?;
        let port = p.strip_prefix(':').map(|p| p.parse()).transpose()?.unwrap_or(default_port);
        return Ok((h.to_owned(), port));
    }
    match a.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_owned(), p.parse().with_context(|| format!("bad port in {a:?}"))?)),
        None => Ok((a.to_owned(), default_port)),
    }
}

async fn read_head(s: &mut TcpStream) -> Result<(Vec<u8>, usize, Head)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some((n, h)) = http::parse_request_head(&buf).map_err(anyhow::Error::msg)? {
            return Ok((buf, n, h));
        }
        if buf.len() > 64 * 1024 {
            bail!("proxy request head too large");
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("client closed before sending a request");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn handle(id: u64, mut client: TcpStream, peer: SocketAddr, ctx: &Arc<Ctx>) -> Result<()> {
    let who = match &ctx.attrib {
        Some(a) => {
            let (cp, lp) = (peer.port(), ctx.listen_port);
            let cgroup_procs = a.cgroup_procs.clone();
            let netns_pid = a.netns_pid;
            tokio::task::spawn_blocking(move || attribute(&Attribution { cgroup_procs, netns_pid }, cp, lp))
                .await
                .ok()
                .flatten()
        }
        None => None,
    };
    let (buf, head_len, head) = read_head(&mut client).await?;

    let mut tun = record("http_tunnel", id);
    // The agent's source port: `local_port` on its kernel `connect` record.
    tun.insert("client_port".into(), json!(peer.port()));
    if let Some(w) = &who {
        tun.extend(w.clone());
    }
    let is_connect = head.method.eq_ignore_ascii_case("CONNECT");
    let (host, port) = if is_connect {
        let (h, p) = split_authority(&head.target, 443)?;
        (h, p)
    } else {
        let rest = head
            .target
            .strip_prefix("http://")
            .with_context(|| format!("unsupported proxy request {} {}", head.method, head.target))?;
        let auth = rest.split(['/', '?']).next().unwrap_or("");
        let (h, p) = split_authority(auth, 80)?;
        (h, p)
    };
    tun.insert("target".into(), json!(format!("{host}:{port}")));

    let upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(u) => u,
        Err(e) => {
            if is_connect {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
            } else {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
            tun.insert("error".into(), json!(format!("connect upstream: {e}")));
            let _ = ctx.tx.send(tun);
            return Ok(());
        }
    };
    if let Ok(a) = upstream.peer_addr() {
        tun.insert("upstream".into(), json!(a.to_string()));
    }
    let base = Base { conn: id, host: host.clone(), port, who, client: peer, server: upstream.peer_addr().ok() };

    if !is_connect {
        // Plain HTTP through the proxy: relay the request as sent.
        tun.insert("tls".into(), json!(false));
        let _ = ctx.tx.send(tun);
        return relay(client, upstream, ctx, base, "http", buf).await;
    }

    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    let early = buf[head_len..].to_vec();
    let mut first = [0u8; 1];
    let is_tls = if let Some(&b) = early.first() {
        b == 0x16
    } else {
        client.peek(&mut first).await? == 1 && first[0] == 0x16
    };
    if !is_tls || !early.is_empty() {
        // Not TLS: an opaque tunnel, still parsed in case it is plain HTTP.
        tun.insert("tls".into(), json!(false));
        let _ = ctx.tx.send(tun);
        return relay(client, upstream, ctx, base, "http", early).await;
    }

    let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client)
        .await
        .context("reading TLS ClientHello")?;
    let sni = start.client_hello().server_name().map(str::to_owned);
    let name = sni.clone().unwrap_or_else(|| host.clone());
    tun.insert("tls".into(), json!("intercepted"));
    if let Some(s) = &sni {
        tun.insert("sni".into(), json!(s));
    }
    // Upstream first: if the real server's certificate doesn't verify, the
    // client never gets a (forged but trusted) certificate for it.
    let server_name = ServerName::try_from(name.clone()).context("server name")?;
    let utls = match tokio_rustls::TlsConnector::from(ctx.client_tls.clone()).connect(server_name, upstream).await {
        Ok(t) => t,
        Err(e) => {
            tun.insert("error".into(), json!(format!("upstream TLS: {e}")));
            let _ = ctx.tx.send(tun);
            return Ok(());
        }
    };
    let ctls = match start.into_stream(ctx.ca.server_config(&name)?).await {
        Ok(t) => t,
        Err(e) => {
            // Usually: the client doesn't trust the run's CA (pinning, or a
            // trust store that ignores the env vars).
            tun.insert("error".into(), json!(format!("client TLS handshake (CA not trusted?): {e}")));
            let _ = ctx.tx.send(tun);
            return Ok(());
        }
    };
    let _ = ctx.tx.send(tun);
    let base = Base { host: name, ..base };
    relay(ctls, utls, ctx, base, "https", Vec::new()).await
}

// ------------------------------------------------------------------- relay

struct Base {
    conn: u64,
    host: String,
    port: u16,
    who: Option<Map<String, Value>>,
    /// The agent's end, as accepted.
    client: SocketAddr,
    /// The real server.
    server: Option<SocketAddr>,
}

struct Exchange {
    time_ns: i128,
    started: Instant,
    req: Head,
    req_body: Body,
    req_complete: bool,
    resp: Option<Head>,
    resp_body: Body,
}

struct Conv {
    ctx: Arc<Ctx>,
    base: Base,
    scheme: &'static str,
    req_p: Parser,
    resp_p: Parser,
    next_req: u64,
    next_resp: u64,
    cur_req: Option<u64>,
    open: HashMap<u64, Exchange>,
    informational: bool,
    errors: u32,
    /// --http-pcap: this connection as a synthesized TCP stream.
    flow: Option<crate::pcap::Flow>,
    /// A 101 just switched this connection to WebSocket.
    upgrade: Option<Upgrade>,
    /// WebSocket frame parsers (client->server, server->client) and the URL.
    ws: Option<(crate::ws::Dir, crate::ws::Dir, String)>,
}

struct Upgrade {
    url: String,
    deflate: bool,
    client_no_takeover: bool,
    server_no_takeover: bool,
}

impl Conv {
    fn feed(&mut self, response: bool, d: &[u8]) {
        if let Some(f) = &mut self.flow {
            f.data(!response, d);
        }
        if self.ws.is_some() {
            return self.feed_ws(response, d);
        }
        if response {
            let mut p = std::mem::replace(&mut self.resp_p, Parser::new(true));
            p.feed(d, &mut RespSink(self));
            self.resp_p = p;
            if let Some(u) = self.upgrade.take() {
                let cap = self.ctx.opts.body_max;
                self.ws = Some((
                    crate::ws::Dir::new(cap, u.deflate, u.client_no_takeover),
                    crate::ws::Dir::new(cap, u.deflate, u.server_no_takeover),
                    u.url,
                ));
                // Frames that arrived in the same read as the 101.
                let rest = self.resp_p.take_rest();
                if !rest.is_empty() {
                    self.feed_ws(true, &rest);
                }
            }
        } else {
            let mut p = std::mem::replace(&mut self.req_p, Parser::new(false));
            p.feed(d, &mut ReqSink(self));
            self.req_p = p;
        }
    }

    fn feed_ws(&mut self, response: bool, d: &[u8]) {
        let Some((c, s, url)) = &mut self.ws else { return };
        let mut msgs = Vec::new();
        if response { s.feed(d, &mut msgs) } else { c.feed(d, &mut msgs) }
        let url = url.clone();
        for msg in msgs {
            let mut m = record("ws", self.base.conn);
            m.insert("client_port".into(), json!(self.base.client.port()));
            if let Some(w) = &self.base.who {
                m.extend(w.clone());
            }
            m.insert("url".into(), json!(url));
            m.insert("direction".into(), json!(if response { "received" } else { "sent" }));
            m.insert("opcode".into(), json!(crate::ws::opcode_name(msg.opcode)));
            m.insert("bytes".into(), json!(msg.wire_bytes));
            if msg.truncated {
                m.insert("truncated".into(), json!(true));
            }
            if msg.undecoded {
                m.insert("undecoded".into(), json!(true));
            } else if msg.opcode == 8 && msg.data.len() >= 2 {
                m.insert("close_code".into(), json!(u16::from_be_bytes([msg.data[0], msg.data[1]])));
                m.insert("reason".into(), json!(String::from_utf8_lossy(&msg.data[2..])));
            } else if !msg.data.is_empty() {
                match std::str::from_utf8(&msg.data) {
                    Ok(t) => {
                        let v = serde_json::from_str::<Value>(t).ok().filter(|v| v.is_object() || v.is_array());
                        m.insert("data".into(), v.unwrap_or_else(|| json!(t)));
                    }
                    Err(_) => {
                        use base64::Engine;
                        m.insert(
                            "data_base64".into(),
                            json!(base64::engine::general_purpose::STANDARD.encode(&msg.data)),
                        );
                    }
                }
            }
            let _ = self.ctx.tx.send(m);
        }
    }

    fn url_of(&self, target: &str) -> String {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        let host = if self.base.port == default_port {
            self.base.host.clone()
        } else {
            format!("{}:{}", self.base.host, self.base.port)
        };
        if target.starts_with('/') {
            format!("{}://{host}{target}", self.scheme)
        } else {
            target.to_owned() // absolute-form (plain HTTP proxying)
        }
    }

    fn eof(&mut self, response: bool) {
        if let Some(f) = &mut self.flow {
            f.fin(!response);
        }
        if response {
            let mut p = std::mem::replace(&mut self.resp_p, Parser::new(true));
            p.eof(&mut RespSink(self));
            self.resp_p = p;
        } else {
            let mut p = std::mem::replace(&mut self.req_p, Parser::new(false));
            p.eof(&mut ReqSink(self));
            self.req_p = p;
        }
    }

    fn parse_error(&mut self, dir: &str, why: String) {
        self.errors += 1;
        if self.errors > 1 {
            return;
        }
        let mut m = record("http_parse_error", self.base.conn);
        m.insert("host".into(), json!(self.base.host));
        m.insert("direction".into(), json!(dir));
        m.insert("error".into(), json!(why));
        let _ = self.ctx.tx.send(m);
    }

    /// Fields shared by `http` and `http_request`: who, where, what.
    fn exchange_record(&self, kind: &str, seq: u64, x: &Exchange) -> Map<String, Value> {
        let mut m = record(kind, self.base.conn);
        m.insert("time".into(), json!(crate::log::rfc3339(x.time_ns)));
        // (conn, seq) identifies the exchange across both record types.
        m.insert("seq".into(), json!(seq));
        m.insert("client_port".into(), json!(self.base.client.port()));
        if let Some(w) = &self.base.who {
            m.extend(w.clone());
        }
        let url = self.url_of(&x.req.target);
        m.insert("method".into(), json!(x.req.method));
        m.insert("url".into(), json!(url));
        m
    }

    /// The request has gone out. Logged right away, without the body, so
    /// there is a trace of it even if the response never completes or
    /// agentbox dies first; the full `http` record follows at the end.
    fn request_sent(&mut self, seq: u64) {
        let Some(x) = self.open.get(&seq) else { return };
        let mut m = self.exchange_record("http_request", seq, x);
        m.insert("body_bytes".into(), json!(x.req_body.total));
        let _ = self.ctx.tx.send(m);
    }

    fn emit(&mut self, seq: u64) {
        let Some(x) = self.open.remove(&seq) else { return };
        let keep = self.ctx.opts.keep_secrets;
        let mut m = self.exchange_record("http", seq, &x);

        let mut rq = Map::new();
        rq.insert("headers".into(), http::headers_json(&x.req, keep));
        http::body_json(&x.req, &x.req_body, &mut rq);
        if !x.req_complete {
            rq.insert("incomplete".into(), json!(true));
        }
        m.insert("request".into(), Value::Object(rq));

        match &x.resp {
            Some(h) => {
                m.insert("status".into(), json!(h.status));
                let mut rs = Map::new();
                rs.insert("reason".into(), json!(h.reason));
                rs.insert("headers".into(), http::headers_json(h, keep));
                http::body_json(h, &x.resp_body, &mut rs);
                m.insert("response".into(), Value::Object(rs));
            }
            None => {
                m.insert("status".into(), Value::Null);
                m.insert("response".into(), Value::Null);
            }
        }
        m.insert("duration_ms".into(), json!(x.started.elapsed().as_millis() as u64));
        let _ = self.ctx.tx.send(m);
    }

    fn finish(&mut self) {
        let mut seqs: Vec<u64> = self.open.keys().copied().collect();
        seqs.sort();
        for s in seqs {
            self.emit(s);
        }
    }
}

struct ReqSink<'a>(&'a mut Conv);
struct RespSink<'a>(&'a mut Conv);

impl Sink for ReqSink<'_> {
    fn head(&mut self, h: Head) -> Framing {
        let c = &mut *self.0;
        let seq = c.next_req;
        c.next_req += 1;
        c.cur_req = Some(seq);
        let f = if h.chunked() {
            Framing::Chunked
        } else {
            Framing::Length(h.content_length().unwrap_or(0))
        };
        let cap = c.ctx.opts.body_max;
        c.open.insert(
            seq,
            Exchange {
                time_ns: now_ns(),
                started: Instant::now(),
                req: h,
                req_body: Body::new(cap),
                req_complete: false,
                resp: None,
                resp_body: Body::new(cap),
            },
        );
        f
    }
    fn data(&mut self, d: &[u8]) {
        let c = &mut *self.0;
        if let Some(x) = c.cur_req.and_then(|s| c.open.get_mut(&s)) {
            x.req_body.push(d);
        }
    }
    fn end(&mut self) {
        let c = &mut *self.0;
        let Some(seq) = c.cur_req.take() else { return };
        if let Some(x) = c.open.get_mut(&seq) {
            x.req_complete = true;
            c.request_sent(seq);
        }
    }
    fn error(&mut self, why: String) {
        self.0.parse_error("request", why);
    }
}

impl Sink for RespSink<'_> {
    fn head(&mut self, h: Head) -> Framing {
        let c = &mut *self.0;
        let seq = c.next_resp;
        let is_head = c.open.get(&seq).is_some_and(|x| x.req.method.eq_ignore_ascii_case("HEAD"));
        // 1xx (except 101) precede the real response and carry no body.
        if (100..200).contains(&h.status) && h.status != 101 {
            c.informational = true;
            return Framing::Empty;
        }
        let f = if h.status == 101 {
            // Protocol switch: HTTP parsing stops in both directions. If it
            // is a WebSocket, the frame parsers take over (see Conv::feed).
            c.req_p.stop();
            let hdr = |h: &Head, n: &str| {
                h.header(n).map(|v| String::from_utf8_lossy(v).to_ascii_lowercase()).unwrap_or_default()
            };
            if hdr(&h, "upgrade").contains("websocket") {
                let ext = hdr(&h, "sec-websocket-extensions");
                let target = c.open.get(&seq).map(|x| x.req.target.clone()).unwrap_or_default();
                c.upgrade = Some(Upgrade {
                    url: c.url_of(&target).replacen("http", "ws", 1),
                    deflate: ext.contains("permessage-deflate"),
                    client_no_takeover: ext.contains("client_no_context_takeover"),
                    server_no_takeover: ext.contains("server_no_context_takeover"),
                });
            }
            Framing::Stop
        } else if is_head || h.status == 204 || h.status == 304 {
            Framing::Empty
        } else if h.chunked() {
            Framing::Chunked
        } else if let Some(n) = h.content_length() {
            Framing::Length(n)
        } else {
            Framing::UntilClose
        };
        let cap = c.ctx.opts.body_max;
        let x = c.open.entry(seq).or_insert_with(|| Exchange {
            time_ns: now_ns(),
            started: Instant::now(),
            req: Head::default(),
            req_body: Body::new(cap),
            req_complete: false,
            resp: None,
            resp_body: Body::new(cap),
        });
        x.resp = Some(h);
        f
    }
    fn data(&mut self, d: &[u8]) {
        let c = &mut *self.0;
        if c.informational {
            return;
        }
        if let Some(x) = c.open.get_mut(&c.next_resp) {
            x.resp_body.push(d);
        }
    }
    fn end(&mut self) {
        let c = &mut *self.0;
        if std::mem::take(&mut c.informational) {
            return;
        }
        let seq = c.next_resp;
        c.next_resp += 1;
        c.emit(seq);
    }
    fn error(&mut self, why: String) {
        self.0.parse_error("response", why);
    }
}

/// Write and flush. A TLS stream buffers ciphertext that the socket didn't
/// take right away; without the flush it sits there until the next write,
/// which may never come (the peer is waiting for the rest of the message).
async fn send<W: AsyncWrite + Unpin>(w: &mut W, d: &[u8]) -> std::io::Result<()> {
    w.write_all(d).await?;
    w.flush().await
}

async fn relay<C, U>(client: C, upstream: U, ctx: &Arc<Ctx>, base: Base, scheme: &'static str, initial: Vec<u8>) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let flow = match (&ctx.pcap, base.server) {
        (Some(p), Some(server)) => Some(crate::pcap::Flow::open(p.clone(), base.client, server)),
        _ => None,
    };
    let conv = Arc::new(Mutex::new(Conv {
        flow,
        upgrade: None,
        ws: None,
        ctx: ctx.clone(),
        base,
        scheme,
        req_p: Parser::new(false),
        resp_p: Parser::new(true),
        next_req: 0,
        next_resp: 0,
        cur_req: None,
        open: HashMap::new(),
        informational: false,
        errors: 0,
    }));
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let c2u = {
        let conv = conv.clone();
        async move {
            if !initial.is_empty() {
                conv.lock().unwrap().feed(false, &initial);
                if send(&mut uw, &initial).await.is_err() {
                    return;
                }
            }
            let mut buf = vec![0u8; 64 * 1024];
            let mut seen = !initial.is_empty();
            loop {
                let n = match cr.read(&mut buf).await {
                    Ok(0) => break,
                    Err(e) => {
                        if !seen {
                            // Typically a TLS alert: the client refused the
                            // run's certificate (pinning, or it ignores the
                            // CA environment variables).
                            let c = conv.lock().unwrap();
                            let mut m = record("http_tunnel", c.base.conn);
                            m.insert("host".into(), json!(c.base.host));
                            m.insert("error".into(), json!(format!("client aborted before sending a request (CA not trusted?): {e}")));
                            let _ = c.ctx.tx.send(m);
                        }
                        break;
                    }
                    Ok(n) => n,
                };
                seen = true;
                conv.lock().unwrap().feed(false, &buf[..n]);
                if send(&mut uw, &buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = uw.shutdown().await;
            conv.lock().unwrap().eof(false);
        }
    };
    let u2c = {
        let conv = conv.clone();
        async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match ur.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                conv.lock().unwrap().feed(true, &buf[..n]);
                if send(&mut cw, &buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = cw.shutdown().await;
            conv.lock().unwrap().eof(true);
        }
    };
    tokio::join!(c2u, u2c);
    conv.lock().unwrap().finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority() {
        assert_eq!(split_authority("api.anthropic.com:443", 1).unwrap(), ("api.anthropic.com".into(), 443));
        assert_eq!(split_authority("[::1]:8443", 1).unwrap(), ("::1".into(), 8443));
        assert_eq!(split_authority("example.com", 80).unwrap(), ("example.com".into(), 80));
    }

    #[test]
    fn ca_issues_leaf() {
        let ca = Ca::generate().unwrap();
        assert!(ca.pem.contains("BEGIN CERTIFICATE"));
        ca.server_config("api.anthropic.com").unwrap();
        ca.server_config("127.0.0.1").unwrap();
    }
}
