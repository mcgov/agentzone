//! agentbox: run an agent harness in a copy-on-write view of a project, with
//! every exec recorded by the kernel.

mod deny;
mod diff;
mod events;
mod http;
mod log;
mod pcap;
mod proxy;
mod sandbox;
mod tracer;

use std::fs;
use std::io::{BufWriter, Write};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use sandbox::{Bind, Cgroup, Config};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command in the sandbox (must be started as root, e.g. via sudo).
    Run(RunArgs),
    /// Show what a finished run changed in the project.
    Diff {
        /// State directory of the run (printed by `run`).
        state: PathBuf,
    },
    /// Run the --log-http proxy on its own, outside any sandbox (no root
    /// needed). Point a client at it with HTTPS_PROXY and trust DIR/ca.pem.
    Proxy(ProxyArgs),
}

#[derive(clap::Args)]
struct HttpLogArgs {
    /// Bytes of each request/response body kept in the log.
    #[arg(long, default_value_t = 8 << 20, value_name = "BYTES")]
    http_body_max: usize,
    /// Log credential headers (Authorization, x-api-key, cookies...)
    /// verbatim. By default they are redacted.
    #[arg(long)]
    http_log_secrets: bool,
    /// Also write the decrypted traffic as a pcap file (one synthesized TCP
    /// stream per connection; open with Wireshark, Decode As HTTP for 443).
    /// Contains credentials unredacted. [default: <state>/http.pcap]
    #[arg(long, value_name = "FILE", num_args = 0..=1)]
    #[allow(clippy::option_option)]
    http_pcap: Option<Option<PathBuf>>,
}

impl HttpLogArgs {
    fn opts(&self) -> proxy::Opts {
        proxy::Opts { body_max: self.http_body_max, keep_secrets: self.http_log_secrets }
    }

    /// Open the --http-pcap file (`default` when given without a value).
    fn pcap(&self, default: &Path) -> Result<Option<Arc<pcap::Pcap>>> {
        let Some(p) = &self.http_pcap else { return Ok(None) };
        let p = p.as_deref().unwrap_or(default);
        let w = pcap::Pcap::create(p)?;
        eprintln!("agentbox: pcap  {}", p.display());
        Ok(Some(w))
    }
}

#[derive(clap::Args)]
struct ProxyArgs {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:3128")]
    listen: String,
    /// Directory to write ca.pem / ca-bundle.pem into.
    #[arg(long, default_value = "./agentbox-proxy")]
    dir: PathBuf,
    /// JSON lines output [default: stdout].
    #[arg(long)]
    log: Option<PathBuf>,
    #[command(flatten)]
    http: HttpLogArgs,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Project directory, mounted copy-on-write.
    #[arg(long, short, default_value = ".")]
    project: PathBuf,
    /// Where the project appears inside the sandbox [default: its host path].
    #[arg(long)]
    mount_at: Option<PathBuf>,
    /// Directory for the overlay layers and logs [default: /var/tmp/agentbox/<name>-<time>].
    #[arg(long)]
    state: Option<PathBuf>,
    /// Exec log (JSON lines) [default: <state>/exec.jsonl].
    #[arg(long)]
    log: Option<PathBuf>,
    /// UID[:GID] the agent runs as [default: $SUDO_UID:$SUDO_GID, else 65534].
    #[arg(long)]
    user: Option<String>,
    /// Give the sandbox its own empty network namespace.
    #[arg(long)]
    no_network: bool,
    /// Record each exec's environment: `names` (default) or `full` values.
    /// Full environments often hold secrets.
    #[arg(long, value_enum, num_args = 0..=1, default_missing_value = "names", value_name = "MODE")]
    capture_env: Option<log::EnvMode>,
    /// Also log read-only opens (default: only opens that can write/create).
    #[arg(long)]
    log_reads: bool,
    /// Use DIR as a template for $HOME, mounted copy-on-write: the agent
    /// sees its contents, but writes land in <state>/home/upper.
    /// e.g. --home-from ~ to bring along your dotfiles and installed tools.
    /// [default: an empty home]
    #[arg(long, value_name = "DIR")]
    home_from: Option<PathBuf>,
    /// Where $HOME is inside the sandbox [default: the --home-from DIR's own
    /// path, so absolute paths and symlinks into it keep working; /home/agent
    /// without --home-from].
    #[arg(long, value_name = "PATH")]
    home_at: Option<PathBuf>,
    /// Extra read-only bind, SRC[:DST]. Repeatable.
    #[arg(long, value_name = "SRC[:DST]")]
    ro_bind: Vec<String>,
    /// Extra read-write bind, SRC[:DST]. Writes go to the host! Repeatable.
    #[arg(long, value_name = "SRC[:DST]")]
    bind: Vec<String>,
    /// Log every HTTP(S) request and response, bodies included, as `http`
    /// records. The sandbox gets its own network namespace whose only exit is
    /// a TLS-intercepting proxy, trusted via a CA generated for this run.
    #[arg(long, conflicts_with = "no_network")]
    log_http: bool,
    #[command(flatten)]
    http: HttpLogArgs,
    /// Refuse to execute a binary: a bare NAME (any file of that name, plus
    /// what it resolves to on $PATH) or an absolute PATH (that file, through
    /// any link to it). Repeatable.
    #[arg(long, value_name = "NAME|PATH")]
    deny: Vec<String>,
    /// Command to run.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

fn parse_bind(s: &str, writable: bool) -> Result<Bind> {
    let (src, dst) = s.split_once(':').unwrap_or((s, s));
    let src = fs::canonicalize(src).with_context(|| format!("bind source {src}"))?;
    let dst = PathBuf::from(dst);
    if !dst.is_absolute() {
        bail!("bind destination {} must be absolute", dst.display());
    }
    Ok(Bind { src, dst, writable })
}

fn parse_user(s: Option<&str>) -> Result<(u32, u32)> {
    if let Some(s) = s {
        let (u, g) = s.split_once(':').unwrap_or((s, s));
        return Ok((u.parse().context("uid")?, g.parse().context("gid")?));
    }
    let env = |k| std::env::var(k).ok().and_then(|v| v.parse().ok());
    match (env("SUDO_UID"), env("SUDO_GID")) {
        (Some(u), Some(g)) => Ok((u, g)),
        _ => Ok((65534, 65534)),
    }
}

fn run(a: RunArgs) -> Result<i32> {
    if !nix::unistd::geteuid().is_root() {
        bail!("agentbox run needs root (namespaces, overlayfs and eBPF); try: sudo agentbox run ...");
    }
    let project = fs::canonicalize(&a.project)
        .with_context(|| format!("project {}", a.project.display()))?;
    if !project.is_dir() {
        bail!("{} is not a directory", project.display());
    }
    let mount_at = a.mount_at.unwrap_or_else(|| project.clone());
    if !mount_at.is_absolute() {
        bail!("--mount-at must be absolute");
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let name = format!(
        "{}-{}-{}",
        project.file_name().and_then(|s| s.to_str()).unwrap_or("project"),
        now.as_secs(),
        std::process::id()
    );
    let state = a.state.unwrap_or_else(|| PathBuf::from("/var/tmp/agentbox").join(&name));
    let (uid, gid) = parse_user(a.user.as_deref())?;
    if uid == 0 {
        eprintln!("agentbox: warning: agent will run as root inside the sandbox");
    }
    let home_from = match &a.home_from {
        Some(h) => {
            let h = fs::canonicalize(h).with_context(|| format!("--home-from {}", h.display()))?;
            if !h.is_dir() {
                bail!("--home-from {} is not a directory", h.display());
            }
            Some(h)
        }
        None => None,
    };
    let home_at = a
        .home_at
        .clone()
        .or_else(|| home_from.clone())
        .unwrap_or_else(|| PathBuf::from("/home/agent"));
    if !home_at.is_absolute() {
        bail!("--home-at must be absolute");
    }
    if mount_at.starts_with(&home_at) && home_from.is_none() {
        bail!("project at {} would be hidden under the empty home {}", mount_at.display(), home_at.display());
    }
    let mut binds = Vec::new();
    for b in &a.ro_bind {
        binds.push(parse_bind(b, false)?);
    }
    for b in &a.bind {
        binds.push(parse_bind(b, true)?);
    }

    let deny = deny::build(
        &a.deny,
        &std::env::var("PATH").unwrap_or_default(),
        &deny::PathMap {
            overlays: std::iter::once((mount_at.as_path(), project.as_path()))
                .chain(home_from.as_deref().map(|h| (home_at.as_path(), h)))
                .collect(),
        },
    )?;
    for n in &deny.notes {
        eprintln!("agentbox: deny {n}");
    }

    let cfg = Config {
        project,
        mount_at,
        state: state.clone(),
        uid,
        gid,
        network: !a.no_network,
        binds,
        command: a.command,
        hostname: "agentbox".into(),
        home_from,
        home_at,
        proxy: a.log_http,
        trust_dir: a.log_http.then(|| state.join("proxy")),
    };
    sandbox::prepare_state(&cfg)?;
    let state = fs::canonicalize(&state)?;
    if a.http.http_pcap.is_some() && !a.log_http {
        bail!("--http-pcap needs --log-http");
    }
    let ca = if a.log_http {
        let ca = Arc::new(proxy::Ca::generate()?);
        proxy::write_trust_files(&ca, &state.join("proxy"))?;
        Some(ca)
    } else {
        None
    };

    fs::write(
        state.join("meta.json"),
        serde_json::to_vec_pretty(&json!({
            "project": cfg.project,
            "mount_at": cfg.mount_at,
            "command": cfg.command,
            "uid": uid,
            "gid": gid,
            "network": cfg.network,
            "home_from": cfg.home_from,
            "home_at": cfg.home_at,
            "log_http": cfg.proxy,
            "deny": a.deny,
            "started_unix": now.as_secs(),
        }))?,
    )?;

    let log_path = a.log.unwrap_or_else(|| state.join("exec.jsonl"));
    let log_file = fs::File::create(&log_path)
        .with_context(|| format!("creating log {}", log_path.display()))?;
    let logger = log::Logger::new(BufWriter::new(log_file), a.capture_env);

    eprintln!("agentbox: state {}", state.display());
    eprintln!("agentbox: log   {}", log_path.display());

    let cgroup = Cgroup::create(&name)?;
    let settings = tracer::Settings {
        cgroup_id: cgroup.id,
        capture_env: a.capture_env.is_some(),
        log_reads: a.log_reads,
        deny: &deny,
    };
    let opts = a.http.opts();
    let pcap = a.http.pcap(&state.join("http.pcap"))?;
    let result = tracer::trace(&settings, logger, || {
        let mut run = sandbox::spawn(&cfg, &cgroup)?;
        let proxy = match (run.listener.take(), &ca) {
            (Some(l), Some(ca)) => Some(proxy::start(
                l,
                ca.clone(),
                opts,
                Some(proxy::Attribution {
                    cgroup_procs: cgroup.path.join("cgroup.procs"),
                    netns_pid: run.helper.as_raw(),
                }),
                pcap.clone(),
            )?),
            _ => None,
        };
        Ok(Sandboxed { run, proxy })
    });
    cgroup.destroy();
    let code = result?;

    let changes = diff::changes(&cfg.upper(), &cfg.project).unwrap_or_default();
    let home_note = match &cfg.home_from {
        Some(h) => format!(
            ", {} in home",
            diff::changes(&cfg.home_upper(), h).map(|c| c.len()).unwrap_or(0)
        ),
        None => String::new(),
    };
    eprintln!(
        "agentbox: exited {code}; {} path(s) changed{home_note} — see: agentbox diff {}",
        changes.len(),
        state.display()
    );
    Ok(code)
}

struct Sandboxed {
    run: sandbox::Running,
    proxy: Option<proxy::Handle>,
}

impl tracer::Supervised for Sandboxed {
    fn try_wait(&mut self) -> Result<Option<i32>> {
        self.run.try_wait()
    }

    fn side_records(&mut self, last: bool) -> Vec<serde_json::Map<String, serde_json::Value>> {
        let Some(p) = &self.proxy else { return Vec::new() };
        if last {
            // The sandbox is gone, so its connections are closing.
            p.settle(std::time::Duration::from_secs(2));
        }
        p.drain()
    }
}

fn run_proxy(a: ProxyArgs) -> Result<i32> {
    let ca = Arc::new(proxy::Ca::generate()?);
    proxy::write_trust_files(&ca, &a.dir)?;
    let dir = fs::canonicalize(&a.dir)?;
    let l = std::net::TcpListener::bind(&a.listen).with_context(|| format!("listening on {}", a.listen))?;
    let url = format!("http://{}", l.local_addr()?);
    let pcap = a.http.pcap(&dir.join("http.pcap"))?;
    let h = proxy::start(l, ca, a.http.opts(), None, pcap)?;
    eprintln!("agentbox: proxy on {url}; to use it:");
    for (k, v) in proxy::agent_env(&url, &dir) {
        if !k.chars().any(|c| c.is_ascii_lowercase()) {
            eprintln!("  export {k}={v}");
        }
    }
    let mut out: Box<dyn Write> = match &a.log {
        Some(p) => Box::new(fs::File::create(p).with_context(|| format!("creating {}", p.display()))?),
        None => Box::new(std::io::stdout()),
    };
    while let Some(m) = h.recv() {
        serde_json::to_writer(&mut out, &serde_json::Value::Object(m))?;
        out.write_all(b"\n")?;
        out.flush()?;
    }
    Ok(0)
}

fn show_diff(state: PathBuf) -> Result<i32> {
    let meta: serde_json::Value = serde_json::from_slice(
        &fs::read(state.join("meta.json")).context("not an agentbox state dir (no meta.json)")?,
    )?;
    let project = PathBuf::from(meta["project"].as_str().context("meta.json: project")?);
    for c in diff::changes(&state.join("upper"), &project)? {
        println!("{} {}", c.code, c.path.display());
    }
    // Home changes are shown relative to $HOME, as ~/path.
    if let Some(home) = meta["home_from"].as_str() {
        for c in diff::changes(&state.join("home/upper"), Path::new(home))? {
            println!("{} ~/{}", c.code, c.path.display());
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Run(a) => run(a),
        Cmd::Diff { state } => show_diff(state),
        Cmd::Proxy(a) => run_proxy(a),
    };
    match r {
        Ok(c) => ExitCode::from(c.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("agentbox: {e:#}");
            ExitCode::from(125)
        }
    }
}
