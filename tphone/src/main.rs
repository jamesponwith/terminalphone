//! TerminalPhone v2 entry point (ARCHITECTURE "main.rs").
//!
//! Parses subcommands (`host`, `dial <onion>`), installs the rustls ring crypto
//! provider, initializes tracing, builds the Tokio runtime, and hands off to
//! [`app::App::run`].

use tphone::app::{App, Command};
use tphone::config::{self, Config};
use tphone::crypto::Psk;
use tphone::error::Result;
use tphone::transport::{ArtiTransport, OnionAddr};

const USAGE: &str = "\
terminalphone — anonymous E2E push-to-talk over Tor

USAGE:
    terminalphone host
    terminalphone dial <onion>

COMMANDS:
    host            Host an onion service and wait for a caller.
    dial <onion>    Dial a remote .onion and start a call.

OPTIONS:
    -h, --help      Print this help.
";

fn main() {
    // rustls 0.23+ won't pick a crypto backend implicitly; install ring once at startup.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Structured logging to stderr (RUST_LOG-controlled).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cmd = match parse_args() {
        Ok(Some(cmd)) => cmd,
        Ok(None) => {
            print!("{USAGE}");
            return;
        }
        Err(msg) => {
            eprintln!("error: {msg}\n");
            print!("{USAGE}");
            std::process::exit(2);
        }
    };

    // Multi-threaded Tokio runtime hosts arti and the async core.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = runtime.block_on(run(cmd)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Parse `std::env` args into a [`Command`]. `Ok(None)` means "print usage".
fn parse_args() -> std::result::Result<Option<Command>, String> {
    let mut args = std::env::args().skip(1);
    let sub = match args.next() {
        Some(s) => s,
        None => return Ok(None),
    };

    match sub.as_str() {
        "-h" | "--help" | "help" => Ok(None),
        "host" => Ok(Some(Command::Host)),
        "dial" => {
            let onion = args
                .next()
                .ok_or_else(|| "`dial` requires an <onion> argument".to_string())?;
            let addr = OnionAddr::parse(&onion).map_err(|e| e.to_string())?;
            Ok(Some(Command::Dial(addr)))
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

/// Resolve config + PSK and run one call over the arti transport.
async fn run(cmd: Command) -> Result<()> {
    let data_dir = config::default_data_dir();
    let cfg = Config::load(&data_dir).unwrap_or_default();
    let psk = load_or_init_psk(&cfg)?;

    let mut app = App::new(cfg, psk);
    app.run::<ArtiTransport>(cmd).await
}

/// Load the PSK from `$DATA_DIR/secret`, generating one on first run.
///
/// M1 scope: the secret is stored as raw 32 bytes at owner-only perms.
/// Passphrase-at-rest wrapping (Argon2id, SPEC §5.2 / ADR-0004) is deferred and
/// noted as a follow-up; the on-disk format is a bare key so a future wrapped
/// format can be distinguished by length/header without ambiguity.
fn load_or_init_psk(cfg: &Config) -> Result<Psk> {
    let path = cfg.secret_path();
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Psk::from_bytes(key))
        }
        Ok(bytes) => Err(tphone::error::Error::Crypto(format!(
            "secret at {} is {} bytes; expected a bare 32-byte PSK (passphrase-wrapped \
             format is not yet supported in M1)",
            path.display(),
            bytes.len()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // First run: generate, persist at 0600, return.
            let psk = Psk::generate();
            std::fs::create_dir_all(&cfg.data_dir)?;
            std::fs::write(&path, psk.0)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            tracing::info!(path = %path.display(), "generated new PSK (share it out of band)");
            Ok(psk)
        }
        Err(e) => Err(tphone::error::Error::Io(e)),
    }
}
