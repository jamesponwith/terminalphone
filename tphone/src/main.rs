//! TerminalPhone v2 entry point (ARCHITECTURE "main.rs").
//!
//! Parses subcommands (`host`, `dial <onion>`, `selftest`), installs the rustls
//! ring crypto provider, initializes tracing, builds the Tokio runtime, and
//! hands off to [`app::App::run`] (or the headless [`selftest`]).

use tphone::app::{App, Command};
use tphone::config::{self, Config};
use tphone::crypto::Psk;
use tphone::error::Result;
use tphone::selftest;
use tphone::transport::{ArtiTransport, OnionAddr};

const USAGE: &str = "\
terminalphone — anonymous E2E push-to-talk over Tor

USAGE:
    terminalphone host
    terminalphone dial <onion>
    terminalphone selftest

COMMANDS:
    host            Host an onion service and wait for a caller.
    dial <onion>    Dial a remote .onion and start a call.
    selftest        Run a headless integrated loopback self-test (no Tor/audio).

OPTIONS:
    -h, --help      Print this help.
";

/// Parsed CLI action.
enum Action {
    /// Run a real call (host or dial) over the arti transport + TUI.
    Call(Command),
    /// Run the headless integrated self-test.
    SelfTest,
    /// Print usage and exit 0.
    Usage,
}

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

    let action = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}\n");
            print!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let Action::Usage = action {
        print!("{USAGE}");
        return;
    }

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

    let result = runtime.block_on(run(action));
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Parse `std::env` args into an [`Action`].
fn parse_args() -> std::result::Result<Action, String> {
    let mut args = std::env::args().skip(1);
    let sub = match args.next() {
        Some(s) => s,
        None => return Ok(Action::Usage),
    };

    match sub.as_str() {
        "-h" | "--help" | "help" => Ok(Action::Usage),
        "selftest" => Ok(Action::SelfTest),
        "host" => Ok(Action::Call(Command::Host)),
        "dial" => {
            let onion = args
                .next()
                .ok_or_else(|| "`dial` requires an <onion> argument".to_string())?;
            let addr = OnionAddr::parse(&onion).map_err(|e| e.to_string())?;
            Ok(Action::Call(Command::Dial(addr)))
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

/// Dispatch the parsed action.
async fn run(action: Action) -> Result<()> {
    match action {
        Action::Usage => Ok(()),
        Action::SelfTest => {
            selftest::run().await?;
            println!("selftest: OK — tone + message round-tripped exactly");
            Ok(())
        }
        Action::Call(cmd) => run_call(cmd).await,
    }
}

/// Resolve config + PSK and run one call over the arti transport.
async fn run_call(cmd: Command) -> Result<()> {
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
