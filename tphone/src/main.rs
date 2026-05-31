//! TerminalPhone v2 entry point (ARCHITECTURE "main.rs").
//!
//! Parses subcommands (`host`, `dial <onion>`, `selftest`), installs the rustls
//! ring crypto provider, initializes tracing, builds the Tokio runtime, and
//! hands off to [`app::App::run`] (or the headless [`selftest`]).

use tphone::app::{App, Command};
use tphone::config::{self, Config, SpeedMode};
use tphone::crypto::Psk;
use tphone::error::Result;
use tphone::selftest;
use tphone::transport::{ArtiTransport, OnionAddr};
use std::path::PathBuf;

const USAGE: &str = "\
terminalphone — anonymous E2E push-to-talk over Tor

USAGE:
    terminalphone [OPTIONS] host
    terminalphone [OPTIONS] dial <onion>
    terminalphone [OPTIONS] selftest

COMMANDS:
    host            Host an onion service and wait for a caller.
    dial <onion>    Dial a remote .onion and start a call.
    selftest        Run a headless integrated loopback self-test (no Tor/audio).

OPTIONS:
    -h, --help              Print this help.
    --data-dir <path>       Data directory (default: $HOME/.terminalphone or $TERMINALPHONE_DIR).
    --speed <mode>          Speed mode: speed_first (default), full_anonymity, single_hop_service.
    --log <level>           Log level: trace, debug, info (default), warn, error.
";

/// Parsed CLI flags.
#[derive(Debug, Default)]
struct Flags {
    data_dir: Option<PathBuf>,
    speed_mode: Option<SpeedMode>,
    log_level: Option<String>,
}

/// Parsed CLI action.
struct Action {
    command: ActionCommand,
    flags: Flags,
}

enum ActionCommand {
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

    let action = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}\n");
            print!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let ActionCommand::Usage = action.command {
        print!("{USAGE}");
        return;
    }

    // Initialize logging after parsing flags (so --log level is honored).
    let log_level = action.flags.log_level.as_deref().unwrap_or("info");
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_from(log_level))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

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

    let result = runtime.block_on(run(action.command, action.flags));
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Parse `std::env` args into an [`Action`].
fn parse_args() -> std::result::Result<Action, String> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    let mut flags = Flags::default();

    // Pre-scan for flags and remove them from args.
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" | "help" => {
                return Ok(Action {
                    command: ActionCommand::Usage,
                    flags,
                });
            }
            "--data-dir" => {
                i += 1;
                let path = args.get(i).ok_or("--data-dir requires a path argument")?;
                flags.data_dir = Some(PathBuf::from(path));
                args.remove(i - 1);
                args.remove(i - 1);
                i -= 1;
            }
            "--speed" => {
                i += 1;
                let mode_str = args.get(i).ok_or("--speed requires a mode argument")?;
                let mode = match mode_str.as_str() {
                    "speed_first" => SpeedMode::SpeedFirst,
                    "full_anonymity" => SpeedMode::FullAnonymity,
                    "single_hop_service" => SpeedMode::SingleHopService,
                    other => return Err(format!("unknown speed mode `{other}`")),
                };
                flags.speed_mode = Some(mode);
                args.remove(i - 1);
                args.remove(i - 1);
                i -= 1;
            }
            "--log" => {
                i += 1;
                let level = args.get(i).ok_or("--log requires a level argument")?;
                flags.log_level = Some(level.clone());
                args.remove(i - 1);
                args.remove(i - 1);
                i -= 1;
            }
            _ if args[i].starts_with("--") => {
                return Err(format!("unknown flag `{}`", args[i]));
            }
            _ => {
                i += 1;
            }
        }
    }

    // Now parse the subcommand from remaining args.
    let sub = match args.first() {
        Some(s) => s.clone(),
        None => return Ok(Action {
            command: ActionCommand::Usage,
            flags,
        }),
    };

    let command = match sub.as_str() {
        "selftest" => ActionCommand::SelfTest,
        "host" => ActionCommand::Call(Command::Host),
        "dial" => {
            let onion = args.get(1).ok_or("`dial` requires an <onion> argument")?;
            let addr = OnionAddr::parse(onion).map_err(|e| e.to_string())?;
            ActionCommand::Call(Command::Dial(addr))
        }
        other => return Err(format!("unknown command `{other}`")),
    };

    Ok(Action { command, flags })
}

/// Dispatch the parsed action.
async fn run(command: ActionCommand, flags: Flags) -> Result<()> {
    match command {
        ActionCommand::Usage => Ok(()),
        ActionCommand::SelfTest => {
            selftest::run().await?;
            println!("selftest: OK — tone + message round-tripped exactly");
            Ok(())
        }
        ActionCommand::Call(cmd) => run_call(cmd, flags).await,
    }
}

/// Resolve config + PSK and run one call over the arti transport.
async fn run_call(cmd: Command, flags: Flags) -> Result<()> {
    let data_dir = flags.data_dir.unwrap_or_else(config::default_data_dir);
    let mut cfg = Config::load(&data_dir).unwrap_or_default();

    // Apply CLI flag overrides to config.
    if let Some(speed) = flags.speed_mode {
        cfg.speed_mode = speed;
    }

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
