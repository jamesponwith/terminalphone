//! TerminalPhone v2 entry point (ARCHITECTURE "main.rs").
//!
//! Parses subcommands (`host`, `dial <onion>`, `selftest`), installs the rustls
//! ring crypto provider, initializes tracing, builds the Tokio runtime, and
//! hands off to [`app::App::run`] (or the headless [`selftest`]).

use std::path::PathBuf;
use tphone::app::{App, Command};
use tphone::config::{self, Config, SpeedMode};
use tphone::crypto::Psk;
use tphone::error::Result;
use tphone::selftest;
use tphone::transport::{ArtiTransport, OnionAddr};

const USAGE: &str = "\
terminalphone — anonymous E2E push-to-talk over Tor

USAGE:
    terminalphone [OPTIONS] host
    terminalphone [OPTIONS] dial <onion>
    terminalphone [OPTIONS] qr <onion>
    terminalphone [OPTIONS] selftest

COMMANDS:
    host            Host an onion service and wait for a caller.
    dial <onion>    Dial a remote .onion and start a call.
    qr <onion>      Render a .onion as a scannable terminal QR code and exit.
    selftest        Run a headless integrated loopback self-test (no Tor/audio).

OPTIONS:
    -h, --help              Print this help.
    --data-dir <path>       Data directory (default: $HOME/.terminalphone or $TERMINALPHONE_DIR).
    --speed <mode>          Speed mode: speed_first (default), full_anonymity, single_hop_service.
    --log <level>           Log level: trace, debug, info (default), warn, error.

ENV:
    TERMINALPHONE_PASSPHRASE  Passphrase to wrap/unwrap the secret at rest
                              (Argon2id). If set on first run, the generated PSK
                              is stored encrypted; if set when a plaintext secret
                              exists, it is migrated to the wrapped format.
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
    /// Render an onion as a terminal QR code and exit (no Tor/audio/data-dir).
    Qr(OnionAddr),
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

    // `qr` is fully offline: no Tor bootstrap, audio, data dir, or runtime needed.
    if let ActionCommand::Qr(onion) = &action.command {
        match tphone::qr::render_onion(onion.host()) {
            Ok(rendered) => {
                print!("{rendered}");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }

    // Initialize logging after parsing flags (so --log level is honored).
    let log_level = action.flags.log_level.as_deref().unwrap_or("info");
    // Honor RUST_LOG/the default env if present; otherwise build directly from
    // the resolved level (EnvFilter::new is infallible, so no fallible convert).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));
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
        None => {
            return Ok(Action {
                command: ActionCommand::Usage,
                flags,
            });
        }
    };

    let command = match sub.as_str() {
        "selftest" => ActionCommand::SelfTest,
        "host" => ActionCommand::Call(Command::Host),
        "dial" => {
            let onion = args.get(1).ok_or("`dial` requires an <onion> argument")?;
            let addr = OnionAddr::parse(onion).map_err(|e| e.to_string())?;
            ActionCommand::Call(Command::Dial(addr))
        }
        "qr" => {
            let onion = args.get(1).ok_or("`qr` requires an <onion> argument")?;
            let addr = OnionAddr::parse(onion).map_err(|e| e.to_string())?;
            ActionCommand::Qr(addr)
        }
        other => return Err(format!("unknown command `{other}`")),
    };

    Ok(Action { command, flags })
}

/// Dispatch the parsed action.
async fn run(command: ActionCommand, flags: Flags) -> Result<()> {
    match command {
        // `Usage` and `Qr` are handled before the runtime is built; reaching
        // them here would be a logic error.
        ActionCommand::Usage | ActionCommand::Qr(_) => Ok(()),
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

    // Explicit warning for the IP-revealing single-hop service mode (ADR-0005).
    if cfg.speed_mode == config::SpeedMode::SingleHopService {
        eprintln!(
            "⚠️  WARNING: single-hop service mode REVEALS YOUR REAL IP ADDRESS\n\
             Use this only if you fully understand the exposure.\n\
             Press Ctrl-C to abort, or Enter to proceed.\n"
        );
        let mut confirm = String::new();
        std::io::stdin().read_line(&mut confirm)?;
    }

    let psk = load_or_init_psk(&cfg)?;

    let mut app = App::new(cfg, psk);
    app.run::<ArtiTransport>(cmd).await
}

/// Load the PSK from `$DATA_DIR/secret`, generating one on first run.
///
/// The on-disk `secret` is either a bare 32-byte PSK (the first-run default) or
/// a passphrase-wrapped blob (Argon2id + AES-256-GCM, SPEC §5.2 / ADR-0004).
/// The passphrase is taken from `$TERMINALPHONE_PASSPHRASE` when set, otherwise
/// prompted interactively on a TTY.
///
/// * Wrapped secret  → acquire passphrase, unwrap (wrong passphrase fails loudly).
/// * Bare secret + a passphrase available → **migrate**: wrap it in place (0600).
/// * Bare secret, no passphrase → used as-is, with a hint to protect it.
/// * No secret → generate one; wrap it if a passphrase is available, else bare.
fn load_or_init_psk(cfg: &Config) -> Result<Psk> {
    use tphone::crypto;
    let path = cfg.secret_path();
    let mut pass = std::env::var("TERMINALPHONE_PASSPHRASE")
        .ok()
        .filter(|s| !s.is_empty());

    // Read the existing secret (None on first run); other IO errors propagate.
    let existing = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(tphone::error::Error::Io(e)),
    };

    // A wrapped secret with no passphrase yet must be prompted for before we can
    // resolve it (the only branch that needs interactive input).
    if let Some(bytes) = &existing
        && crypto::is_wrapped(bytes)
        && pass.is_none()
    {
        pass = Some(prompt_passphrase("Enter passphrase to unlock secret: ")?);
    }

    let resolved = resolve_psk(existing.as_deref(), pass.as_deref())?;

    if let Some(blob) = resolved.write_back {
        std::fs::create_dir_all(&cfg.data_dir)?;
        write_secret(&path, &blob)?;
    }
    match resolved.action {
        PskAction::LoadedWrapped => {}
        PskAction::LoadedPlaintext => tracing::info!(
            path = %path.display(),
            "secret stored in plaintext; set TERMINALPHONE_PASSPHRASE to wrap it at rest"
        ),
        PskAction::Migrated => tracing::info!(
            path = %path.display(),
            "migrated plaintext secret to passphrase-wrapped (Argon2id)"
        ),
        PskAction::GeneratedWrapped => tracing::info!(
            path = %path.display(),
            "generated new PSK (passphrase-wrapped); share it out of band"
        ),
        PskAction::GeneratedPlaintext => tracing::info!(
            path = %path.display(),
            "generated new PSK (plaintext at rest); share it out of band"
        ),
    }
    Ok(resolved.psk)
}

/// What [`resolve_psk`] decided to do, for logging.
#[derive(Debug, PartialEq, Eq)]
enum PskAction {
    /// An existing wrapped secret was unlocked.
    LoadedWrapped,
    /// An existing plaintext secret was used as-is.
    LoadedPlaintext,
    /// A plaintext secret was wrapped in place.
    Migrated,
    /// A new PSK was generated and wrapped.
    GeneratedWrapped,
    /// A new PSK was generated in plaintext.
    GeneratedPlaintext,
}

/// The outcome of [`resolve_psk`]: the key, optional bytes to persist, and what
/// happened (for the caller's log line).
struct PskResolution {
    psk: Psk,
    /// Bytes to write back to the secret file, if anything changed on disk.
    write_back: Option<Vec<u8>>,
    action: PskAction,
}

/// Pure secret-resolution policy (no I/O, no env, no prompting), so the
/// migration / generation / unlock matrix is unit-testable.
///
/// `existing` is the current secret-file bytes (None on first run); `pass` is the
/// passphrase already acquired by the caller (env or prompt), if any.
fn resolve_psk(existing: Option<&[u8]>, pass: Option<&str>) -> Result<PskResolution> {
    use tphone::crypto;
    match existing {
        // First run: generate; wrap if a passphrase is available.
        None => {
            let psk = Psk::generate();
            match pass {
                Some(p) => {
                    let blob = crypto::wrap_psk(&psk, p)?;
                    Ok(PskResolution {
                        psk,
                        write_back: Some(blob),
                        action: PskAction::GeneratedWrapped,
                    })
                }
                None => Ok(PskResolution {
                    write_back: Some(psk.0.to_vec()),
                    psk,
                    action: PskAction::GeneratedPlaintext,
                }),
            }
        }
        Some(bytes) if crypto::is_wrapped(bytes) => {
            let p = pass.ok_or_else(|| {
                tphone::error::Error::Crypto("a passphrase is required to unlock the secret".into())
            })?;
            let psk = crypto::unwrap_psk(bytes, p).map_err(|e| match e {
                tphone::error::Error::AuthFailed => {
                    tphone::error::Error::Crypto("wrong passphrase: secret did not unlock".into())
                }
                other => other,
            })?;
            Ok(PskResolution {
                psk,
                write_back: None,
                action: PskAction::LoadedWrapped,
            })
        }
        Some(bytes) if bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(bytes);
            let psk = Psk::from_bytes(key);
            match pass {
                // Plaintext-at-rest migration: wrap the bare secret in place.
                Some(p) => {
                    let blob = crypto::wrap_psk(&psk, p)?;
                    Ok(PskResolution {
                        psk,
                        write_back: Some(blob),
                        action: PskAction::Migrated,
                    })
                }
                None => Ok(PskResolution {
                    psk,
                    write_back: None,
                    action: PskAction::LoadedPlaintext,
                }),
            }
        }
        Some(bytes) => Err(tphone::error::Error::Crypto(format!(
            "secret is {} bytes: not a bare 32-byte PSK nor a recognized wrapped blob",
            bytes.len()
        ))),
    }
}

/// Write `bytes` to the secret `path` at owner-only (0600) permissions on unix.
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Prompt for a passphrase on the controlling terminal and read one line.
///
/// Requires a TTY; with no terminal and no `$TERMINALPHONE_PASSPHRASE` there is
/// no way to acquire the passphrase, which is an explicit error rather than a
/// silent hang. NOTE: input is echoed (no `rpassword` dependency); for
/// unattended use, prefer the env var.
fn prompt_passphrase(prompt: &str) -> Result<String> {
    use std::io::{IsTerminal as _, Write as _};
    if !std::io::stdin().is_terminal() {
        return Err(tphone::error::Error::Crypto(
            "secret is passphrase-wrapped but no TTY is available; \
             set TERMINALPHONE_PASSPHRASE to unlock it non-interactively"
                .into(),
        ));
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tphone::crypto;

    #[test]
    fn first_run_no_pass_generates_plaintext() {
        let r = resolve_psk(None, None).unwrap();
        assert_eq!(r.action, PskAction::GeneratedPlaintext);
        // Write-back is the bare 32-byte key.
        let wb = r.write_back.unwrap();
        assert_eq!(wb.len(), 32);
        assert_eq!(wb, r.psk.0.to_vec());
        assert!(!crypto::is_wrapped(&wb));
    }

    #[test]
    fn first_run_with_pass_generates_wrapped() {
        let r = resolve_psk(None, Some("pw")).unwrap();
        assert_eq!(r.action, PskAction::GeneratedWrapped);
        let wb = r.write_back.unwrap();
        assert!(crypto::is_wrapped(&wb));
        // The wrapped blob unlocks back to the same key.
        assert_eq!(crypto::unwrap_psk(&wb, "pw").unwrap().0, r.psk.0);
    }

    #[test]
    fn bare_secret_no_pass_loads_plaintext_unchanged() {
        let bare = [0x7u8; 32];
        let r = resolve_psk(Some(&bare), None).unwrap();
        assert_eq!(r.action, PskAction::LoadedPlaintext);
        assert!(r.write_back.is_none());
        assert_eq!(r.psk.0, bare);
    }

    #[test]
    fn bare_secret_with_pass_migrates_to_wrapped() {
        let bare = [0x9u8; 32];
        let r = resolve_psk(Some(&bare), Some("hunter2")).unwrap();
        assert_eq!(r.action, PskAction::Migrated);
        // Same key, now persisted in wrapped form.
        assert_eq!(r.psk.0, bare);
        let wb = r.write_back.unwrap();
        assert!(crypto::is_wrapped(&wb));
        assert_eq!(crypto::unwrap_psk(&wb, "hunter2").unwrap().0, bare);
    }

    #[test]
    fn wrapped_secret_unlocks_with_correct_pass() {
        let psk = Psk::generate();
        let blob = crypto::wrap_psk(&psk, "right").unwrap();
        let r = resolve_psk(Some(&blob), Some("right")).unwrap();
        assert_eq!(r.action, PskAction::LoadedWrapped);
        assert!(r.write_back.is_none());
        assert_eq!(r.psk.0, psk.0);
    }

    #[test]
    fn wrapped_secret_wrong_pass_errors() {
        let psk = Psk::generate();
        let blob = crypto::wrap_psk(&psk, "right").unwrap();
        assert!(resolve_psk(Some(&blob), Some("wrong")).is_err());
    }

    #[test]
    fn wrapped_secret_without_pass_errors() {
        let psk = Psk::generate();
        let blob = crypto::wrap_psk(&psk, "right").unwrap();
        // The caller is responsible for prompting; with no passphrase, resolve fails.
        assert!(resolve_psk(Some(&blob), None).is_err());
    }

    #[test]
    fn malformed_secret_length_errors() {
        let junk = [0u8; 17];
        assert!(resolve_psk(Some(&junk), None).is_err());
    }
}
