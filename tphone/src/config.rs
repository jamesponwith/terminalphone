//! User configuration and data-dir resolution (SPEC §6.1, §6.2).
//!
//! Config is loaded from `$DATA_DIR/config.toml`; this skeleton freezes the field
//! set every subsystem reads. Data-dir helpers resolve the on-disk layout
//! (identity key, arti cache, PSK, config).

use std::path::PathBuf;
use std::time::Duration;

use crate::crypto::AeadSuite;
use crate::error::Result;
use crate::transport::TorConfig;

/// Opus codec parameters (SPEC §5.4). Defaults: 16 kHz wideband mono, ~24 kbps VBR, 20 ms frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpusParams {
    /// Sample rate in Hz (e.g. 16000; 8000 for constrained links).
    pub sample_rate: u32,
    /// Channel count (mono = 1).
    pub channels: u8,
    /// Target bitrate in bits/sec.
    pub bitrate: u32,
    /// Frame duration in milliseconds (20–40).
    pub frame_ms: u8,
}

impl Default for OpusParams {
    fn default() -> Self {
        OpusParams {
            sample_rate: 16_000,
            channels: 1,
            bitrate: 24_000,
            frame_ms: 20,
        }
    }
}

/// Anonymity vs. latency posture (SPEC §5.1, ADR-0005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpeedMode {
    /// Full anonymity: standard 3+3 hop circuits.
    FullAnonymity,
    /// Speed-first default: reduced hops, still client-anonymous.
    #[default]
    SpeedFirst,
    /// IP-revealing single-hop *service* mode — explicit opt-in, never silent.
    SingleHopService,
}

/// Top-level user config persisted as `config.toml` (SPEC §6.2).
#[derive(Debug, Clone)]
pub struct Config {
    /// Negotiated-by-default AEAD suite advertised in HELLO.
    pub aead_suite: AeadSuite,
    /// Opus encoder/decoder parameters.
    pub opus: OpusParams,
    /// Push-to-talk key (the terminal key that gates capture).
    pub ptt_key: char,
    /// Anonymity / speed posture for Tor circuits.
    pub speed_mode: SpeedMode,
    /// Jitter-buffer lead before playout begins (SPEC §5.4 design knob).
    pub jitter_lead: Duration,
    /// Application port carried inside the onion circuit (matches v1 LISTEN_PORT).
    pub app_port: u16,
    /// Root data directory ($DATA_DIR); all other paths derive from it.
    pub data_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            aead_suite: AeadSuite::Aes256Gcm,
            opus: OpusParams::default(),
            ptt_key: ' ',
            speed_mode: SpeedMode::default(),
            jitter_lead: Duration::from_millis(250),
            app_port: 7777,
            data_dir: default_data_dir(),
        }
    }
}

impl Config {
    /// Load config from `data_dir/config.toml`, falling back to defaults when absent.
    ///
    /// M1 scope: the data-dir is honored (so all derived paths resolve under it)
    /// and an absent config file yields defaults. A full TOML field parse is
    /// deferred (no `serde`/`toml` dependency in M1); when the file exists we
    /// currently start from defaults rooted at `data_dir`. The frozen field set
    /// and the merge-over-defaults contract are preserved for that future parse.
    pub fn load(data_dir: &std::path::Path) -> Result<Self> {
        let cfg = Config {
            data_dir: data_dir.to_path_buf(),
            ..Config::default()
        };
        // If a config file is present we keep defaults for now; the explicit
        // data-dir root is the part every subsystem actually depends on in M1.
        Ok(cfg)
    }

    /// Persist config to `data_dir/config.toml` (0600).
    ///
    /// M1 scope: writes a minimal, human-readable snapshot of the knobs that are
    /// stable on the wire/codec (suite, opus params, ptt key, app port). Full
    /// round-trippable TOML is deferred with [`Config::load`].
    pub fn save(&self) -> Result<()> {
        use std::io::Write as _;

        std::fs::create_dir_all(&self.data_dir)?;
        let path = self.config_path();
        let suite = match self.aead_suite {
            AeadSuite::Aes256Gcm => "aes256gcm",
            AeadSuite::ChaCha20Poly1305 => "chacha20poly1305",
        };
        let body = format!(
            "# terminalphone config (M1 snapshot)\n\
             aead_suite = \"{suite}\"\n\
             ptt_key = \"{}\"\n\
             app_port = {}\n\
             [opus]\n\
             sample_rate = {}\n\
             channels = {}\n\
             bitrate = {}\n\
             frame_ms = {}\n",
            self.ptt_key,
            self.app_port,
            self.opus.sample_rate,
            self.opus.channels,
            self.opus.bitrate,
            self.opus.frame_ms,
        );

        let mut f = std::fs::File::create(&path)?;
        f.write_all(body.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Project the transport-relevant subset for `Transport::bootstrap`.
    pub fn tor_config(&self) -> TorConfig {
        TorConfig {
            speed_mode: self.speed_mode,
            cache_dir: self.arti_dir(),
            state_dir: self.arti_dir(),
        }
    }

    /// `$DATA_DIR/identity` — onion service key material (0600).
    pub fn identity_dir(&self) -> PathBuf {
        self.data_dir.join("identity")
    }

    /// `$DATA_DIR/arti` — cached consensus + state for warm starts.
    pub fn arti_dir(&self) -> PathBuf {
        self.data_dir.join("arti")
    }

    /// `$DATA_DIR/secret` — the PSK (optionally passphrase-wrapped).
    pub fn secret_path(&self) -> PathBuf {
        self.data_dir.join("secret")
    }

    /// `$DATA_DIR/config.toml`.
    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("config.toml")
    }
}

/// Resolve the default data directory (`$TERMINALPHONE_DIR`, else an XDG/HOME path).
pub fn default_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TERMINALPHONE_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".terminalphone")
}
