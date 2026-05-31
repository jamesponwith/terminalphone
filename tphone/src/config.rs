//! User configuration and data-dir resolution (SPEC §6.1, §6.2).
//!
//! Config is loaded from `$DATA_DIR/config.toml`; this skeleton freezes the field
//! set every subsystem reads. Data-dir helpers resolve the on-disk layout
//! (identity key, arti cache, PSK, config).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::AeadSuite;
use crate::error::Result;
use crate::transport::TorConfig;

/// Opus codec parameters (SPEC §5.4). Defaults: 16 kHz wideband mono, ~24 kbps VBR, 20 ms frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedMode {
    /// Full anonymity: standard 3+3 hop circuits.
    FullAnonymity,
    /// Speed-first default: reduced hops, still client-anonymous.
    #[default]
    SpeedFirst,
    /// IP-revealing single-hop *service* mode — explicit opt-in, never silent.
    SingleHopService,
}

/// Intermediate struct for TOML deserialization (Duration handled separately).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigToml {
    #[serde(default)]
    aead_suite: Option<AeadSuite>,
    #[serde(default)]
    opus: Option<OpusParams>,
    #[serde(default)]
    ptt_key: Option<char>,
    #[serde(default)]
    speed_mode: Option<SpeedMode>,
    #[serde(default)]
    jitter_lead_ms: Option<u64>,
    #[serde(default)]
    app_port: Option<u16>,
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
    /// Parses TOML fields: `aead_suite`, `ptt_key`, `app_port`, `speed_mode`,
    /// `jitter_lead_ms`, and `[opus]` table (sample_rate, channels, bitrate, frame_ms).
    /// Missing fields use [`Config::default()`] values. An absent config file is
    /// not an error; defaults are used throughout.
    pub fn load(data_dir: &std::path::Path) -> Result<Self> {
        let path = data_dir.join("config.toml");
        let mut cfg = Config {
            data_dir: data_dir.to_path_buf(),
            ..Config::default()
        };

        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let parsed: ConfigToml = toml::from_str(&content)?;

            if let Some(suite) = parsed.aead_suite {
                cfg.aead_suite = suite;
            }
            if let Some(ptt) = parsed.ptt_key {
                cfg.ptt_key = ptt;
            }
            if let Some(port) = parsed.app_port {
                cfg.app_port = port;
            }
            if let Some(mode) = parsed.speed_mode {
                cfg.speed_mode = mode;
            }
            if let Some(ms) = parsed.jitter_lead_ms {
                cfg.jitter_lead = Duration::from_millis(ms);
            }
            if let Some(opus) = parsed.opus {
                cfg.opus = opus;
            }
        }

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

        let toml_data = ConfigToml {
            aead_suite: Some(self.aead_suite),
            ptt_key: Some(self.ptt_key),
            app_port: Some(self.app_port),
            speed_mode: Some(self.speed_mode),
            jitter_lead_ms: Some(self.jitter_lead.as_millis() as u64),
            opus: Some(self.opus),
        };

        let body = toml::to_string_pretty(&toml_data)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn config_toml_round_trip() {
        let tmpdir = TempDir::new().unwrap();
        let data_dir = tmpdir.path();

        let orig = Config {
            data_dir: data_dir.to_path_buf(),
            aead_suite: AeadSuite::ChaCha20Poly1305,
            ptt_key: 'p',
            app_port: 8888,
            speed_mode: SpeedMode::FullAnonymity,
            jitter_lead: Duration::from_millis(500),
            opus: OpusParams {
                sample_rate: 8_000,
                channels: 1,
                bitrate: 16_000,
                frame_ms: 40,
            },
        };

        orig.save().unwrap();
        let loaded = Config::load(data_dir).unwrap();

        assert_eq!(orig.aead_suite, loaded.aead_suite);
        assert_eq!(orig.ptt_key, loaded.ptt_key);
        assert_eq!(orig.app_port, loaded.app_port);
        assert_eq!(orig.speed_mode, loaded.speed_mode);
        assert_eq!(orig.jitter_lead, loaded.jitter_lead);
        assert_eq!(orig.opus.sample_rate, loaded.opus.sample_rate);
        assert_eq!(orig.opus.channels, loaded.opus.channels);
        assert_eq!(orig.opus.bitrate, loaded.opus.bitrate);
        assert_eq!(orig.opus.frame_ms, loaded.opus.frame_ms);
    }

    #[test]
    fn missing_config_yields_defaults() {
        let tmpdir = TempDir::new().unwrap();
        let data_dir = tmpdir.path();

        let cfg = Config::load(data_dir).unwrap();
        assert_eq!(cfg.aead_suite, AeadSuite::Aes256Gcm);
        assert_eq!(cfg.speed_mode, SpeedMode::SpeedFirst);
    }
}
