//! The `Transport` trait — the arti firewall (ARCHITECTURE "Key boundaries", SPEC §5.1).
//!
//! All Tor knowledge lives behind this one trait so a `SystemTorTransport`
//! fallback could drop in without touching crypto/audio/proto. M1 ships only
//! [`arti::ArtiTransport`]; [`loopback::LoopbackTransport`] backs in-process tests.

pub mod arti;
pub mod loopback;

pub use arti::ArtiTransport;
pub use loopback::LoopbackTransport;

use std::path::PathBuf;
use std::pin::Pin;

use futures::{AsyncRead, AsyncWrite, Stream};

use crate::config::SpeedMode;
use crate::error::Result;

/// An onion DataStream (or test equivalent): byte-duplex, framed by `proto`.
///
/// Note: arti's `DataStream` implements **futures** `AsyncRead`/`AsyncWrite`
/// (not tokio's), so this boxed trait object uses the `futures` traits.
pub type Conn = Pin<Box<dyn DuplexStream + Send + Unpin>>;

/// Blanket-implemented marker tying together the read/write halves a `Conn` needs.
pub trait DuplexStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> DuplexStream for T {}

/// A stream of inbound connections accepted on a hosted onion service.
pub type Incoming = Pin<Box<dyn Stream<Item = Result<Conn>> + Send>>;

/// Our long-term onion-service identity (the persisted hidden-service key).
///
/// The `.onion` public form is the user's stable identity (SPEC §5.1). Held
/// opaquely here so the transport impl owns the key representation.
#[derive(Clone)]
pub struct Identity {
    /// Directory under `$DATA_DIR/identity` holding the key material (0600).
    pub key_dir: PathBuf,
    /// Onion-service nickname (arti config requirement).
    pub nickname: String,
}

/// A remote onion address to dial (e.g. `abc…xyz.onion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionAddr(pub String);

impl OnionAddr {
    /// Construct from a user-supplied string, trimming whitespace/trailing slash.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(OnionAddr(s.trim().trim_end_matches('/').to_string()))
    }

    /// The bare host portion (no port).
    pub fn host(&self) -> &str {
        &self.0
    }
}

/// Transport-layer Tor settings projected from [`crate::config::Config`].
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Hop/speed posture (ADR-0005).
    pub speed_mode: SpeedMode,
    /// arti directory cache path (separate per process to avoid lock contention).
    pub cache_dir: PathBuf,
    /// arti state path.
    pub state_dir: PathBuf,
}

/// All Tor access sits behind this trait (ARCHITECTURE).
///
/// Implementors bootstrap once, then either host an onion service (callee) or
/// dial a remote onion (caller). The returned [`Conn`] is framed by `proto`.
#[allow(async_fn_in_trait)]
pub trait Transport: Sized + Send {
    /// Bootstrap the Tor client (background-warmed at launch; cached to disk).
    async fn bootstrap(cfg: &TorConfig) -> Result<Self>;

    /// Host an onion service for `id`; yields a stream of inbound connections.
    async fn host(&self, id: &Identity) -> Result<Incoming>;

    /// Dial a remote onion; yields one outbound connection (the app-port stream).
    async fn dial(&self, onion: &OnionAddr) -> Result<Conn>;

    /// The `.onion` this transport hosts, once a service is launched and published.
    fn onion_address(&self) -> Option<OnionAddr>;
}
