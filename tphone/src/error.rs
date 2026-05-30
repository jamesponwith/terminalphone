//! Centralized crate error type and `Result` alias (SPEC §-, ARCHITECTURE "Error & shutdown").
//!
//! User-facing messages are explicit, especially for the failure modes the spec
//! calls out by name: AEAD cipher-suite mismatch, Tor bootstrap failure, and dial
//! failure. Every subsystem maps its lower-level errors into one of these variants.

use thiserror::Error;

/// The single error type returned across the crate's public surface.
#[derive(Debug, Error)]
pub enum Error {
    /// Tor / onion transport failures: bootstrap, hosting, dialing, circuit teardown.
    #[error("transport error: {0}")]
    Transport(String),

    /// AEAD seal/open, HKDF derivation, nonce/counter exhaustion, replay rejection.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The peer offered an AEAD suite we did not negotiate (SPEC §5.2 — abort, never silent).
    #[error("cipher suite mismatch: local {local:?}, peer {peer:?}")]
    CipherMismatch {
        /// The suite this side requested in HELLO.
        local: crate::crypto::AeadSuite,
        /// The suite the peer advertised in HELLO.
        peer: crate::crypto::AeadSuite,
    },

    /// Wire-protocol violations: bad version/type byte, oversized frame, truncated payload.
    #[error("protocol error: {0}")]
    Proto(String),

    /// A frame failed authentication or fell outside the replay window; it is dropped.
    #[error("frame authentication failed (forged, modified, or replayed)")]
    AuthFailed,

    /// Audio capture/playback/codec errors (cpal device, audiopus encode/decode).
    #[error("audio error: {0}")]
    Audio(String),

    /// Config load/parse/validation and data-dir resolution errors.
    #[error("config error: {0}")]
    Config(String),

    /// Underlying byte I/O on the onion `Conn` or on local files.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The remote sent HANGUP or the connection closed cleanly mid-call.
    #[error("connection closed by peer")]
    Closed,

    /// Fallthrough for context-rich errors bubbled via `anyhow`.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Crate-wide `Result` alias bound to [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
