//! TerminalPhone v2 — anonymous end-to-end push-to-talk over Tor.
//!
//! Library crate exposing the call core (transport / proto / crypto / audio /
//! app state machine) so integration tests and the `terminalphone` binary share
//! one implementation. The binary (`main.rs`) is a thin CLI + runtime shell over
//! [`app::App`].
//!
//! See `docs/ARCHITECTURE.md` for the module map and the `Transport`-trait
//! boundary, and `docs/SPEC.md` for the wire/crypto specifications.

pub mod app;
pub mod audio;
pub mod config;
pub mod crypto;
pub mod error;
pub mod proto;
pub mod qr;
pub mod selftest;
pub mod transport;
pub mod tui;
