//! Raw-mode push-to-talk input and call-screen render (SPEC §5.5, crossterm).
//!
//! Terminal raw mode for PTT (no root). The call screen shows the remote
//! `.onion`, AEAD suite-match indicator, ms-level stats, remote PTT state, and a
//! circuit/hops summary.
//!
//! M1 scope: this is a minimal but functional raw-mode harness — enough for the
//! binary to run and route PTT/quit events. Deep UI (alt-screen layout, live
//! stat redraw, hops summary) is intentionally lightweight; the event mapping
//! and raw-mode lifecycle are the load-bearing parts and are implemented.

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::proto::PeerInfo;

/// A PTT-related terminal event surfaced to the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PttEvent {
    /// PTT key pressed — begin capture.
    Down,
    /// PTT key released — flush utterance.
    Up,
    /// User requested hangup (e.g. `q` / Ctrl-C).
    Quit,
}

/// Live stats rendered on the call screen.
#[derive(Debug, Clone, Copy, Default)]
pub struct CallStats {
    /// One-way latency estimate in ms.
    pub latency_ms: u32,
    /// Whether the remote is currently transmitting (their PTT held).
    pub remote_ptt: bool,
}

/// Owns the terminal raw-mode session for the duration of a call.
pub struct Tui {
    /// The PTT key from config.
    ptt_key: char,
    /// Whether raw mode is currently enabled (so `Drop` only restores once).
    raw_enabled: bool,
}

impl Tui {
    /// Enter raw mode and prepare the call screen.
    pub fn enter(cfg: &Config) -> Result<Self> {
        enable_raw_mode().map_err(|e| Error::Io(std::io::Error::other(e)))?;
        Ok(Tui {
            ptt_key: cfg.ptt_key,
            raw_enabled: true,
        })
    }

    /// Poll for the next PTT event (non-blocking-friendly).
    ///
    /// Returns `Ok(None)` if no event was ready within a short window. Maps the
    /// configured PTT key's press/release to [`PttEvent::Down`]/[`PttEvent::Up`]
    /// (terminals that report key-release — most modern ones via the Kitty
    /// protocol — give true press/hold/release; otherwise a press is treated as
    /// a momentary Down+Up by the caller). `q` and Ctrl-C map to [`PttEvent::Quit`].
    pub fn poll_event(&mut self) -> Result<Option<PttEvent>> {
        if !event::poll(Duration::from_millis(10)).map_err(|e| Error::Io(std::io::Error::other(e)))? {
            return Ok(None);
        }
        match event::read().map_err(|e| Error::Io(std::io::Error::other(e)))? {
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind,
                ..
            }) => Ok(self.map_key(code, modifiers, kind)),
            _ => Ok(None),
        }
    }

    /// Map a decoded key event to an optional [`PttEvent`].
    fn map_key(
        &self,
        code: KeyCode,
        modifiers: KeyModifiers,
        kind: KeyEventKind,
    ) -> Option<PttEvent> {
        // Quit: `q` or Ctrl-C, on press.
        if kind != KeyEventKind::Release {
            if let KeyCode::Char('c') = code
                && modifiers.contains(KeyModifiers::CONTROL)
            {
                return Some(PttEvent::Quit);
            }
            if let KeyCode::Char('q') = code {
                return Some(PttEvent::Quit);
            }
        }

        // PTT key: press -> Down, release -> Up.
        if let KeyCode::Char(c) = code
            && c == self.ptt_key
        {
            return match kind {
                KeyEventKind::Release => Some(PttEvent::Up),
                _ => Some(PttEvent::Down),
            };
        }
        None
    }

    /// Render the call screen for `peer` with current `stats`.
    ///
    /// M1 minimal render: a single status line printed in raw mode. Carriage
    /// return + clear keeps it on one line without a full alt-screen layout.
    pub fn render(&mut self, peer: &PeerInfo, stats: &CallStats) -> Result<()> {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let talk = if stats.remote_ptt { "RX" } else { "--" };
        write!(
            out,
            "\r\x1b[2K[call] {} | suite {:?} | {} ms | {} | PTT={}",
            peer.onion.host(),
            peer.suite,
            stats.latency_ms,
            talk,
            self.ptt_key,
        )
        .map_err(Error::Io)?;
        out.flush().map_err(Error::Io)?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        if self.raw_enabled {
            let _ = disable_raw_mode();
        }
    }
}
