//! Audio subsystem: threads behind an async facade (ARCHITECTURE "audio", SPEC §5.4).
//!
//! cpal fires on OS audio threads, so capture/playback own dedicated threads and
//! bridge to the async core via bounded channels. [`AudioEngine`] is the only
//! type the app touches; it never sees cpal directly.

pub mod capture;
pub mod codec;
pub mod playback;

// Re-export the submodule facades the app builds against.
pub use capture::Capture;
pub use codec::{OpusDecoder, OpusEncoder};
pub use playback::Playback;

use tokio::sync::mpsc;

use crate::config::OpusParams;
use crate::error::Result;

/// A raw PCM frame captured from / destined for the device (mono, opus-rate samples).
#[derive(Debug, Clone)]
pub struct PcmFrame {
    /// Interleaved i16 mono samples for one opus frame interval.
    pub samples: Vec<i16>,
}

/// An encoded Opus frame ready to be sealed (or freshly opened, ready to decode).
#[derive(Debug, Clone)]
pub struct OpusFrame {
    /// Compressed Opus payload bytes.
    pub data: Vec<u8>,
}

/// Audio configuration (the codec-relevant subset of [`crate::config::Config`]).
#[derive(Debug, Clone, Copy)]
pub struct AudioConfig {
    /// Opus encode/decode parameters.
    pub opus: OpusParams,
}

/// Async facade over capture, codec, and playback (ARCHITECTURE).
///
/// `capture()` yields encoded [`OpusFrame`]s while PTT is held; `play()` enqueues
/// opened frames into the jitter buffer for smooth playout.
pub struct AudioEngine {
    /// Effective audio config.
    _cfg: AudioConfig,
    /// Receiver fed by the capture thread (drained while PTT is held).
    _capture_rx: Option<mpsc::Receiver<OpusFrame>>,
}

impl AudioEngine {
    /// Spin up capture/playback threads and the codec for `cfg`.
    pub fn start(_cfg: AudioConfig) -> Result<Self> {
        todo!("spawn cpal input/output threads, build OpusEncoder/OpusDecoder, wire channels")
    }

    /// Begin PTT-gated capture; returns a receiver yielding encoded frames until
    /// [`AudioEngine::stop_capture`] is called.
    pub fn capture(&mut self) -> Result<mpsc::Receiver<OpusFrame>> {
        todo!("gate capture thread on, hand back the OpusFrame receiver")
    }

    /// Stop capture and flush the end-of-utterance marker (SPEC §5.4).
    pub fn stop_capture(&mut self) -> Result<()> {
        todo!("gate capture off, flush remaining frames")
    }

    /// Enqueue an opened Opus frame into the playback jitter buffer.
    pub fn play(&self, _frame: OpusFrame) -> Result<()> {
        todo!("decode + push into jitter buffer; playout starts after the configured lead")
    }
}
