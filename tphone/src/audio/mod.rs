//! Audio subsystem: threads behind an async facade (ARCHITECTURE "audio", SPEC §5.4).
//!
//! cpal fires on OS audio threads, so capture/playback own dedicated threads and
//! bridge to the async core via bounded channels. [`AudioEngine`] is the only
//! type the app touches; it never sees cpal directly.
//!
//! ## Backends
//!
//! The engine talks to its devices through an [`AudioBackend`] trait, which has
//! two implementations:
//!
//!   * [`CpalBackend`] — real device I/O via cpal (the app default). Input opens
//!     the mic, resamples to the opus rate, gates on PTT, and *encodes* to
//!     [`OpusFrame`]; output *decodes* incoming [`OpusFrame`]s and drives the
//!     speaker from a jitter buffer. A missing device returns a clean
//!     [`Error::Audio`] rather than panicking.
//!   * [`SyntheticBackend`] — no hardware. Capture yields a deterministic sine
//!     tone (encoded to a real [`OpusFrame`]) on demand; playback decodes into an
//!     in-memory sink that records every PCM sample it receives. This lets the
//!     *entire* capture→encode→decode→play path run headlessly in tests and in a
//!     `selftest` mode.
//!
//! ## Threading / `Send`
//!
//! cpal's `Stream` and (potentially) the libopus codec handles are not `Send` on
//! every platform, yet [`AudioEngine`] is moved into a Tokio task by the app. To
//! stay `Send`-clean unconditionally, **no codec or device handle is ever stored
//! in the engine or moved across a thread boundary**: each dedicated thread
//! *builds* its own encoder/decoder and stream and owns them for its lifetime.
//! The engine and the backend handles carry only plain channels (which are
//! `Send`). Capture sources therefore emit already-encoded [`OpusFrame`]s and
//! playback sinks accept [`OpusFrame`]s to decode internally.

pub mod capture;
pub mod codec;
pub mod playback;

// Re-export the submodule facades the app builds against.
pub use capture::Capture;
pub use codec::{OpusDecoder, OpusEncoder};
pub use playback::Playback;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::config::OpusParams;
use crate::error::{Error, Result};

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

/// How long the playback jitter buffer leads before playout begins. Mirrors
/// `Config::jitter_lead`; kept here so the engine can size both real and
/// synthetic playback identically without depending on the full [`crate::config::Config`].
const DEFAULT_JITTER_LEAD: Duration = Duration::from_millis(250);

// ===========================================================================
// Backend abstraction
// ===========================================================================

/// A capture source: produces *encoded* [`OpusFrame`]s while PTT is engaged.
///
/// The source owns its device + encoder (on whatever thread it needs);
/// the engine only flips the PTT gate and polls. `next_frame` is non-blocking —
/// it returns `None` when nothing is ready yet (PTT up, or not enough audio
/// accumulated).
pub trait CaptureSource: Send {
    /// Engage or disengage the PTT gate. While disengaged, no frames are produced
    /// and any partially-accumulated frame is discarded (SPEC §5.4 end-of-utterance).
    fn set_ptt(&mut self, held: bool);

    /// Pull the next encoded Opus frame, if a full opus-frame interval is ready.
    fn next_frame(&mut self) -> Option<OpusFrame>;
}

/// A playback sink: accepts *encoded* [`OpusFrame`]s, decodes them, and plays
/// (or, for tests, records) the resulting PCM.
pub trait PlaybackSink: Send {
    /// Enqueue an encoded Opus frame for decode + playout.
    fn enqueue(&self, frame: OpusFrame) -> Result<()>;
}

/// A full audio backend: opens a capture source and a playback sink for `cfg`.
///
/// Opening is fallible (a real device may be absent); the engine surfaces that
/// as a clean [`Error::Audio`] rather than panicking.
pub trait AudioBackend: Send {
    /// Open the capture (input) side for `cfg`.
    fn open_capture(&self, cfg: AudioConfig) -> Result<Box<dyn CaptureSource>>;

    /// Open the playback (output) side for `cfg`, buffering `lead` before playout.
    fn open_playback(&self, cfg: AudioConfig, lead: Duration) -> Result<Box<dyn PlaybackSink>>;
}

/// Samples per opus frame at `rate` for a `frame_ms` interval. (Mirrors the
/// private helpers in `capture`/`playback`; kept here for the synthetic backend.)
fn frame_len(rate: u32, frame_ms: u8) -> usize {
    (rate as u64 * frame_ms as u64 / 1000) as usize
}

// ---------------------------------------------------------------------------
// CpalBackend — real device I/O (the app default).
// ---------------------------------------------------------------------------

/// Real device I/O via cpal. Input opens the default mic, resamples to the opus
/// rate, and encodes; output decodes and drives the default speaker from a jitter
/// buffer. A missing device surfaces as an [`Error::Audio`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CpalBackend;

impl CpalBackend {
    /// Construct the cpal backend (no device is opened until the engine asks).
    pub fn new() -> Self {
        CpalBackend
    }
}

impl AudioBackend for CpalBackend {
    fn open_capture(&self, cfg: AudioConfig) -> Result<Box<dyn CaptureSource>> {
        // cpal's `Stream` (and possibly the codec) is `!Send` on some platforms
        // (e.g. CoreAudio on macOS), so the device, stream, and encoder must live
        // on a dedicated thread and never cross into the async engine. We park
        // them on that thread and expose only Send-safe channel handles. The
        // device-open result is relayed back over `ready` so a missing mic
        // surfaces here as an Error rather than from a silent background thread.
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<CaptureCmd>();
        let (frame_tx, frame_rx) = std::sync::mpsc::channel::<OpusFrame>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();

        std::thread::spawn(move || capture_thread(cfg, cmd_rx, frame_tx, ready_tx));

        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(Error::Audio(
                    "capture thread exited before signalling readiness".into(),
                ))
            }
        }

        Ok(Box::new(CpalCaptureSource {
            cmd_tx,
            frame_rx,
            pending: VecDeque::new(),
        }))
    }

    fn open_playback(&self, cfg: AudioConfig, lead: Duration) -> Result<Box<dyn PlaybackSink>> {
        // Same `!Send` constraint: the output stream + decoder live on their own
        // thread; the sink holds only a Send sender of encoded frames.
        let (frame_tx, frame_rx) = std::sync::mpsc::channel::<OpusFrame>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();

        std::thread::spawn(move || playback_thread(cfg, lead, frame_rx, ready_tx));

        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(Error::Audio(
                    "playback thread exited before signalling readiness".into(),
                ))
            }
        }

        Ok(Box::new(CpalPlaybackSink { frame_tx }))
    }
}

/// Commands sent to the capture-owning thread.
enum CaptureCmd {
    /// Flip the PTT gate.
    Ptt(bool),
    /// Wind the thread down (dropping the sender also achieves this).
    Stop,
}

/// Owns the `!Send` cpal input stream and the encoder for its whole lifetime,
/// polling for PCM frames, encoding them, and forwarding the [`OpusFrame`]s to
/// the engine over a Send channel. Runs until the command channel closes or a
/// `Stop` is received.
fn capture_thread(
    cfg: AudioConfig,
    cmd_rx: std::sync::mpsc::Receiver<CaptureCmd>,
    frame_tx: std::sync::mpsc::Sender<OpusFrame>,
    ready_tx: std::sync::mpsc::Sender<Result<()>>,
) {
    // Open the device first; report failure (missing mic, bad params) cleanly.
    let mut cap = match Capture::open(cfg) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let mut encoder = match OpusEncoder::new(cfg.opus) {
        Ok(e) => e,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let _ = ready_tx.send(Ok(()));

    let poll = Duration::from_millis((cfg.opus.frame_ms as u64 / 2).max(1));
    loop {
        // Drain commands without blocking.
        loop {
            match cmd_rx.try_recv() {
                Ok(CaptureCmd::Ptt(held)) => cap.set_ptt(held),
                Ok(CaptureCmd::Stop) => return,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
            }
        }
        let mut produced = false;
        while let Some(pcm) = cap.next_frame() {
            produced = true;
            match encoder.encode(&pcm) {
                Ok(frame) => {
                    if frame_tx.send(frame).is_err() {
                        return; // engine gone
                    }
                }
                Err(e) => tracing::warn!(error = %e, "capture encode failed"),
            }
        }
        if !produced {
            std::thread::sleep(poll);
        }
    }
}

/// Owns the `!Send` cpal output stream and the decoder, decoding each inbound
/// [`OpusFrame`] into the jitter buffer until the channel closes.
fn playback_thread(
    cfg: AudioConfig,
    lead: Duration,
    frame_rx: std::sync::mpsc::Receiver<OpusFrame>,
    ready_tx: std::sync::mpsc::Sender<Result<()>>,
) {
    let pb = match Playback::open(cfg, lead) {
        Ok(p) => p,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let mut decoder = match OpusDecoder::new(cfg.opus) {
        Ok(d) => d,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let _ = ready_tx.send(Ok(()));

    // Block on the channel; decode each frame straight into the jitter buffer.
    // The cpal output callback (owned by `pb`) pulls from there independently.
    while let Ok(frame) = frame_rx.recv() {
        match decoder.decode(&frame) {
            Ok(pcm) => {
                if let Err(e) = pb.enqueue(pcm) {
                    tracing::warn!(error = %e, "cpal playback enqueue failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "playback decode failed"),
        }
    }
    drop(pb); // channel closed: stop the output stream.
}

/// cpal capture source handle (Send): commands the capture thread and pulls the
/// encoded frames it produces. `next_frame` is non-blocking.
struct CpalCaptureSource {
    /// Commands to the capture-owning thread (PTT, stop).
    cmd_tx: std::sync::mpsc::Sender<CaptureCmd>,
    /// Encoded frames produced by the capture thread.
    frame_rx: std::sync::mpsc::Receiver<OpusFrame>,
    /// Frames received but not yet handed out (the thread may batch several).
    pending: VecDeque<OpusFrame>,
}

impl CaptureSource for CpalCaptureSource {
    fn set_ptt(&mut self, held: bool) {
        let _ = self.cmd_tx.send(CaptureCmd::Ptt(held));
    }

    fn next_frame(&mut self) -> Option<OpusFrame> {
        while let Ok(frame) = self.frame_rx.try_recv() {
            self.pending.push_back(frame);
        }
        self.pending.pop_front()
    }
}

impl Drop for CpalCaptureSource {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(CaptureCmd::Stop);
    }
}

/// cpal playback sink handle (Send): forwards encoded frames to the playback thread.
struct CpalPlaybackSink {
    frame_tx: std::sync::mpsc::Sender<OpusFrame>,
}

impl PlaybackSink for CpalPlaybackSink {
    fn enqueue(&self, frame: OpusFrame) -> Result<()> {
        self.frame_tx
            .send(frame)
            .map_err(|_| Error::Audio("playback thread has stopped".into()))
    }
}

// ---------------------------------------------------------------------------
// SyntheticBackend — no hardware, fully deterministic (tests + selftest).
// ---------------------------------------------------------------------------

/// Frequency of the synthetic capture tone (Hz). A mid-band speech frequency so
/// the encoded frame is representative of real voice.
const SYNTH_TONE_HZ: f32 = 440.0;

/// Amplitude of the synthetic capture tone, in i16 units (well below clipping).
const SYNTH_TONE_AMPLITUDE: f32 = 16_000.0;

/// A no-hardware backend for headless runs (tests, `selftest`).
///
/// Capture emits a deterministic sine tone (encoded to a real [`OpusFrame`] on
/// every poll while PTT is engaged); playback decodes every received frame into
/// a shared in-memory sink the caller can inspect afterwards.
#[derive(Debug, Default, Clone)]
pub struct SyntheticBackend {
    /// Shared sink the playback side decodes into, so tests / selftest can read
    /// back what playout received.
    sink: Arc<Mutex<Vec<i16>>>,
}

impl SyntheticBackend {
    /// Construct a synthetic backend with a fresh, empty playback sink.
    pub fn new() -> Self {
        SyntheticBackend {
            sink: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A clone of the shared in-memory sink that playback decodes into. Useful
    /// for tests / selftest to assert that audio actually flowed end to end.
    pub fn sink_handle(&self) -> Arc<Mutex<Vec<i16>>> {
        self.sink.clone()
    }
}

impl AudioBackend for SyntheticBackend {
    fn open_capture(&self, cfg: AudioConfig) -> Result<Box<dyn CaptureSource>> {
        let frame_len = frame_len(cfg.opus.sample_rate, cfg.opus.frame_ms);
        if frame_len == 0 {
            return Err(Error::Audio(
                "synthetic capture: opus frame interval resolves to zero samples".into(),
            ));
        }
        let encoder = OpusEncoder::new(cfg.opus)?;
        Ok(Box::new(SyntheticCaptureSource {
            sample_rate: cfg.opus.sample_rate,
            frame_len,
            phase: 0,
            gate: false,
            encoder,
        }))
    }

    fn open_playback(&self, cfg: AudioConfig, _lead: Duration) -> Result<Box<dyn PlaybackSink>> {
        // Decode happens on the caller's thread inside `enqueue`; the decoder is
        // therefore behind a Mutex (the synthetic sink is shared via Arc and has
        // no thread of its own). This keeps the sink `Send + Sync` so it can live
        // in the engine and be driven from any async worker.
        let decoder = OpusDecoder::new(cfg.opus)?;
        Ok(Box::new(SyntheticPlaybackSink {
            decoder: Mutex::new(decoder),
            sink: self.sink.clone(),
        }))
    }
}

/// Synthetic capture source: a deterministic sine tone, PTT-gated, encoded.
struct SyntheticCaptureSource {
    /// Opus sample rate the tone is generated at.
    sample_rate: u32,
    /// Samples per opus frame.
    frame_len: usize,
    /// Running sample index so the tone is phase-continuous across frames.
    phase: u64,
    /// PTT gate; while closed, `next_frame` yields nothing.
    gate: bool,
    /// Encoder owned by this source (single-threaded use).
    encoder: OpusEncoder,
}

impl CaptureSource for SyntheticCaptureSource {
    fn set_ptt(&mut self, held: bool) {
        // On release, reset phase so the next utterance starts clean — mirrors
        // the real capture's resampler/pending reset.
        if self.gate && !held {
            self.phase = 0;
        }
        self.gate = held;
    }

    fn next_frame(&mut self) -> Option<OpusFrame> {
        if !self.gate {
            return None;
        }
        let mut samples = Vec::with_capacity(self.frame_len);
        for _ in 0..self.frame_len {
            let t = self.phase as f32 / self.sample_rate as f32;
            let v = (2.0 * std::f32::consts::PI * SYNTH_TONE_HZ * t).sin() * SYNTH_TONE_AMPLITUDE;
            samples.push(v as i16);
            self.phase = self.phase.wrapping_add(1);
        }
        match self.encoder.encode(&PcmFrame { samples }) {
            Ok(frame) => Some(frame),
            Err(e) => {
                tracing::warn!(error = %e, "synthetic capture encode failed");
                None
            }
        }
    }
}

/// Synthetic playback sink: decodes every received frame into a shared buffer.
struct SyntheticPlaybackSink {
    decoder: Mutex<OpusDecoder>,
    sink: Arc<Mutex<Vec<i16>>>,
}

impl PlaybackSink for SyntheticPlaybackSink {
    fn enqueue(&self, frame: OpusFrame) -> Result<()> {
        let pcm = {
            let mut dec = self
                .decoder
                .lock()
                .map_err(|_| Error::Audio("synthetic decoder lock poisoned".into()))?;
            dec.decode(&frame)?
        };
        let mut sink = self
            .sink
            .lock()
            .map_err(|_| Error::Audio("synthetic playback sink lock poisoned".into()))?;
        sink.extend(pcm.samples);
        Ok(())
    }
}

// ===========================================================================
// AudioEngine
// ===========================================================================

/// Async facade over capture, codec, and playback (ARCHITECTURE).
///
/// `capture()` yields encoded [`OpusFrame`]s while PTT is held; `play()` enqueues
/// opened frames into the jitter buffer for smooth playout.
///
/// The engine is backend-agnostic: build it with [`AudioEngine::cpal`] for real
/// devices (the app default), [`AudioEngine::synthetic`] for headless runs, or
/// [`AudioEngine::with_backend`] to supply your own [`AudioBackend`]. No codec or
/// device handle lives in the engine itself, so the engine is `Send` and can be
/// moved into a Tokio task (as `app.rs` does).
pub struct AudioEngine {
    /// Effective audio config.
    cfg: AudioConfig,
    /// Jitter lead applied when opening playback.
    lead: Duration,
    /// The backend that opens capture sources / playback sinks.
    backend: Box<dyn AudioBackend>,
    /// The open playback sink, set up at [`AudioEngine::start_engine`].
    sink: Mutex<Option<Box<dyn PlaybackSink>>>,
    /// Handle to a running capture pump, if PTT capture is active.
    capture: Mutex<Option<CaptureHandle>>,
}

/// A running capture pump: the thread draining the capture source into the
/// outbound channel, plus the stop flag shared with it.
struct CaptureHandle {
    /// Set to `false` to ask the capture thread to wind down.
    running: Arc<AtomicBool>,
    /// Join handle for the pump thread, taken when `stop_capture` joins it.
    join: Option<std::thread::JoinHandle<()>>,
}

impl AudioEngine {
    /// Build an engine over an arbitrary backend (no device is opened yet).
    pub fn with_backend(cfg: AudioConfig, backend: Box<dyn AudioBackend>) -> Self {
        AudioEngine {
            cfg,
            lead: DEFAULT_JITTER_LEAD,
            backend,
            sink: Mutex::new(None),
            capture: Mutex::new(None),
        }
    }

    /// Build a cpal-backed engine (real devices; the app default).
    pub fn cpal(cfg: AudioConfig) -> Self {
        Self::with_backend(cfg, Box::new(CpalBackend::new()))
    }

    /// Build a synthetic, hardware-free engine (tests / `selftest`).
    pub fn synthetic(cfg: AudioConfig) -> Self {
        Self::with_backend(cfg, Box::new(SyntheticBackend::new()))
    }

    /// Override the jitter lead applied when playback opens (defaults to 250 ms).
    /// Call before [`AudioEngine::start_engine`].
    pub fn with_lead(mut self, lead: Duration) -> Self {
        self.lead = lead;
        self
    }

    /// Spin up the playback side for `cfg` over the cpal backend.
    ///
    /// This is the constructor `app.rs` calls. It defaults to the cpal backend so
    /// the production binary opens real devices; a headless caller builds the
    /// engine with [`AudioEngine::synthetic`] / [`AudioEngine::with_backend`] and
    /// then calls [`AudioEngine::start_engine`].
    pub fn start(cfg: AudioConfig) -> Result<Self> {
        let mut engine = Self::cpal(cfg);
        engine.start_engine()?;
        Ok(engine)
    }

    /// Open the playback sink on an already-constructed engine (any backend).
    /// Re-opening replaces the existing sink.
    pub fn start_engine(&mut self) -> Result<()> {
        let sink = self.backend.open_playback(self.cfg, self.lead)?;
        *self.sink.lock().expect("sink lock") = Some(sink);
        Ok(())
    }

    /// Begin PTT-gated capture; returns a receiver yielding encoded frames until
    /// [`AudioEngine::stop_capture`] is called.
    ///
    /// Opens the backend's capture source, engages PTT, and spawns a pump thread
    /// that polls the source and forwards each [`OpusFrame`] over the returned
    /// channel. The thread runs until the channel receiver is dropped or
    /// [`AudioEngine::stop_capture`] is called.
    pub fn capture(&mut self) -> Result<mpsc::Receiver<OpusFrame>> {
        // Stop any prior capture so we never run two pumps at once.
        self.stop_capture()?;

        let mut source = self.backend.open_capture(self.cfg)?;
        source.set_ptt(true);

        let (tx, rx) = mpsc::channel::<OpusFrame>(64);
        let running = Arc::new(AtomicBool::new(true));
        let run_flag = running.clone();

        // Poll cadence: a fraction of the frame interval so the pump keeps the
        // source drained without busy-spinning.
        let poll = Duration::from_millis((self.cfg.opus.frame_ms as u64 / 2).max(1));

        let join = std::thread::spawn(move || {
            'pump: while run_flag.load(Ordering::SeqCst) {
                let mut produced = false;
                while let Some(mut frame) = source.next_frame() {
                    produced = true;
                    // Send without blocking indefinitely: a full channel (slow or
                    // absent receiver) must not wedge the pump so it stops
                    // checking `run_flag`. Back off and retry, bailing the moment
                    // the receiver is gone or we are asked to stop.
                    loop {
                        match tx.try_send(frame) {
                            Ok(()) => break,
                            Err(mpsc::error::TrySendError::Closed(_)) => break 'pump,
                            Err(mpsc::error::TrySendError::Full(f)) => {
                                if !run_flag.load(Ordering::SeqCst) {
                                    break 'pump;
                                }
                                frame = f;
                                std::thread::sleep(poll);
                            }
                        }
                    }
                    if !run_flag.load(Ordering::SeqCst) {
                        break 'pump;
                    }
                }
                if !produced {
                    std::thread::sleep(poll);
                }
            }
            // Disengage PTT so the source flushes its end-of-utterance state
            // before it drops.
            source.set_ptt(false);
        });

        *self.capture.lock().expect("capture lock") = Some(CaptureHandle {
            running,
            join: Some(join),
        });
        Ok(rx)
    }

    /// Stop capture and flush the end-of-utterance marker (SPEC §5.4).
    ///
    /// Signals the pump thread to wind down and joins it; disengaging PTT inside
    /// the thread discards any partial frame so the next utterance starts clean.
    pub fn stop_capture(&mut self) -> Result<()> {
        let handle = self.capture.lock().expect("capture lock").take();
        if let Some(mut h) = handle {
            h.running.store(false, Ordering::SeqCst);
            if let Some(join) = h.join.take() {
                // A panicked audio thread should not poison the engine; log and
                // continue so teardown still completes.
                if join.join().is_err() {
                    tracing::warn!("capture thread panicked during stop_capture");
                }
            }
        }
        Ok(())
    }

    /// Enqueue an opened Opus frame into the playback path (decode + jitter
    /// buffer). Returns an error if the engine was never started (no sink).
    pub fn play(&self, frame: OpusFrame) -> Result<()> {
        let guard = self.sink.lock().expect("sink lock");
        let sink = guard
            .as_ref()
            .ok_or_else(|| Error::Audio("play() before start: no playback sink".into()))?;
        sink.enqueue(frame)
    }
}

impl Drop for AudioEngine {
    fn drop(&mut self) {
        // Best-effort: wind down the capture pump so its thread does not outlive
        // the engine.
        let _ = self.stop_capture();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AudioConfig {
        AudioConfig {
            opus: OpusParams::default(),
        }
    }

    /// PTT-gated synthetic capture produces (encoded) frames only while engaged.
    #[test]
    fn ptt_gates_synthetic_capture() {
        let backend = SyntheticBackend::new();
        let mut source = backend.open_capture(cfg()).unwrap();

        // Gate closed by default: nothing.
        assert!(source.next_frame().is_none(), "no frames before PTT engaged");

        source.set_ptt(true);
        let frame = source.next_frame().expect("a frame while PTT held");
        assert!(!frame.data.is_empty(), "encoded opus frame is non-empty");

        source.set_ptt(false);
        assert!(source.next_frame().is_none(), "no frames after PTT released");
    }

    /// The engine capture pump only emits frames while PTT is engaged, and stops
    /// cleanly when asked.
    #[tokio::test]
    async fn engine_capture_pump_is_ptt_gated_and_stoppable() {
        let mut engine = AudioEngine::synthetic(cfg());
        engine.start_engine().unwrap();

        // capture() engages PTT and starts producing.
        let mut rx = engine.capture().unwrap();
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a frame should arrive while PTT is engaged")
            .expect("channel open");
        assert!(!first.data.is_empty(), "encoded opus frame is non-empty");

        // Stopping capture winds the pump down; the channel eventually closes.
        engine.stop_capture().unwrap();
        loop {
            match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Some(_)) => continue, // residual buffered frame
                Ok(None) => break,       // channel closed -> pump gone
                Err(_) => panic!("pump did not stop after stop_capture"),
            }
        }
    }

    /// `play()` round-trips an encoded frame through decode into the synthetic
    /// sink, recovering one frame's worth of PCM with real energy.
    #[test]
    fn play_round_trips_into_sink() {
        let backend = SyntheticBackend::new();
        let sink = backend.sink_handle();
        let mut engine = AudioEngine::with_backend(cfg(), Box::new(backend));
        engine.start_engine().unwrap();

        // Produce a real encoded frame from a separate synthetic source.
        let mut source = SyntheticBackend::new().open_capture(cfg()).unwrap();
        source.set_ptt(true);
        let opus = source.next_frame().unwrap();

        engine.play(opus).expect("play decodes + enqueues");

        let recorded = sink.lock().unwrap();
        let expected = frame_len(cfg().opus.sample_rate, cfg().opus.frame_ms);
        assert_eq!(
            recorded.len(),
            expected,
            "one decoded frame's worth of PCM reached the sink"
        );
        let energy: i64 = recorded.iter().map(|&s| (s as i64) * (s as i64)).sum();
        assert!(energy > 0, "decoded tone reached the sink with energy");
    }

    /// `play()` before `start_engine` is a clean error, not a panic.
    #[test]
    fn play_before_start_errors() {
        let engine = AudioEngine::synthetic(cfg());
        let err = engine.play(OpusFrame { data: vec![0u8; 8] });
        assert!(matches!(err, Err(Error::Audio(_))), "got {err:?}");
    }

    /// Multiple frames accumulate in arrival order in the synthetic sink.
    #[test]
    fn play_accumulates_multiple_frames_in_order() {
        let backend = SyntheticBackend::new();
        let sink = backend.sink_handle();
        let mut engine = AudioEngine::with_backend(cfg(), Box::new(backend));
        engine.start_engine().unwrap();

        let mut src = SyntheticBackend::new().open_capture(cfg()).unwrap();
        src.set_ptt(true);

        let n_frames = 3;
        for _ in 0..n_frames {
            let opus = src.next_frame().unwrap();
            engine.play(opus).unwrap();
        }

        let frame = frame_len(cfg().opus.sample_rate, cfg().opus.frame_ms);
        let recorded = sink.lock().unwrap();
        assert_eq!(
            recorded.len(),
            frame * n_frames,
            "all decoded frames accumulate in arrival order"
        );
    }

    /// End-to-end headless path: drive the engine's capture pump into `play()`,
    /// proving capture→encode→decode→sink runs with no hardware. This is the
    /// shape a `selftest` mode uses.
    #[tokio::test]
    async fn synthetic_capture_to_play_round_trip() {
        let backend = SyntheticBackend::new();
        let sink = backend.sink_handle();
        let mut engine = AudioEngine::with_backend(cfg(), Box::new(backend));
        engine.start_engine().unwrap();

        let mut rx = engine.capture().unwrap();
        // Pull a few captured (encoded) frames and play them back.
        let mut played = 0;
        for _ in 0..3 {
            let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("captured frame")
                .expect("channel open");
            engine.play(frame).unwrap();
            played += 1;
        }
        engine.stop_capture().unwrap();

        let frame = frame_len(cfg().opus.sample_rate, cfg().opus.frame_ms);
        let recorded = sink.lock().unwrap();
        assert_eq!(
            recorded.len(),
            frame * played,
            "every captured frame decoded into the sink"
        );
        let energy: i64 = recorded.iter().map(|&s| (s as i64) * (s as i64)).sum();
        assert!(energy > 0, "round-tripped tone carries energy");
    }
}
