//! Microphone capture: cpal input + resample to the Opus rate, PTT-gated
//! (SPEC §5.4, ARCHITECTURE "capture.rs", ADR-0003).
//!
//! cpal fires its data callback on an OS-owned audio thread. We do the minimum
//! work there — downmix to mono, push raw samples into a [`std::sync::mpsc`]
//! channel — and perform resampling + frame chunking on the consumer side
//! ([`Capture::next_frame`]), which is driven by the async core. A PTT gate
//! (an [`AtomicBool`] shared with the callback) decides whether captured audio
//! is kept or dropped, so silence while the key is up costs nothing downstream.
//!
//! Device-touching code is gated behind the `Capture::open` constructor; the
//! pure resample/frame logic is exercised by unit tests with a synthetic
//! producer, so the crate builds and the logic is testable without a mic.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;

use crate::audio::{AudioConfig, PcmFrame};
use crate::error::{Error, Result};

/// Owns the cpal input stream and produces opus-rate PCM frames while PTT is held.
pub struct Capture {
    /// Effective audio config (sample rate / channels drive resampling).
    _cfg: AudioConfig,
    /// Shared inner state (gate + plumbing) usable with or without a device.
    inner: CaptureInner,
    /// The live cpal stream handle. Stored opaquely so the rest of the module
    /// is device-agnostic. Dropping it stops capture.
    _device_stream: Option<DeviceStream>,
}

/// Device-independent capture state: the PTT gate, the raw-sample receiver, and
/// the streaming resampler that turns the device rate into opus-rate frames.
struct CaptureInner {
    /// PTT gate shared with the device callback. When `false`, the callback
    /// discards audio so nothing reaches the channel.
    gate: Arc<AtomicBool>,
    /// Raw mono samples at the *device* sample rate, as delivered by cpal.
    raw_rx: Receiver<f32>,
    /// Streaming linear resampler: device rate -> opus rate, producing fixed
    /// opus-frame-sized chunks.
    resampler: Resampler,
    /// Samples per opus frame at the opus rate (e.g. 320 for 20 ms @ 16 kHz).
    frame_len: usize,
    /// Accumulates opus-rate samples until a full frame is available.
    pending: Vec<i16>,
}

/// Opaque holder for the platform audio stream. We never name cpal types in the
/// public surface; this keeps the device wiring in one place.
struct DeviceStream {
    #[allow(dead_code)]
    stream: cpal::Stream,
}

// cpal::Stream is `!Send` on some platforms; `Capture` is therefore intended to
// live on the thread that opened it. The async facade in `mod.rs` owns it on a
// dedicated thread, matching the ARCHITECTURE note that audio owns its threads.

impl Capture {
    /// Open the default input device and prepare the resampler.
    ///
    /// On success the device is streaming immediately but the PTT gate starts
    /// **closed**, so no frames are produced until [`Capture::set_ptt(true)`].
    pub fn open(cfg: AudioConfig) -> Result<Self> {
        let opus_rate = cfg.opus.sample_rate;
        let frame_len = frame_len(opus_rate, cfg.opus.frame_ms);
        if frame_len == 0 {
            return Err(Error::Audio(
                "opus frame interval resolves to zero samples".into(),
            ));
        }

        let gate = Arc::new(AtomicBool::new(false));
        let (raw_tx, raw_rx) = std::sync::mpsc::channel::<f32>();

        let (device_stream, device_rate) =
            open_input_stream(gate.clone(), raw_tx).map_err(|e| {
                Error::Audio(format!("failed to open input device: {e}"))
            })?;

        let inner = CaptureInner {
            gate,
            raw_rx,
            resampler: Resampler::new(device_rate, opus_rate),
            frame_len,
            pending: Vec::with_capacity(frame_len * 2),
        };

        Ok(Capture {
            _cfg: cfg,
            inner,
            _device_stream: Some(device_stream),
        })
    }

    /// Enable or disable the PTT gate. While disabled, captured audio is dropped
    /// at the device callback and any partially-accumulated frame is discarded
    /// so the next utterance starts clean (SPEC §5.4 end-of-utterance semantics).
    pub fn set_ptt(&mut self, held: bool) {
        let was = self.inner.gate.swap(held, Ordering::SeqCst);
        if was && !held {
            // PTT released: drop the partial frame and any raw remainder so we
            // do not splice the tail of one utterance onto the head of the next.
            self.inner.pending.clear();
            self.inner.resampler.reset();
            // Drain whatever the callback queued between the last poll and the
            // gate flip; it belongs to the just-ended utterance.
            while let Ok(_sample) = self.inner.raw_rx.try_recv() {}
        }
    }

    /// Pull the next captured PCM frame (one opus frame interval), if available.
    ///
    /// Drains all raw samples currently queued by the device callback, resamples
    /// them to the opus rate, and returns one full frame if enough samples have
    /// accumulated. Returns `None` when PTT is up or not enough audio is ready
    /// yet (caller should poll again after a short interval).
    pub fn next_frame(&mut self) -> Option<PcmFrame> {
        self.inner.next_frame()
    }
}

impl CaptureInner {
    fn next_frame(&mut self) -> Option<PcmFrame> {
        let gate_open = self.gate.load(Ordering::SeqCst);

        // Always drain the channel to keep it from backing up; only keep the
        // samples when the gate is open.
        loop {
            match self.raw_rx.try_recv() {
                Ok(sample) => {
                    if gate_open {
                        self.resampler.push(sample, &mut self.pending);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        if !gate_open || self.pending.len() < self.frame_len {
            return None;
        }

        let frame: Vec<i16> = self.pending.drain(..self.frame_len).collect();
        Some(PcmFrame { samples: frame })
    }
}

/// Samples per opus frame at `rate` for a `frame_ms` interval.
fn frame_len(rate: u32, frame_ms: u8) -> usize {
    (rate as u64 * frame_ms as u64 / 1000) as usize
}

/// A minimal streaming linear-interpolation resampler from `in_rate` to
/// `out_rate`, converting f32 device samples to clamped i16 opus-rate samples.
///
/// Linear interpolation is deliberate: it is cheap (latency budget, SPEC §3),
/// allocation-free per sample, and adequate for speech where Opus re-bandlimits
/// anyway. It maintains phase across `push` calls so frame boundaries do not
/// introduce discontinuities; `reset` clears that phase between utterances.
struct Resampler {
    /// Ratio of input samples consumed per output sample produced.
    step: f64,
    /// Fractional read position into the input stream, in input samples.
    pos: f64,
    /// The previous input sample, needed to interpolate across `push` calls.
    prev: f32,
    /// Whether `prev` holds a real sample yet.
    primed: bool,
    /// True when no resampling is needed (rates equal).
    passthrough: bool,
}

impl Resampler {
    fn new(in_rate: u32, out_rate: u32) -> Self {
        let in_rate = in_rate.max(1);
        let out_rate = out_rate.max(1);
        Resampler {
            step: in_rate as f64 / out_rate as f64,
            pos: 0.0,
            prev: 0.0,
            primed: false,
            passthrough: in_rate == out_rate,
        }
    }

    fn reset(&mut self) {
        self.pos = 0.0;
        self.prev = 0.0;
        self.primed = false;
    }

    /// Feed one input-rate sample, appending any output-rate samples it yields.
    fn push(&mut self, sample: f32, out: &mut Vec<i16>) {
        if self.passthrough {
            out.push(to_i16(sample));
            return;
        }

        if !self.primed {
            self.prev = sample;
            self.primed = true;
            // `pos` is measured relative to the previous input sample at index 0;
            // emit any output samples that fall in [0, 1) before the new sample.
        }

        // Each input sample advances the input timeline by exactly 1.0. Emit
        // every output sample whose position falls in [n-1, n) — i.e. between
        // `prev` (at integer index n-1) and `sample` (at index n).
        // `pos` tracks the absolute output read head in input-sample units,
        // normalized so the current interval is [0, 1).
        while self.pos < 1.0 {
            let frac = self.pos as f32;
            let interp = self.prev + (sample - self.prev) * frac;
            out.push(to_i16(interp));
            self.pos += self.step;
        }
        // Shift into the next interval.
        self.pos -= 1.0;
        self.prev = sample;
    }
}

/// Clamp + convert a normalized f32 sample to i16.
fn to_i16(s: f32) -> i16 {
    let clamped = s.clamp(-1.0, 1.0);
    (clamped * i16::MAX as f32) as i16
}

// ---------------------------------------------------------------------------
// Device wiring (cpal). Isolated so the rest of the module is device-agnostic
// and the pure logic above is unit-testable without hardware.
// ---------------------------------------------------------------------------

/// Open the default input device, downmix to mono in the callback, and push raw
/// mono f32 samples into `raw_tx`. Returns the live stream and its sample rate.
fn open_input_stream(
    gate: Arc<AtomicBool>,
    raw_tx: Sender<f32>,
) -> std::result::Result<(DeviceStream, u32), String> {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| "no default input device".to_string())?;
    let config = device
        .default_input_config()
        .map_err(|e| format!("default input config: {e}"))?;

    let device_rate = config.sample_rate().0;
    let channels = config.channels() as usize;
    let sample_format = config.sample_format();
    let stream_config: cpal::StreamConfig = config.into();

    let err_fn = |err| tracing::warn!(error = %err, "cpal input stream error");

    macro_rules! build {
        ($sample:ty, $to_f32:expr) => {{
            let gate = gate.clone();
            let raw_tx = raw_tx.clone();
            device
                .build_input_stream(
                    &stream_config,
                    move |data: &[$sample], _: &cpal::InputCallbackInfo| {
                        if !gate.load(Ordering::Relaxed) {
                            return;
                        }
                        // Downmix interleaved frames to mono by averaging.
                        for frame in data.chunks(channels) {
                            let mut acc = 0.0f32;
                            for &s in frame {
                                acc += $to_f32(s);
                            }
                            let mono = acc / channels as f32;
                            if raw_tx.send(mono).is_err() {
                                // Consumer gone; nothing useful to do.
                                return;
                            }
                        }
                    },
                    err_fn,
                    None,
                )
                .map_err(|e| format!("build input stream: {e}"))?
        }};
    }

    let stream = match sample_format {
        cpal::SampleFormat::F32 => build!(f32, |s: f32| s),
        cpal::SampleFormat::I16 => {
            build!(i16, |s: i16| s as f32 / i16::MAX as f32)
        }
        cpal::SampleFormat::U16 => {
            build!(u16, |s: u16| (s as f32 / u16::MAX as f32) * 2.0 - 1.0)
        }
        other => {
            return Err(format!("unsupported input sample format: {other:?}"));
        }
    };

    stream
        .play()
        .map_err(|e| format!("start input stream: {e}"))?;

    Ok((DeviceStream { stream }, device_rate))
}

// ---------------------------------------------------------------------------
// Tests: pure resample/frame logic, no device.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn drive(_inner: &mut CaptureInner, tx: &Sender<f32>, samples: &[f32]) {
        for &s in samples {
            tx.send(s).unwrap();
        }
    }

    fn mk_inner(device_rate: u32, opus_rate: u32, frame_ms: u8) -> (CaptureInner, Sender<f32>) {
        let (tx, rx) = channel::<f32>();
        let frame_len = frame_len(opus_rate, frame_ms);
        let inner = CaptureInner {
            gate: Arc::new(AtomicBool::new(true)),
            raw_rx: rx,
            resampler: Resampler::new(device_rate, opus_rate),
            frame_len,
            pending: Vec::new(),
        };
        (inner, tx)
    }

    #[test]
    fn frame_len_matches_spec_defaults() {
        // 20 ms @ 16 kHz = 320 samples.
        assert_eq!(frame_len(16_000, 20), 320);
        // 20 ms @ 48 kHz = 960 samples.
        assert_eq!(frame_len(48_000, 20), 960);
        // 40 ms @ 8 kHz = 320 samples.
        assert_eq!(frame_len(8_000, 40), 320);
    }

    #[test]
    fn passthrough_when_rates_equal_produces_exact_frame() {
        let (mut inner, tx) = mk_inner(16_000, 16_000, 20); // frame_len 320
        assert!(inner.next_frame().is_none(), "no samples yet");

        // Feed exactly one frame's worth.
        let buf: Vec<f32> = (0..320).map(|i| (i as f32 / 320.0) - 0.5).collect();
        drive(&mut inner, &tx, &buf);

        let frame = inner.next_frame().expect("a full frame");
        assert_eq!(frame.samples.len(), 320);
        // No leftover -> next poll is empty.
        assert!(inner.next_frame().is_none());
    }

    #[test]
    fn gate_closed_drops_audio() {
        let (mut inner, tx) = mk_inner(16_000, 16_000, 20);
        inner.gate.store(false, Ordering::SeqCst);
        let buf = vec![0.5f32; 1000];
        drive(&mut inner, &tx, &buf);
        // Drains the channel but keeps nothing.
        assert!(inner.next_frame().is_none());
        assert!(inner.pending.is_empty());
    }

    #[test]
    fn downsample_48k_to_16k_yields_roughly_third() {
        // 48 kHz in, 16 kHz out: 3 input samples per output sample.
        let (mut inner, tx) = mk_inner(48_000, 16_000, 20); // out frame_len 320
        // Feed 960 input samples (= one 20 ms frame at 48 kHz) -> ~320 out.
        let buf: Vec<f32> = (0..960).map(|i| ((i as f32) * 0.001).sin()).collect();
        drive(&mut inner, &tx, &buf);
        let frame = inner.next_frame().expect("downsampled frame");
        assert_eq!(frame.samples.len(), 320);
    }

    #[test]
    fn upsample_8k_to_16k_doubles() {
        // 8 kHz -> 16 kHz: produces ~2 output samples per input sample.
        let (mut inner, tx) = mk_inner(8_000, 16_000, 20); // out frame_len 320
        // 160 input samples (20 ms @ 8 kHz) should produce ~320 output samples.
        let buf: Vec<f32> = (0..160).map(|i| i as f32 / 160.0).collect();
        drive(&mut inner, &tx, &buf);
        let frame = inner.next_frame().expect("upsampled frame");
        assert_eq!(frame.samples.len(), 320);
    }

    #[test]
    fn resampler_reset_clears_phase() {
        let mut r = Resampler::new(48_000, 16_000);
        let mut out = Vec::new();
        r.push(0.5, &mut out);
        r.push(-0.5, &mut out);
        r.reset();
        assert_eq!(r.pos, 0.0);
        assert!(!r.primed);
    }

    #[test]
    fn to_i16_clamps() {
        assert_eq!(to_i16(2.0), i16::MAX);
        assert_eq!(to_i16(-2.0), -i16::MAX); // symmetric clamp
        assert_eq!(to_i16(0.0), 0);
    }
}
