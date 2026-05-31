//! Speaker playback: cpal output + jitter buffer for smooth playout
//! (SPEC §5.4, ARCHITECTURE "playback.rs", ADR-0003).
//!
//! Decoded PCM frames arrive over the network at the mercy of Tor latency
//! jitter. We buffer them in an ordered jitter buffer keyed by arrival and only
//! begin handing samples to the device once a tunable *lead* has accumulated;
//! thereafter we stream smoothly, substituting silence on underrun rather than
//! glitching or blocking the audio thread.
//!
//! The cpal output callback runs on an OS audio thread and pulls samples from a
//! lock-free-ish shared buffer ([`JitterBuffer`] behind a [`Mutex`]); the lock
//! is held only for the microseconds needed to copy out a callback's worth of
//! samples. The device wiring is isolated in [`open_output_stream`] so the
//! jitter-buffer logic is unit-testable without a speaker.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::audio::{AudioConfig, PcmFrame};
use crate::error::{Error, Result};

/// Linear makeup gain applied to decoded audio before playout.
///
/// The capture→Opus→playout path is unity-gain end to end, so received audio
/// plays back at the raw microphone level — typically −20…−30 dBFS for speech,
/// with no AGC like phones/Zoom apply. That sounds *extremely quiet*. This
/// constant lifts playout to a comfortable level (≈ +12 dB). It is applied with
/// per-sample saturation so the occasional loud passage clips hard rather than
/// wrapping around. Lower it toward `1.0` if your input is already hot; this is
/// a deliberately simple knob (a future config/CLI option can supersede it).
const PLAYBACK_GAIN: f32 = 4.0;

/// Scale `samples` in place by `gain`, saturating at the i16 range so a boosted
/// loud sample clips instead of wrapping. A gain of ~1.0 is a no-op fast path.
fn apply_gain(samples: &mut [i16], gain: f32) {
    if (gain - 1.0).abs() < f32::EPSILON {
        return;
    }
    for s in samples {
        let scaled = (*s as f32 * gain).round();
        *s = scaled.clamp(i16::MIN as f32, i16::MAX as f32) as i16;
    }
}

/// Owns the cpal output stream and a small jitter buffer; playout begins once a
/// tunable lead is buffered, then streams smoothly (SPEC §5.4).
pub struct Playback {
    /// Effective audio config.
    _cfg: AudioConfig,
    /// Lead to buffer before playout starts (from `Config::jitter_lead`).
    _lead: Duration,
    /// Shared jitter buffer pulled by the device callback and pushed by `enqueue`.
    buffer: Arc<Mutex<JitterBuffer>>,
    /// The live cpal output stream. Dropping it stops playout. `None` only if a
    /// device could not be opened (then `enqueue` still accepts frames but they
    /// are never consumed — kept for headless symmetry / tests).
    _device_stream: Option<DeviceStream>,
}

/// Opaque holder for the platform output stream.
struct DeviceStream {
    #[allow(dead_code)]
    stream: cpal::Stream,
}

impl Playback {
    /// Open the default output device with the given jitter lead.
    pub fn open(cfg: AudioConfig, lead: Duration) -> Result<Self> {
        let opus_rate = cfg.opus.sample_rate;
        let lead_samples = duration_to_samples(lead, opus_rate);

        let buffer = Arc::new(Mutex::new(JitterBuffer::new(lead_samples)));

        let device_stream = open_output_stream(cfg, buffer.clone())
            .map_err(|e| Error::Audio(format!("failed to open output device: {e}")))?;

        Ok(Playback {
            _cfg: cfg,
            _lead: lead,
            buffer,
            _device_stream: Some(device_stream),
        })
    }

    /// Push a decoded PCM frame into the jitter buffer.
    ///
    /// Returns an error only if the shared buffer lock is poisoned (a panic in
    /// the audio callback) — every normal enqueue succeeds; the buffer caps its
    /// own depth and drops the oldest audio on overflow rather than rejecting.
    pub fn enqueue(&self, pcm: PcmFrame) -> Result<()> {
        // Apply makeup gain before buffering so playout is at a usable level.
        // Done outside the lock to keep the critical section minimal.
        let mut samples = pcm.samples;
        apply_gain(&mut samples, PLAYBACK_GAIN);

        let mut buf = self
            .buffer
            .lock()
            .map_err(|_| Error::Audio("playback buffer lock poisoned".into()))?;
        buf.push(samples);
        Ok(())
    }
}

/// Convert a duration to a sample count at `rate`.
fn duration_to_samples(d: Duration, rate: u32) -> usize {
    // d.as_secs_f64() * rate, guarded against absurd values.
    (d.as_secs_f64() * rate as f64).round() as usize
}

/// Ordered, depth-capped jitter buffer.
///
/// Frames are appended in arrival order (proto delivers them in sequence; the
/// transport is a single ordered stream, so we do not need to reorder by an
/// explicit sequence number here — ordering is preserved by the channel). The
/// buffer holds samples in a flat ring of mono i16 and gates the start of
/// playout until `lead_samples` have accumulated.
struct JitterBuffer {
    /// Pending mono samples, oldest first.
    samples: VecDeque<i16>,
    /// Samples to accumulate before playout begins.
    lead_samples: usize,
    /// Whether playout has started (lead reached at least once).
    playing: bool,
    /// Hard cap on buffered samples; beyond this we drop the oldest to bound
    /// latency growth if the producer outruns the consumer.
    max_samples: usize,
}

impl JitterBuffer {
    fn new(lead_samples: usize) -> Self {
        // Cap at 4x the lead, but never so small that a single just-pushed frame
        // would be truncated before it can be played out. A small absolute floor
        // (`MIN_CAP`) covers the zero-/tiny-lead case where `4 * lead` would be
        // 0 or 1, while a large lead still scales the cap up to honor it.
        const MIN_CAP: usize = 32;
        let max_samples = lead_samples
            .saturating_mul(4)
            .max(lead_samples + 1)
            .max(MIN_CAP);
        JitterBuffer {
            samples: VecDeque::new(),
            lead_samples,
            playing: false,
            max_samples,
        }
    }

    /// Append a decoded frame's samples.
    fn push(&mut self, frame: Vec<i16>) {
        self.samples.extend(frame);
        // Bound latency: if we have run away past the cap, drop the oldest.
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    /// Fill `out` with the next `out.len()` samples for the device.
    ///
    /// Returns the number of *real* (non-silence) samples written. Before the
    /// lead is reached, writes silence (returns 0) so the device has something
    /// to play without draining the buffer prematurely. After playout starts,
    /// drains buffered audio and pads any shortfall with silence (underrun),
    /// re-arming the lead gate so a sustained underrun re-buffers before
    /// resuming (avoids choppy stutter).
    fn fill(&mut self, out: &mut [i16]) -> usize {
        // Gate: do not start until the lead is buffered.
        if !self.playing {
            if self.samples.len() >= self.lead_samples && self.lead_samples > 0 {
                self.playing = true;
            } else if self.lead_samples == 0 && !self.samples.is_empty() {
                // Zero lead: start as soon as there is anything.
                self.playing = true;
            } else {
                for s in out.iter_mut() {
                    *s = 0;
                }
                return 0;
            }
        }

        let mut written = 0;
        for slot in out.iter_mut() {
            match self.samples.pop_front() {
                Some(s) => {
                    *slot = s;
                    written += 1;
                }
                None => {
                    *slot = 0;
                }
            }
        }

        // Underrun: buffer fully drained mid-callback. Re-arm the lead gate so
        // we re-buffer before resuming smooth playout.
        if written < out.len() && self.lead_samples > 0 {
            self.playing = false;
        }

        written
    }

    /// Total buffered samples (test/inspection helper).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.samples.len()
    }
}

// ---------------------------------------------------------------------------
// Device wiring (cpal). Isolated so the jitter-buffer logic above is testable
// without a speaker.
// ---------------------------------------------------------------------------

/// Open the default output device and drive it from the shared jitter buffer.
fn open_output_stream(
    cfg: AudioConfig,
    buffer: Arc<Mutex<JitterBuffer>>,
) -> std::result::Result<DeviceStream, String> {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or_else(|| "no default output device".to_string())?;
    let supported = device
        .default_output_config()
        .map_err(|e| format!("default output config: {e}"))?;

    let out_channels = supported.channels() as usize;
    let sample_format = supported.sample_format();
    // We mix at the opus rate; if the device disagrees, request the opus rate
    // explicitly. cpal will error if the device cannot do it, which surfaces as
    // an Audio error rather than silently playing at the wrong pitch.
    let stream_config = cpal::StreamConfig {
        channels: supported.channels(),
        sample_rate: cpal::SampleRate(cfg.opus.sample_rate),
        buffer_size: cpal::BufferSize::Default,
    };

    let err_fn = |err| tracing::warn!(error = %err, "cpal output stream error");

    // Pull one mono sample per output frame from the jitter buffer and fan it
    // out across all output channels.
    macro_rules! build {
        ($sample:ty, $from_i16:expr) => {{
            let buffer = buffer.clone();
            device
                .build_output_stream(
                    &stream_config,
                    move |data: &mut [$sample], _: &cpal::OutputCallbackInfo| {
                        let frames = data.len() / out_channels.max(1);
                        let mut mono = vec![0i16; frames];
                        if let Ok(mut buf) = buffer.lock() {
                            buf.fill(&mut mono);
                        }
                        for (i, frame) in data.chunks_mut(out_channels.max(1)).enumerate() {
                            let v = $from_i16(mono[i]);
                            for ch in frame.iter_mut() {
                                *ch = v;
                            }
                        }
                    },
                    err_fn,
                    None,
                )
                .map_err(|e| format!("build output stream: {e}"))?
        }};
    }

    let stream = match sample_format {
        cpal::SampleFormat::F32 => build!(f32, |s: i16| s as f32 / i16::MAX as f32),
        cpal::SampleFormat::I16 => build!(i16, |s: i16| s),
        cpal::SampleFormat::U16 => {
            build!(u16, |s: i16| (s as i32 + 32768) as u16)
        }
        other => return Err(format!("unsupported output sample format: {other:?}")),
    };

    stream
        .play()
        .map_err(|e| format!("start output stream: {e}"))?;

    Ok(DeviceStream { stream })
}

// ---------------------------------------------------------------------------
// Tests: pure jitter-buffer logic, no device.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_to_samples_matches_rate() {
        // 250 ms @ 16 kHz = 4000 samples.
        assert_eq!(
            duration_to_samples(Duration::from_millis(250), 16_000),
            4000
        );
        // 20 ms @ 48 kHz = 960 samples.
        assert_eq!(duration_to_samples(Duration::from_millis(20), 48_000), 960);
        assert_eq!(duration_to_samples(Duration::from_millis(0), 16_000), 0);
    }

    #[test]
    fn playout_waits_for_lead() {
        let mut jb = JitterBuffer::new(100); // need 100 samples before playout
        jb.push(vec![1; 50]); // below lead

        let mut out = [9i16; 32];
        let written = jb.fill(&mut out);
        assert_eq!(written, 0, "must not play before lead is reached");
        assert!(out.iter().all(|&s| s == 0), "pre-lead output is silence");
        assert!(!jb.playing);
        // Samples were preserved (not drained while gated).
        assert_eq!(jb.len(), 50);
    }

    #[test]
    fn playout_starts_once_lead_reached_and_drains_in_order() {
        let mut jb = JitterBuffer::new(4);
        // Push two frames; ordering must be preserved across frame boundaries.
        jb.push(vec![1, 2, 3, 4]);
        jb.push(vec![5, 6, 7, 8]);

        let mut out = [0i16; 6];
        let written = jb.fill(&mut out);
        assert_eq!(written, 6);
        assert_eq!(out, [1, 2, 3, 4, 5, 6], "FIFO order preserved");
        assert!(jb.playing);
        assert_eq!(jb.len(), 2, "remaining buffered");
    }

    #[test]
    fn underrun_pads_silence_and_rearms_lead() {
        let mut jb = JitterBuffer::new(2);
        jb.push(vec![10, 20, 30]); // reaches lead of 2

        let mut out = [0i16; 5];
        let written = jb.fill(&mut out);
        assert_eq!(written, 3, "only 3 real samples available");
        assert_eq!(out, [10, 20, 30, 0, 0], "shortfall padded with silence");
        // Underrun re-arms the gate: must re-buffer the lead before resuming.
        assert!(!jb.playing, "underrun re-arms lead gate");

        // A subsequent fill with insufficient buffer stays silent.
        jb.push(vec![40]); // 1 sample, below lead of 2
        let mut out2 = [7i16; 4];
        let w2 = jb.fill(&mut out2);
        assert_eq!(w2, 0);
        assert!(out2.iter().all(|&s| s == 0));
    }

    #[test]
    fn zero_lead_plays_immediately() {
        let mut jb = JitterBuffer::new(0);
        let mut out = [0i16; 3];
        // Empty + zero lead -> silence, not yet playing.
        assert_eq!(jb.fill(&mut out), 0);

        jb.push(vec![1, 2]);
        let w = jb.fill(&mut out);
        assert_eq!(w, 2);
        assert_eq!(out, [1, 2, 0]);
    }

    #[test]
    fn apply_gain_scales_and_saturates() {
        // Unity gain is an exact no-op.
        let mut s = vec![100, -100, 0, 32767, -32768];
        apply_gain(&mut s, 1.0);
        assert_eq!(s, vec![100, -100, 0, 32767, -32768]);

        // 4x boost scales quiet samples and saturates loud ones (no wraparound).
        let mut s = vec![100, -100, 10_000, -10_000];
        apply_gain(&mut s, 4.0);
        assert_eq!(s, vec![400, -400, i16::MAX, i16::MIN]);

        // The default playout gain is a real boost (> unity).
        assert!(PLAYBACK_GAIN > 1.0, "playout must apply makeup gain");
    }

    #[test]
    fn buffer_is_depth_capped() {
        let mut jb = JitterBuffer::new(10); // max = 40
        // Push way more than the cap.
        jb.push(vec![0i16; 1000]);
        assert!(jb.len() <= jb.max_samples, "depth cap bounds latency");
        // Newest samples are retained (oldest dropped).
        jb.push((0..100).collect());
        assert!(jb.len() <= jb.max_samples);
    }
}
