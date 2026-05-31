//! Opus encode/decode wrappers around `audiopus` (SPEC §5.4, ADR-0007).
//!
//! Thin, low-latency wrappers over libopus (via [`audiopus`]) tuned for
//! encrypted half-duplex voice over a Tor onion stream:
//!
//! * Mono. There is no stereo voice path in this product.
//! * 16 kHz wideband by default; 8 kHz narrowband supported for constrained
//!   links. Both are driven by [`OpusParams`] from the peer's HELLO.
//! * ~24 kbps VBR — the sweet spot for intelligible speech that still fits
//!   comfortably inside one Tor cell's payload per frame (~3 KB/s aggregate).
//! * 20–40 ms frames. Longer frames amortise per-packet overhead (frame header
//!   + AEAD nonce + Tor cell framing) at the cost of a little extra
//!     mouth-to-ear latency; the SPEC §3 budget allows up to 40 ms here.
//!
//! libopus only accepts a fixed set of frame durations (2.5/5/10/20/40/60 ms),
//! and the number of PCM samples per frame is therefore
//! `sample_rate_hz * frame_ms / 1000` (mono ⇒ samples == samples-per-channel).
//! We validate [`OpusParams`] against the supported surface at construction
//! time so a bad config fails loudly rather than producing garbage frames.

use audiopus::{
    Application, Bitrate, Channels, SampleRate,
    coder::{Decoder as RawDecoder, Encoder as RawEncoder},
};

use crate::audio::{OpusFrame, PcmFrame};
use crate::config::OpusParams;
use crate::error::{Error, Result};

/// Maximum bytes an encoded Opus frame can occupy.
///
/// libopus documents 4000 bytes as the largest packet it will ever emit for a
/// single frame; we size the encode scratch buffer to that so `encode` never
/// has to grow or fail for want of space. In practice a 24 kbps / 20 ms VBR
/// speech frame is only ~50–80 bytes, so this is pure headroom.
const MAX_PACKET_BYTES: usize = 4000;

/// Translate a [`OpusParams`] sample rate into the audiopus enum, rejecting
/// rates libopus does not accept. We only ever want narrowband (8 kHz) or
/// wideband (16 kHz) for voice, but accept all the standard Opus rates so a
/// future config can widen without touching this code.
fn sample_rate(params: &OpusParams) -> Result<SampleRate> {
    match params.sample_rate {
        8_000 => Ok(SampleRate::Hz8000),
        12_000 => Ok(SampleRate::Hz12000),
        16_000 => Ok(SampleRate::Hz16000),
        24_000 => Ok(SampleRate::Hz24000),
        48_000 => Ok(SampleRate::Hz48000),
        other => Err(Error::Audio(format!(
            "unsupported opus sample rate {other} Hz (allowed: 8000/12000/16000/24000/48000)"
        ))),
    }
}

/// Translate a channel count into the audiopus enum. Only mono and stereo
/// exist; this product only ever uses mono, but we map both for completeness.
fn channels(params: &OpusParams) -> Result<Channels> {
    match params.channels {
        1 => Ok(Channels::Mono),
        2 => Ok(Channels::Stereo),
        other => Err(Error::Audio(format!(
            "unsupported opus channel count {other} (allowed: 1 mono, 2 stereo)"
        ))),
    }
}

/// Number of PCM samples in one frame for these params, validating the frame
/// duration against the durations libopus accepts.
///
/// Returned count is the *total* interleaved sample count (samples-per-channel
/// × channels). For our mono default that is just samples-per-channel.
fn frame_samples(params: &OpusParams) -> Result<usize> {
    // Opus permits 2.5/5/10/20/40/60 ms. SPEC §5.4 calls for 20–40 ms; we accept
    // the speech-grade subset and reject anything that would not divide cleanly
    // into an integer sample count.
    let valid = matches!(params.frame_ms, 10 | 20 | 40 | 60);
    if !valid {
        return Err(Error::Audio(format!(
            "unsupported opus frame duration {} ms (allowed: 10/20/40/60; SPEC default 20)",
            params.frame_ms
        )));
    }
    let per_channel = (params.sample_rate as usize * params.frame_ms as usize) / 1000;
    Ok(per_channel * params.channels as usize)
}

/// Opus encoder wrapper. Configured from [`OpusParams`]; encodes mono PCM frames.
pub struct OpusEncoder {
    /// The underlying libopus encoder.
    inner: RawEncoder,
    /// Codec parameters (rate, channels, bitrate, frame size).
    params: OpusParams,
    /// Expected interleaved sample count per [`PcmFrame`], cached from `params`.
    frame_samples: usize,
}

impl OpusEncoder {
    /// Build an encoder for the given parameters (sets bitrate, VBR).
    ///
    /// Uses the VOIP application profile (libopus tunes its psychoacoustic model
    /// for speech), enables unconstrained VBR (lets the encoder spend extra bits
    /// on hard frames while the long-run average tracks the target), and sets
    /// the target bitrate from `params.bitrate`.
    pub fn new(params: OpusParams) -> Result<Self> {
        let sr = sample_rate(&params)?;
        let ch = channels(&params)?;
        let frame_samples = frame_samples(&params)?;

        let mut inner = RawEncoder::new(sr, ch, Application::Voip).map_err(opus_err)?;
        inner
            .set_bitrate(Bitrate::BitsPerSecond(params.bitrate as i32))
            .map_err(opus_err)?;
        inner.set_vbr(true).map_err(opus_err)?;
        // Unconstrained VBR keeps speech crisp on transients; the average still
        // tracks `params.bitrate`.
        inner.set_vbr_constraint(false).map_err(opus_err)?;

        Ok(OpusEncoder {
            inner,
            params,
            frame_samples,
        })
    }

    /// Encode one PCM frame into a compressed [`OpusFrame`].
    ///
    /// `pcm.samples` must contain exactly one frame's worth of interleaved i16
    /// samples (mono ⇒ a flat sample list); the count is fixed by the params
    /// this encoder was built with. A mismatch is a programmer/capture error and
    /// returns [`Error::Audio`] rather than corrupting the stream.
    pub fn encode(&mut self, pcm: &PcmFrame) -> Result<OpusFrame> {
        if pcm.samples.len() != self.frame_samples {
            return Err(Error::Audio(format!(
                "pcm frame length mismatch: got {} samples, expected {} ({} Hz, {} ch, {} ms)",
                pcm.samples.len(),
                self.frame_samples,
                self.params.sample_rate,
                self.params.channels,
                self.params.frame_ms
            )));
        }
        let mut out = vec![0u8; MAX_PACKET_BYTES];
        let n = self
            .inner
            .encode(&pcm.samples, &mut out)
            .map_err(opus_err)?;
        out.truncate(n);
        Ok(OpusFrame { data: out })
    }
}

/// Opus decoder wrapper. Configured from the peer's [`OpusParams`].
pub struct OpusDecoder {
    /// The underlying libopus decoder.
    inner: RawDecoder,
    /// Codec parameters mirrored from the peer's HELLO.
    params: OpusParams,
    /// Interleaved samples produced per decoded frame, cached from `params`.
    frame_samples: usize,
}

impl OpusDecoder {
    /// Build a decoder for the given parameters.
    pub fn new(params: OpusParams) -> Result<Self> {
        let sr = sample_rate(&params)?;
        let ch = channels(&params)?;
        let frame_samples = frame_samples(&params)?;

        let inner = RawDecoder::new(sr, ch).map_err(opus_err)?;
        Ok(OpusDecoder {
            inner,
            params,
            frame_samples,
        })
    }

    /// Decode one [`OpusFrame`] back into PCM.
    ///
    /// Allocates an output buffer sized for one frame's worth of samples (the
    /// fixed frame size negotiated for this call) and truncates to the count
    /// libopus actually wrote. `false` = no in-band FEC; we feed the real
    /// packet.
    pub fn decode(&mut self, frame: &OpusFrame) -> Result<PcmFrame> {
        let mut out = vec![0i16; self.frame_samples];
        let n = self
            .inner
            .decode(Some(&frame.data), &mut out, false)
            .map_err(opus_err)?;
        out.truncate(n * self.params.channels as usize);
        Ok(PcmFrame { samples: out })
    }
}

/// Map an [`audiopus::Error`] into the crate's [`Error::Audio`] variant with a
/// descriptive message. (The crate error type is opaque `String`-backed for the
/// audio domain; we preserve libopus's own message.)
fn opus_err(e: audiopus::Error) -> Error {
    Error::Audio(format!("opus codec error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::PI;

    /// Build a mono sine tone of `samples` i16 samples at `rate` Hz.
    fn sine(samples: usize, rate: u32, freq_hz: f32) -> PcmFrame {
        let s = (0..samples)
            .map(|i| {
                let t = i as f32 / rate as f32;
                ((2.0 * PI * freq_hz * t).sin() * 16_000.0) as i16
            })
            .collect();
        PcmFrame { samples: s }
    }

    fn params(sample_rate: u32, frame_ms: u8) -> OpusParams {
        OpusParams {
            sample_rate,
            channels: 1,
            bitrate: 24_000,
            frame_ms,
        }
    }

    #[test]
    fn frame_samples_math() {
        // 16 kHz wideband
        assert_eq!(frame_samples(&params(16_000, 20)).unwrap(), 320);
        assert_eq!(frame_samples(&params(16_000, 40)).unwrap(), 640);
        // 8 kHz narrowband
        assert_eq!(frame_samples(&params(8_000, 20)).unwrap(), 160);
        assert_eq!(frame_samples(&params(8_000, 40)).unwrap(), 320);
    }

    #[test]
    fn rejects_bad_params() {
        assert!(sample_rate(&params(44_100, 20)).is_err());
        assert!(frame_samples(&params(16_000, 33)).is_err());
        let mut bad = params(16_000, 20);
        bad.channels = 7;
        assert!(channels(&bad).is_err());
    }

    #[test]
    fn default_params_are_supported() {
        // The frozen config default (16k/mono/24kbps/20ms) must build cleanly.
        let p = OpusParams::default();
        OpusEncoder::new(p).unwrap();
        OpusDecoder::new(p).unwrap();
        assert_eq!(frame_samples(&p).unwrap(), 320);
    }

    #[test]
    fn rejects_wrong_pcm_length() {
        let p = OpusParams::default();
        let mut enc = OpusEncoder::new(p).unwrap();
        let bad = PcmFrame {
            samples: vec![0i16; frame_samples(&p).unwrap() + 1],
        };
        match enc.encode(&bad) {
            Err(Error::Audio(_)) => {}
            other => panic!("expected Error::Audio for bad pcm length, got {other:?}"),
        }
    }

    /// Round-trip every supported (rate, frame) speech combination and assert
    /// the shapes line up: encode a sine frame, confirm the packet is non-empty
    /// and within the libopus ceiling, decode it, and confirm the sample count
    /// matches the input frame.
    #[test]
    fn round_trip_all_speech_configs() {
        let rates = [8_000u32, 16_000u32];
        let frames = [20u8, 40u8];

        for &rate in &rates {
            for &frame_ms in &frames {
                let p = params(rate, frame_ms);
                let mut enc = OpusEncoder::new(p).unwrap();
                let mut dec = OpusDecoder::new(p).unwrap();

                let n = frame_samples(&p).unwrap();
                let pcm = sine(n, rate, 440.0);

                let opus = enc.encode(&pcm).unwrap();
                assert!(
                    !opus.data.is_empty() && opus.data.len() <= MAX_PACKET_BYTES,
                    "{rate}Hz/{frame_ms}ms: packet len {} out of range",
                    opus.data.len()
                );

                let decoded = dec.decode(&opus).unwrap();
                assert_eq!(
                    decoded.samples.len(),
                    n,
                    "{rate}Hz/{frame_ms}ms: decoded sample count mismatch"
                );
            }
        }
    }

    /// A continuous tone is highly compressible; confirm 24 kbps VBR keeps the
    /// default-config frame well under one Tor cell's payload (~498 bytes),
    /// which is the whole point of choosing this bitrate (SPEC §5.4).
    #[test]
    fn frame_fits_in_a_tor_cell() {
        let p = OpusParams::default();
        let mut enc = OpusEncoder::new(p).unwrap();
        let pcm = sine(frame_samples(&p).unwrap(), p.sample_rate, 300.0);
        let opus = enc.encode(&pcm).unwrap();
        assert!(
            opus.data.len() < 498,
            "20ms/24kbps frame unexpectedly large: {} bytes",
            opus.data.len()
        );
    }

    /// Round-trip output of a tone should itself carry real energy, not silence;
    /// guards against a mute/zeroed decode path. Encode several frames first so
    /// the encoder leaves its initial ramp-up and produces a representative
    /// steady-state frame.
    #[test]
    fn decoded_signal_has_energy() {
        let p = OpusParams::default();
        let mut enc = OpusEncoder::new(p).unwrap();
        let mut dec = OpusDecoder::new(p).unwrap();

        let mut last = PcmFrame { samples: vec![] };
        for _ in 0..5 {
            let pcm = sine(frame_samples(&p).unwrap(), p.sample_rate, 440.0);
            let opus = enc.encode(&pcm).unwrap();
            last = dec.decode(&opus).unwrap();
        }
        let energy: f64 = last.samples.iter().map(|&s| (s as f64).powi(2)).sum();
        assert!(energy > 0.0, "decoded steady-state frame was silent");
    }
}
