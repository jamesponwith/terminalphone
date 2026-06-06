//! Voice changer: in-process DSP applied to outgoing PCM before Opus encode
//! (tp-5xj, M3 feature parity with v1's sox effects).
//!
//! Effects run per-frame on the captured i16 PCM, just before encoding. To stay
//! click-free at frame boundaries, any oscillator/filter state is carried across
//! frames in a [`VoiceState`] owned by the capture path. Every effect clamps its
//! output to [-1.0, 1.0] so a hot effect never blows up the Opus encoder.
//!
//! ## Scope
//!
//! Only effects that are correct and deterministic *per frame* are implemented.
//! True pitch shifting (v1's "deep"/"high") needs resampling / a phase vocoder,
//! which cannot be done correctly frame-by-frame without artefacts, so it is
//! deliberately out of scope and omitted. The supported effects are
//! [`VoiceEffect::Robot`], [`VoiceEffect::Tremolo`], [`VoiceEffect::Overdrive`],
//! [`VoiceEffect::Telephone`], and [`VoiceEffect::Whisper`].

use serde::{Deserialize, Serialize};

/// A selectable outgoing-voice effect. [`VoiceEffect::Off`] is the default and a
/// true no-op (the capture path skips DSP entirely).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceEffect {
    /// No effect; PCM passes through untouched.
    #[default]
    Off,
    /// Ring modulation against a fixed carrier sine — a classic "robot" timbre.
    Robot,
    /// Low-frequency amplitude modulation (a wobbling volume).
    Tremolo,
    /// Soft-clip (tanh) distortion with input drive — a gritty overdrive.
    Overdrive,
    /// Band-limited "telephone" voice via cascaded one-pole high/low-pass filters.
    Telephone,
    /// Whisper: strip the low end and replace the signal with amplitude-shaped
    /// noise, removing voiced pitch while tracking the speech envelope.
    Whisper,
}

impl VoiceEffect {
    /// Whether this effect changes the signal (i.e. is not [`VoiceEffect::Off`]).
    pub fn is_active(self) -> bool {
        self != VoiceEffect::Off
    }
}

/// Carrier frequency of the ring-modulation "robot" effect, in Hz.
const ROBOT_CARRIER_HZ: f64 = 80.0;
/// Modulation frequency of the tremolo effect, in Hz.
const TREMOLO_HZ: f64 = 6.0;
/// Tremolo modulation depth in [0, 1]: fraction of amplitude swept.
const TREMOLO_DEPTH: f32 = 0.7;
/// Input drive applied before the overdrive soft-clip (higher = more grit).
const OVERDRIVE_DRIVE: f32 = 4.0;
/// Telephone passband low corner (Hz): cut energy below this.
const TELEPHONE_LOW_HZ: f64 = 300.0;
/// Telephone passband high corner (Hz): cut energy above this.
const TELEPHONE_HIGH_HZ: f64 = 3400.0;
/// Smoothing pole for the whisper envelope follower in [0, 1) (closer to 1 =
/// slower envelope).
const WHISPER_ENV_POLE: f32 = 0.98;

/// Cross-frame DSP state so per-frame modulation/filtering stays continuous.
///
/// One instance is owned by the capture path for the life of an utterance; the
/// oscillator phase and filter memories persist across [`apply`] calls so there
/// are no discontinuities (clicks) at frame boundaries.
#[derive(Debug, Default, Clone)]
pub struct VoiceState {
    /// Oscillator phase in radians, shared by the periodic effects (robot,
    /// tremolo). Kept in `f64` to resist long-run drift.
    phase: f64,
    /// One-pole high-pass memory (previous input + output) for telephone/whisper.
    hp_prev_in: f32,
    hp_prev_out: f32,
    /// One-pole low-pass memory (previous output) for telephone.
    lp_prev_out: f32,
    /// Whisper amplitude envelope follower.
    whisper_env: f32,
    /// Deterministic PRNG state for whisper noise (seeded lazily on first use).
    rng: u64,
}

impl VoiceState {
    /// Fresh state with all oscillators/filters zeroed.
    pub fn new() -> Self {
        VoiceState::default()
    }
}

/// Apply `effect` to one frame of f32 PCM in-place, advancing `state` so the
/// next frame continues seamlessly.
///
/// `samples` are normalized PCM in [-1.0, 1.0]; `sample_rate` is the PCM rate in
/// Hz. [`VoiceEffect::Off`] returns immediately (zero overhead). Output is always
/// clamped to [-1.0, 1.0].
pub fn apply(effect: VoiceEffect, samples: &mut [f32], sample_rate: u32, state: &mut VoiceState) {
    if !effect.is_active() || samples.is_empty() {
        return;
    }
    let sr = (sample_rate.max(1)) as f64;
    match effect {
        VoiceEffect::Off => {}
        VoiceEffect::Robot => robot(samples, sr, state),
        VoiceEffect::Tremolo => tremolo(samples, sr, state),
        VoiceEffect::Overdrive => overdrive(samples),
        VoiceEffect::Telephone => telephone(samples, sr, state),
        VoiceEffect::Whisper => whisper(samples, sr, state),
    }
    for s in samples.iter_mut() {
        *s = clamp_unit(*s);
    }
}

/// Convenience wrapper that converts an i16 frame to f32, runs [`apply`], and
/// writes the result back as clamped i16. This is the form the capture path uses
/// (its PCM is i16). A no-op effect leaves `samples` bit-for-bit unchanged.
pub fn apply_i16(
    effect: VoiceEffect,
    samples: &mut [i16],
    sample_rate: u32,
    state: &mut VoiceState,
) {
    if !effect.is_active() || samples.is_empty() {
        return;
    }
    let mut buf: Vec<f32> = samples
        .iter()
        .map(|&s| s as f32 / i16::MAX as f32)
        .collect();
    apply(effect, &mut buf, sample_rate, state);
    for (dst, &src) in samples.iter_mut().zip(buf.iter()) {
        *dst = (clamp_unit(src) * i16::MAX as f32) as i16;
    }
}

/// Clamp a sample to the normalized PCM range, mapping NaN to 0.0.
fn clamp_unit(s: f32) -> f32 {
    if s.is_nan() { 0.0 } else { s.clamp(-1.0, 1.0) }
}

/// Ring-modulate against a fixed carrier sine, advancing the shared phase.
fn robot(samples: &mut [f32], sr: f64, state: &mut VoiceState) {
    let dphase = 2.0 * std::f64::consts::PI * ROBOT_CARRIER_HZ / sr;
    for s in samples.iter_mut() {
        let carrier = state.phase.sin() as f32;
        *s *= carrier;
        state.phase = (state.phase + dphase).rem_euclid(2.0 * std::f64::consts::PI);
    }
}

/// Low-frequency amplitude modulation (tremolo), advancing the shared phase.
fn tremolo(samples: &mut [f32], sr: f64, state: &mut VoiceState) {
    let dphase = 2.0 * std::f64::consts::PI * TREMOLO_HZ / sr;
    let depth = TREMOLO_DEPTH;
    for s in samples.iter_mut() {
        // Unipolar LFO in [1-depth, 1]: never inverts, just dips the gain.
        let lfo = 1.0 - depth * (0.5 - 0.5 * state.phase.sin() as f32);
        *s *= lfo;
        state.phase = (state.phase + dphase).rem_euclid(2.0 * std::f64::consts::PI);
    }
}

/// Soft-clip (tanh) distortion. Stateless; drive then tanh keeps output bounded.
fn overdrive(samples: &mut [f32]) {
    for s in samples.iter_mut() {
        *s = (*s * OVERDRIVE_DRIVE).tanh();
    }
}

/// One-pole low-pass smoothing coefficient for a given corner frequency.
fn lp_alpha(corner_hz: f64, sr: f64) -> f32 {
    let dt = 1.0 / sr;
    let rc = 1.0 / (2.0 * std::f64::consts::PI * corner_hz);
    (dt / (rc + dt)) as f32
}

/// One-pole high-pass coefficient for a given corner frequency.
fn hp_alpha(corner_hz: f64, sr: f64) -> f32 {
    let dt = 1.0 / sr;
    let rc = 1.0 / (2.0 * std::f64::consts::PI * corner_hz);
    (rc / (rc + dt)) as f32
}

/// Band-limit to a telephone-like passband via a one-pole high-pass followed by
/// a one-pole low-pass, both carrying state across frames. Stable by
/// construction (coefficients in (0,1)).
fn telephone(samples: &mut [f32], sr: f64, state: &mut VoiceState) {
    let a_hp = hp_alpha(TELEPHONE_LOW_HZ, sr);
    let a_lp = lp_alpha(TELEPHONE_HIGH_HZ.min(sr / 2.0 - 1.0), sr);
    for s in samples.iter_mut() {
        let x = *s;
        // High-pass: y = a*(y_prev + x - x_prev).
        let hp = a_hp * (state.hp_prev_out + x - state.hp_prev_in);
        state.hp_prev_in = x;
        state.hp_prev_out = hp;
        // Low-pass: y += a*(x - y).
        state.lp_prev_out += a_lp * (hp - state.lp_prev_out);
        *s = state.lp_prev_out;
    }
}

/// Advance an xorshift64* PRNG and return a sample in [-1.0, 1.0].
fn next_noise(state: &mut VoiceState) -> f32 {
    if state.rng == 0 {
        // Lazy non-zero seed; fixed so the effect is deterministic per run.
        state.rng = 0x9E37_79B9_7F4A_7C15;
    }
    let mut x = state.rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state.rng = x;
    let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
    // Map the top 24 bits to [-1, 1).
    ((v >> 40) as f32 / (1u32 << 23) as f32) - 1.0
}

/// Whisper: high-pass the input to remove the low end, follow its amplitude
/// envelope, and emit noise shaped by that envelope. Removes voiced pitch while
/// preserving intelligible speech rhythm.
fn whisper(samples: &mut [f32], sr: f64, state: &mut VoiceState) {
    let a_hp = hp_alpha(TELEPHONE_LOW_HZ, sr);
    for s in samples.iter_mut() {
        let x = *s;
        let hp = a_hp * (state.hp_prev_out + x - state.hp_prev_in);
        state.hp_prev_in = x;
        state.hp_prev_out = hp;
        // Envelope follower on the rectified high-passed signal.
        let rect = hp.abs();
        state.whisper_env = WHISPER_ENV_POLE * state.whisper_env + (1.0 - WHISPER_ENV_POLE) * rect;
        // Shaped noise; a small gain compensates for noise being lower-energy.
        *s = next_noise(state) * state.whisper_env * 1.5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SR: u32 = 16_000;

    /// One frame of a constant DC-ish tone for modulation tests.
    fn constant(n: usize, v: f32) -> Vec<f32> {
        vec![v; n]
    }

    /// One frame of a sine tone.
    fn tone(n: usize, freq: f32, amp: f32) -> Vec<f32> {
        (0..n)
            .map(|i| {
                let t = i as f32 / SR as f32;
                (2.0 * std::f32::consts::PI * freq * t).sin() * amp
            })
            .collect()
    }

    fn assert_finite_bounded(samples: &[f32]) {
        for &s in samples {
            assert!(s.is_finite(), "sample not finite: {s}");
            assert!((-1.0..=1.0).contains(&s), "sample out of [-1,1]: {s}");
        }
    }

    #[test]
    fn off_is_exact_noop_f32() {
        let orig = tone(320, 440.0, 0.5);
        let mut buf = orig.clone();
        let mut st = VoiceState::new();
        apply(VoiceEffect::Off, &mut buf, SR, &mut st);
        assert_eq!(buf, orig, "Off must be a bit-for-bit no-op");
    }

    #[test]
    fn off_is_exact_noop_i16() {
        let orig: Vec<i16> = (0..320).map(|i| ((i * 137) % 4000 - 2000) as i16).collect();
        let mut buf = orig.clone();
        let mut st = VoiceState::new();
        apply_i16(VoiceEffect::Off, &mut buf, SR, &mut st);
        assert_eq!(buf, orig, "Off must be a bit-for-bit no-op on i16");
    }

    #[test]
    fn silence_in_silence_or_bounded_out() {
        for effect in [
            VoiceEffect::Robot,
            VoiceEffect::Tremolo,
            VoiceEffect::Overdrive,
            VoiceEffect::Telephone,
            VoiceEffect::Whisper,
        ] {
            let mut buf = constant(320, 0.0);
            let mut st = VoiceState::new();
            apply(effect, &mut buf, SR, &mut st);
            assert_finite_bounded(&buf);
            // Multiplicative/filter effects must keep silence silent; whisper
            // emits noise scaled by a zero envelope, so it stays at silence too.
            if effect != VoiceEffect::Whisper {
                assert!(
                    buf.iter().all(|&s| s == 0.0),
                    "{effect:?}: silence should stay silent"
                );
            } else {
                assert!(
                    buf.iter().all(|&s| s.abs() < 1e-3),
                    "whisper on silence should stay near-silent"
                );
            }
        }
    }

    #[test]
    fn all_effects_stay_finite_and_bounded_on_loud_input() {
        for effect in [
            VoiceEffect::Robot,
            VoiceEffect::Tremolo,
            VoiceEffect::Overdrive,
            VoiceEffect::Telephone,
            VoiceEffect::Whisper,
        ] {
            // Hot, full-scale input.
            let mut buf = tone(640, 300.0, 1.0);
            let mut st = VoiceState::new();
            // Run several frames to exercise cross-frame state.
            for _ in 0..4 {
                apply(effect, &mut buf, SR, &mut st);
                assert_finite_bounded(&buf);
            }
        }
    }

    #[test]
    fn overdrive_softclips_large_input() {
        let mut buf = constant(64, 1.0);
        let mut st = VoiceState::new();
        apply(VoiceEffect::Overdrive, &mut buf, SR, &mut st);
        // tanh(4.0) ~= 0.9993; never exceeds 1.0.
        for &s in &buf {
            assert!(s <= 1.0 && s > 0.99, "expected soft-clipped near 1.0: {s}");
        }
    }

    #[test]
    fn overdrive_amplifies_small_input() {
        let small = 0.05f32;
        let mut buf = constant(64, small);
        let mut st = VoiceState::new();
        apply(VoiceEffect::Overdrive, &mut buf, SR, &mut st);
        // With drive 4.0, tanh(0.2) ~= 0.197 > 0.05 input.
        assert!(
            buf[0] > small,
            "overdrive should boost small input: {} -> {}",
            small,
            buf[0]
        );
        assert_finite_bounded(&buf);
    }

    #[test]
    fn tremolo_modulates_constant_input() {
        let n = 16_000; // a full second so the 6 Hz LFO sweeps fully.
        let mut buf = constant(n, 0.5);
        let orig = buf.clone();
        let mut st = VoiceState::new();
        apply(VoiceEffect::Tremolo, &mut buf, SR, &mut st);
        assert_finite_bounded(&buf);
        assert_ne!(buf, orig, "tremolo should change a constant input");
        // The LFO must actually dip the amplitude somewhere.
        let min = buf.iter().cloned().fold(f32::INFINITY, f32::min);
        assert!(min < 0.5, "tremolo should dip below the input level: {min}");
    }

    #[test]
    fn robot_modulates_tone_input() {
        let buf0 = tone(1600, 440.0, 0.6);
        let mut buf = buf0.clone();
        let mut st = VoiceState::new();
        apply(VoiceEffect::Robot, &mut buf, SR, &mut st);
        assert_finite_bounded(&buf);
        assert_ne!(buf, buf0, "robot ring-mod should change a tone input");
    }

    #[test]
    fn periodic_effects_are_phase_continuous_across_frames() {
        // Two adjacent frames processed with carried state should look the same
        // as one big frame processed in one go (no boundary discontinuity).
        let whole = tone(640, 300.0, 0.5);
        let (a, b) = whole.split_at(320);
        let mut one_shot = whole.clone();
        let mut st_single = VoiceState::new();
        apply(VoiceEffect::Tremolo, &mut one_shot, SR, &mut st_single);

        let mut fa = a.to_vec();
        let mut fb = b.to_vec();
        let mut st = VoiceState::new();
        apply(VoiceEffect::Tremolo, &mut fa, SR, &mut st);
        apply(VoiceEffect::Tremolo, &mut fb, SR, &mut st);

        let mut joined = fa;
        joined.extend(fb);
        for (i, (x, y)) in joined.iter().zip(one_shot.iter()).enumerate() {
            assert!((x - y).abs() < 1e-6, "phase discontinuity at sample {i}");
        }
    }

    #[test]
    fn telephone_attenuates_a_low_tone() {
        // A 60 Hz tone is well below the 300 Hz high-pass corner and should be
        // strongly attenuated.
        let buf0 = tone(16_000, 60.0, 0.8);
        let mut buf = buf0.clone();
        let mut st = VoiceState::new();
        apply(VoiceEffect::Telephone, &mut buf, SR, &mut st);
        assert_finite_bounded(&buf);
        let rms = |v: &[f32]| (v.iter().map(|&s| s * s).sum::<f32>() / v.len() as f32).sqrt();
        assert!(
            rms(&buf) < rms(&buf0) * 0.5,
            "telephone should attenuate a 60 Hz tone"
        );
    }
}
