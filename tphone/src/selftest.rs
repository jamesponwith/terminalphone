//! Headless integrated self-test (no TTY, no Tor, no audio device).
//!
//! [`run`] drives a complete loopback call between two in-process call cores
//! over [`LoopbackTransport`] using the [`SyntheticBackend`] on both sides. It
//! runs the *real* proto handshake (HELLO exchange + HKDF call-key derivation),
//! then pushes a synthetic tone (captured → encoded by the real engine) and a
//! text `MSG` through the full
//! `capture → encode → seal → write → read → open → decode → sink` pipeline,
//! and asserts an exact round-trip: every PCM sample the receiver plays back
//! matches the codec reference, and the message arrives byte-for-byte.
//!
//! This is the canonical proof the integrated app works end to end; it backs
//! both the `selftest` subcommand and the integration test in `tests/`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::app::{run_call, run_handshake, CallIo, Role};
use crate::audio::codec::{OpusDecoder, OpusEncoder};
use crate::audio::{AudioConfig, AudioEngine, OpusFrame, PcmFrame, SyntheticBackend};
use crate::config::OpusParams;
use crate::crypto::{AeadSuite, CallNonce, Psk};
use crate::error::{Error, Result};
use crate::proto::Hello;
use crate::transport::{Conn, Identity, LoopbackTransport, OnionAddr, Transport};

/// Number of tone frames pushed through the pipeline (25 * 20 ms = 0.5 s).
const TONE_FRAMES: usize = 25;
/// Text message round-tripped alongside the audio.
const TEST_MESSAGE: &str = "selftest-roundtrip";
/// Shared PSK both synthetic cores use.
const TEST_PSK: [u8; 32] = [0x42; 32];

/// Run the headless integrated self-test. Returns `Ok(())` on an exact match.
pub async fn run() -> Result<()> {
    let opus = OpusParams::default();
    let audio_cfg = AudioConfig { opus };

    // --- Transport pair over loopback (no Tor). ---
    let (mut caller_conn, mut callee_conn) = connected_pair().await?;

    // --- Real handshake on both sides (HELLO + HKDF). ---
    let psk = Psk::from_bytes(TEST_PSK);
    let (caller_hs, callee_hs) = tokio::join!(
        run_handshake(
            &mut caller_conn,
            &psk,
            hello("caller.onion", 0x11, opus),
            Role::Caller,
        ),
        run_handshake(
            &mut callee_conn,
            &psk,
            hello("callee.onion", 0x22, opus),
            Role::Callee,
        ),
    );
    let (caller_keys, caller_peer) = caller_hs?;
    let (callee_keys, callee_peer) = callee_hs?;

    // --- Audio engines (synthetic, no hardware). ---
    // Caller captures the tone; callee records what it plays back so we can
    // assert the round-tripped PCM.
    let callee_backend = SyntheticBackend::new();
    let played: Arc<Mutex<Vec<i16>>> = callee_backend.sink_handle();

    let mut caller_engine = AudioEngine::synthetic(audio_cfg);
    caller_engine.start_engine()?;
    let mut callee_engine = AudioEngine::with_backend(audio_cfg, Box::new(callee_backend));
    callee_engine.start_engine()?;

    // --- Build the two CallIo bridges. ---
    let (caller_io, mut caller_handles) = make_io();
    let (callee_io, mut callee_handles) = make_io();

    // --- Run both call loops concurrently. ---
    let caller_loop = tokio::spawn(run_call(
        caller_conn,
        caller_keys,
        Role::Caller,
        caller_peer,
        caller_io,
    ));
    let callee_loop = tokio::spawn(run_call(
        callee_conn,
        callee_keys,
        Role::Callee,
        callee_peer,
        callee_io,
    ));

    // --- Reference PCM: encode+decode the same tone the engine captures, to
    // compare exactly against the callee's decoded playback. ---
    let reference = reference_pcm(opus)?;

    // --- Bridge the caller's capture pump into its send path. ---
    // capture() engages PTT and yields encoded OpusFrames; feed exactly
    // TONE_FRAMES of them to the call's audio_out so they are sealed and sent.
    let mut capture_rx = caller_engine.capture()?;
    let caller_audio_out = caller_handles
        .audio_out_tx
        .take()
        .expect("audio_out_tx present");
    let pump = tokio::spawn(async move {
        for _ in 0..TONE_FRAMES {
            match capture_rx.recv().await {
                Some(frame) => {
                    if caller_audio_out.send(frame).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
        // Returning here drops capture_rx and caller_audio_out.
    });

    // --- Caller also sends a text message. ---
    let caller_msg_out = caller_handles
        .msg_out_tx
        .take()
        .expect("msg_out_tx present");
    caller_msg_out
        .send(TEST_MESSAGE.to_string())
        .await
        .map_err(|_| Error::Audio("selftest: msg_out closed".into()))?;

    // --- Drain the callee's inbound audio and play it through the engine.
    // Playback runs inline (the synthetic engine is single-threaded and not
    // `Send`, so it must not be moved into a spawned task) until every tone
    // frame has been decoded into the shared sink. ---
    let mut callee_audio_in_rx = callee_handles
        .audio_in_rx
        .take()
        .expect("audio_in_rx present");
    let mut played_frames = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while played_frames < TONE_FRAMES {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(Error::Audio(format!(
                "selftest: timed out playing audio: played {played_frames} of {TONE_FRAMES} frames"
            )));
        }
        match tokio::time::timeout(remaining, callee_audio_in_rx.recv()).await {
            Ok(Some(frame)) => {
                callee_engine.play(frame)?;
                played_frames += 1;
            }
            Ok(None) => break, // call core dropped the audio sink
            Err(_) => {
                return Err(Error::Audio(
                    "selftest: timed out waiting for inbound audio".into(),
                ))
            }
        }
    }

    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
    wait_for_samples(&played, reference.len(), Duration::from_secs(5)).await?;

    // --- Wait for the callee to receive the text message. ---
    let mut callee_msg_in_rx = callee_handles
        .msg_in_rx
        .take()
        .expect("msg_in_rx present");
    let got_msg = tokio::time::timeout(Duration::from_secs(5), callee_msg_in_rx.recv())
        .await
        .map_err(|_| Error::Audio("selftest: timed out waiting for message".into()))?
        .ok_or_else(|| Error::Audio("selftest: msg_in channel closed".into()))?;
    if got_msg != TEST_MESSAGE {
        return Err(Error::Audio(format!(
            "selftest: message mismatch: got {got_msg:?}, expected {TEST_MESSAGE:?}"
        )));
    }

    // --- Assert: callee's played PCM matches the codec reference exactly. ---
    {
        let recorded = played.lock().expect("played lock");
        if recorded.len() != reference.len() {
            return Err(Error::Audio(format!(
                "selftest: sample count mismatch: played {}, expected {}",
                recorded.len(),
                reference.len()
            )));
        }
        if *recorded != reference {
            return Err(Error::Audio(
                "selftest: round-trip PCM differs from the codec reference".into(),
            ));
        }
    }

    // --- Tear down: dropping the remaining out-senders ends both call loops. ---
    drop(caller_msg_out);
    drop(caller_engine); // stops the caller capture pump
    let _ = tokio::time::timeout(Duration::from_secs(5), caller_loop).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), callee_loop).await;

    Ok(())
}

/// Establish a connected (caller_conn, callee_conn) pair over loopback.
async fn connected_pair() -> Result<(Conn, Conn)> {
    use futures::StreamExt;
    let transport = LoopbackTransport::new(OnionAddr("selftest.onion".to_string()));
    let id = Identity {
        key_dir: std::path::PathBuf::from("/tmp/tphone-selftest"),
        nickname: "selftest".to_string(),
    };
    let mut incoming = transport.host(&id).await?;
    let dialer = transport
        .dial(&OnionAddr("selftest.onion".to_string()))
        .await?;
    let host_conn = incoming
        .next()
        .await
        .ok_or_else(|| Error::Transport("selftest: no inbound connection".into()))??;
    Ok((dialer, host_conn))
}

/// Build a HELLO for one side.
fn hello(onion: &str, nonce: u8, opus: OpusParams) -> Hello {
    Hello {
        onion: OnionAddr(onion.to_string()),
        suite: AeadSuite::Aes256Gcm,
        opus,
        nonce: CallNonce([nonce; 32]),
    }
}

/// The producing/consuming halves of a [`CallIo`] the selftest drives.
struct IoHandles {
    /// Send captured OpusFrames into the call's send path.
    audio_out_tx: Option<mpsc::Sender<OpusFrame>>,
    /// Send outbound text into the call's send path.
    msg_out_tx: Option<mpsc::Sender<String>>,
    /// Receive opened inbound audio from the call's recv path.
    audio_in_rx: Option<mpsc::Receiver<OpusFrame>>,
    /// Receive opened inbound text from the call's recv path.
    msg_in_rx: Option<mpsc::Receiver<String>>,
    /// Held so the hangup channel stays open for the call's lifetime.
    #[allow(dead_code)]
    hangup_tx: mpsc::Sender<()>,
}

/// Construct a [`CallIo`] plus the handles to feed and observe it.
fn make_io() -> (CallIo, IoHandles) {
    let (audio_out_tx, audio_out) = mpsc::channel::<OpusFrame>(64);
    let (msg_out_tx, msg_out) = mpsc::channel::<String>(8);
    let (audio_in, audio_in_rx) = mpsc::channel::<OpusFrame>(64);
    let (msg_in, msg_in_rx) = mpsc::channel::<String>(8);
    let (hangup_tx, hangup) = mpsc::channel::<()>(1);
    (
        CallIo {
            audio_out,
            msg_out,
            audio_in,
            msg_in,
            hangup,
        },
        IoHandles {
            audio_out_tx: Some(audio_out_tx),
            msg_out_tx: Some(msg_out_tx),
            audio_in_rx: Some(audio_in_rx),
            msg_in_rx: Some(msg_in_rx),
            hangup_tx,
        },
    )
}

/// Produce the exact PCM the callee's sink will accumulate for the synthetic
/// tone, by running the same `encode → decode` the live pipeline performs.
///
/// The synthetic capture source emits a phase-continuous 440 Hz tone, encoding
/// each frame with one encoder (stateful, matching a single utterance); we
/// mirror that here with one encoder/decoder pair.
fn reference_pcm(opus: OpusParams) -> Result<Vec<i16>> {
    let mut enc = OpusEncoder::new(opus)?;
    let mut dec = OpusDecoder::new(opus)?;
    let frame_len = (opus.sample_rate as usize * opus.frame_ms as usize) / 1000;

    let mut out = Vec::with_capacity(frame_len * TONE_FRAMES);
    let mut phase: u64 = 0;
    for _ in 0..TONE_FRAMES {
        let mut samples = Vec::with_capacity(frame_len);
        for _ in 0..frame_len {
            let t = phase as f32 / opus.sample_rate as f32;
            let v = (2.0 * std::f32::consts::PI * 440.0 * t).sin() * 16_000.0;
            samples.push(v as i16);
            phase = phase.wrapping_add(1);
        }
        let encoded = enc.encode(&PcmFrame { samples })?;
        let decoded = dec.decode(&encoded)?;
        out.extend(decoded.samples);
    }
    Ok(out)
}

/// Poll the playback buffer until it holds at least `n` samples or `timeout`.
async fn wait_for_samples(played: &Arc<Mutex<Vec<i16>>>, n: usize, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if played.lock().expect("played lock").len() >= n {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            let have = played.lock().expect("played lock").len();
            return Err(Error::Audio(format!(
                "selftest: timed out waiting for playback: have {have} of {n} samples"
            )));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
