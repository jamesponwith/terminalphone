//! End-to-end proof of the crypto + proto call core over the in-process
//! [`LoopbackTransport`] — NO Tor, NO audio hardware (ARCHITECTURE "Testing").
//!
//! Two `App`-equivalent call cores are wired to opposite ends of a loopback
//! pipe. We run the real proto handshake (HELLO exchange + HKDF call-key
//! derivation), then drive [`tphone::app::run_call`] on both sides and push
//! synthetic Opus frames + a text `Msg` through the full
//! seal → write → read → open pipeline, asserting an exact byte round-trip.
//!
//! A second test proves the security boundary: when the two sides derive keys
//! from *different* PSKs, every sealed frame fails authentication on open, so
//! nothing is ever delivered to the peer's sinks.

use std::time::Duration;

use tphone::app::{CallEvent, CallIo, Role, run_call, run_handshake};
use tphone::audio::OpusFrame;
use tphone::config::OpusParams;
use tphone::crypto::{AeadSuite, CallNonce, Psk};
use tphone::proto::Hello;
use tphone::transport::{Conn, Identity, LoopbackTransport, OnionAddr, Transport};

use futures::StreamExt;
use tokio::sync::mpsc;

/// Establish a connected (caller_conn, callee_conn) pair over loopback.
async fn connected_pair() -> (Conn, Conn) {
    let transport = LoopbackTransport::new(OnionAddr("loop.onion".to_string()));
    let id = Identity {
        key_dir: std::path::PathBuf::from("/tmp/tphone-loopback-test"),
        nickname: "loopback".to_string(),
    };
    let mut incoming = transport.host(&id).await.expect("host");
    let dialer = transport
        .dial(&OnionAddr("loop.onion".to_string()))
        .await
        .expect("dial");
    let host_conn = incoming.next().await.expect("accept").expect("accept ok");
    (dialer, host_conn)
}

fn hello(onion: &str, nonce: u8) -> Hello {
    Hello {
        onion: OnionAddr(onion.to_string()),
        suite: AeadSuite::Aes256Gcm,
        opus: OpusParams::default(),
        nonce: CallNonce([nonce; 32]),
    }
}

/// A `CallIo` plus the handles the test uses to feed/observe it.
struct Endpoint {
    io: CallIo,
    audio_out_tx: mpsc::Sender<OpusFrame>,
    msg_out_tx: mpsc::Sender<String>,
    #[allow(dead_code)]
    ptt_out_tx: mpsc::Sender<bool>,
    audio_in_rx: mpsc::Receiver<OpusFrame>,
    msg_in_rx: mpsc::Receiver<String>,
    events_in_rx: mpsc::Receiver<CallEvent>,
    /// Shared byte counters (same Arc handed to the call loop).
    stats: std::sync::Arc<tphone::app::CallStats>,
    #[allow(dead_code)]
    hangup_tx: mpsc::Sender<()>,
}

fn make_endpoint() -> Endpoint {
    let (audio_out_tx, audio_out) = mpsc::channel(64);
    let (msg_out_tx, msg_out) = mpsc::channel(8);
    let (ptt_out_tx, ptt_out) = mpsc::channel(8);
    let (audio_in, audio_in_rx) = mpsc::channel(64);
    let (msg_in, msg_in_rx) = mpsc::channel(8);
    let (events_in, events_in_rx) = mpsc::channel(16);
    let (hangup_tx, hangup) = mpsc::channel(1);
    let stats = std::sync::Arc::new(tphone::app::CallStats::default());
    Endpoint {
        io: CallIo {
            audio_out,
            msg_out,
            ptt_out,
            audio_in,
            msg_in,
            events_in,
            stats: stats.clone(),
            // Long by default so existing tests see no surprise keepalive PINGs;
            // the keepalive test overrides `io.keepalive` before spawning.
            keepalive: std::time::Duration::from_secs(3600),
            hangup,
        },
        audio_out_tx,
        msg_out_tx,
        ptt_out_tx,
        audio_in_rx,
        msg_in_rx,
        events_in_rx,
        stats,
        hangup_tx,
    }
}

/// Three synthetic "Opus" frames (opaque bytes; the call core never decodes them
/// — it only seals/opens, so any payload proves the pipeline).
fn synthetic_frames() -> Vec<OpusFrame> {
    vec![
        OpusFrame {
            data: vec![0x01, 0x02, 0x03, 0x04],
        },
        OpusFrame {
            data: vec![0xAA; 80],
        },
        OpusFrame {
            data: (0..200u32).map(|i| (i % 251) as u8).collect(),
        },
    ]
}

#[tokio::test]
async fn loopback_full_pipeline_round_trips_audio_and_msg() {
    let psk = Psk::from_bytes([0x42; 32]);
    let (mut caller_conn, mut callee_conn) = connected_pair().await;

    // Real handshake over the loopback pipe (both sides, concurrently).
    let psk_a = psk.clone();
    let psk_b = psk.clone();
    let (caller_hs, callee_hs) = tokio::join!(
        run_handshake(
            &mut caller_conn,
            &psk_a,
            hello("caller.onion", 0x11),
            Role::Caller
        ),
        run_handshake(
            &mut callee_conn,
            &psk_b,
            hello("callee.onion", 0x22),
            Role::Callee
        ),
    );
    let (caller_keys, caller_peer) = caller_hs.expect("caller handshake");
    let (callee_keys, callee_peer) = callee_hs.expect("callee handshake");

    // Each side learned the other's identity.
    assert_eq!(caller_peer.onion.host(), "callee.onion");
    assert_eq!(callee_peer.onion.host(), "caller.onion");

    let mut caller = make_endpoint();
    let mut callee = make_endpoint();

    // Run both call loops concurrently.
    let caller_loop = tokio::spawn(run_call(
        caller_conn,
        caller_keys,
        Role::Caller,
        caller_peer,
        caller.io,
    ));
    let callee_loop = tokio::spawn(run_call(
        callee_conn,
        callee_keys,
        Role::Callee,
        callee_peer,
        callee.io,
    ));

    // Caller -> callee: push synthetic Opus frames; assert exact bytes arrive.
    let frames = synthetic_frames();
    for f in &frames {
        caller.audio_out_tx.send(f.clone()).await.unwrap();
    }
    for expected in &frames {
        let got = tokio::time::timeout(Duration::from_secs(5), callee.audio_in_rx.recv())
            .await
            .expect("audio frame not received in time")
            .expect("audio_in channel closed");
        assert_eq!(
            got.data, expected.data,
            "audio frame must round-trip exactly"
        );
    }

    // Callee -> caller: a text message round-trips exactly.
    callee
        .msg_out_tx
        .send("hello over the onion".to_string())
        .await
        .unwrap();
    let got_msg = tokio::time::timeout(Duration::from_secs(5), caller.msg_in_rx.recv())
        .await
        .expect("msg not received in time")
        .expect("msg_in channel closed");
    assert_eq!(got_msg, "hello over the onion");

    // Caller -> callee: a message the other way too.
    caller.msg_out_tx.send("ack".to_string()).await.unwrap();
    let got_ack = tokio::time::timeout(Duration::from_secs(5), callee.msg_in_rx.recv())
        .await
        .expect("ack not received in time")
        .expect("msg_in channel closed");
    assert_eq!(got_ack, "ack");

    // Tear down: dropping the out-senders closes the capture sources, which makes
    // each send loop emit HANGUP and return, ending both call loops.
    drop(caller.audio_out_tx);
    drop(callee.audio_out_tx);

    let _ = tokio::time::timeout(Duration::from_secs(5), caller_loop).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), callee_loop).await;
}

#[tokio::test]
async fn wrong_psk_peer_cannot_open_frames() {
    let (mut caller_conn, mut callee_conn) = connected_pair().await;

    // Mismatched PSKs: the handshake still completes (no PSK in HELLO), but the
    // two sides derive *different* call keys, so sealed frames fail to open.
    let caller_psk = Psk::from_bytes([0x42; 32]);
    let callee_psk = Psk::from_bytes([0x99; 32]);

    let (caller_hs, callee_hs) = tokio::join!(
        run_handshake(
            &mut caller_conn,
            &caller_psk,
            hello("caller.onion", 0x11),
            Role::Caller
        ),
        run_handshake(
            &mut callee_conn,
            &callee_psk,
            hello("callee.onion", 0x22),
            Role::Callee
        ),
    );
    let (caller_keys, caller_peer) = caller_hs.expect("caller handshake");
    let (callee_keys, callee_peer) = callee_hs.expect("callee handshake");

    let caller = make_endpoint();
    let mut callee = make_endpoint();

    let caller_loop = tokio::spawn(run_call(
        caller_conn,
        caller_keys,
        Role::Caller,
        caller_peer,
        caller.io,
    ));
    let callee_loop = tokio::spawn(run_call(
        callee_conn,
        callee_keys,
        Role::Callee,
        callee_peer,
        callee.io,
    ));

    // Caller seals + sends with its key; callee tries to open with a key derived
    // from a different PSK. Every frame must fail auth and be dropped — nothing
    // is delivered to the callee's sinks.
    for f in synthetic_frames() {
        caller.audio_out_tx.send(f).await.unwrap();
    }
    caller.msg_out_tx.send("secret".to_string()).await.unwrap();

    // Give the pipeline ample time; assert NOTHING is delivered.
    let audio = tokio::time::timeout(Duration::from_millis(500), callee.audio_in_rx.recv()).await;
    assert!(
        audio.is_err(),
        "wrong-PSK peer must NOT receive any audio frame (got {audio:?})"
    );
    let msg = tokio::time::timeout(Duration::from_millis(500), callee.msg_in_rx.recv()).await;
    assert!(
        msg.is_err(),
        "wrong-PSK peer must NOT receive any message (got {msg:?})"
    );

    drop(caller.audio_out_tx);
    drop(callee.audio_out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), caller_loop).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), callee_loop).await;
}

/// PTT start/stop signaling propagates end-to-end through the authenticated
/// control-frame path (sealed + opened), surfacing as `CallEvent::RemotePtt` on
/// the peer, and byte stats accrue on both ends.
#[tokio::test]
async fn ptt_signaling_propagates_and_stats_accrue() {
    let psk = Psk::from_bytes([0x42; 32]);
    let (mut caller_conn, mut callee_conn) = connected_pair().await;

    let psk_a = psk.clone();
    let psk_b = psk.clone();
    let (caller_hs, callee_hs) = tokio::join!(
        run_handshake(
            &mut caller_conn,
            &psk_a,
            hello("caller.onion", 0x11),
            Role::Caller
        ),
        run_handshake(
            &mut callee_conn,
            &psk_b,
            hello("callee.onion", 0x22),
            Role::Callee
        ),
    );
    let (caller_keys, caller_peer) = caller_hs.expect("caller handshake");
    let (callee_keys, callee_peer) = callee_hs.expect("callee handshake");

    let caller = make_endpoint();
    let mut callee = make_endpoint();
    let caller_stats = caller.stats.clone();
    let callee_stats = callee.stats.clone();

    let caller_loop = tokio::spawn(run_call(
        caller_conn,
        caller_keys,
        Role::Caller,
        caller_peer,
        caller.io,
    ));
    let callee_loop = tokio::spawn(run_call(
        callee_conn,
        callee_keys,
        Role::Callee,
        callee_peer,
        callee.io,
    ));

    // Caller signals PTT start, then stop; the callee must observe both, in order.
    caller.ptt_out_tx.send(true).await.unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(5), callee.events_in_rx.recv())
        .await
        .expect("no PTT_START event in time")
        .expect("events channel closed");
    assert!(
        matches!(ev, CallEvent::RemotePtt(true)),
        "expected RemotePtt(true), got {ev:?}"
    );

    caller.ptt_out_tx.send(false).await.unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(5), callee.events_in_rx.recv())
        .await
        .expect("no PTT_STOP event in time")
        .expect("events channel closed");
    assert!(
        matches!(ev, CallEvent::RemotePtt(false)),
        "expected RemotePtt(false), got {ev:?}"
    );

    use std::sync::atomic::Ordering;
    assert!(
        caller_stats.bytes_sent.load(Ordering::Relaxed) > 0,
        "caller should have sent bytes for the PTT frames"
    );
    assert!(
        callee_stats.bytes_recv.load(Ordering::Relaxed) > 0,
        "callee should have received bytes for the PTT frames"
    );

    drop(caller.audio_out_tx);
    drop(callee.audio_out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), caller_loop).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), callee_loop).await;
}

/// With a short keepalive interval and no user traffic, the send loop emits
/// sealed PINGs that the peer authenticates and answers with PONG — so bytes
/// flow in both directions during silence, keeping the circuit warm.
#[tokio::test]
async fn keepalive_pings_flow_during_silence() {
    let psk = Psk::from_bytes([0x42; 32]);
    let (mut caller_conn, mut callee_conn) = connected_pair().await;

    let psk_a = psk.clone();
    let psk_b = psk.clone();
    let (caller_hs, callee_hs) = tokio::join!(
        run_handshake(
            &mut caller_conn,
            &psk_a,
            hello("caller.onion", 0x11),
            Role::Caller
        ),
        run_handshake(
            &mut callee_conn,
            &psk_b,
            hello("callee.onion", 0x22),
            Role::Callee
        ),
    );
    let (caller_keys, caller_peer) = caller_hs.expect("caller handshake");
    let (callee_keys, callee_peer) = callee_hs.expect("callee handshake");

    let mut caller = make_endpoint();
    let mut callee = make_endpoint();
    // Fast keepalive on both ends; override the long default before spawning.
    caller.io.keepalive = Duration::from_millis(40);
    callee.io.keepalive = Duration::from_millis(40);
    let caller_stats = caller.stats.clone();
    let callee_stats = callee.stats.clone();

    let caller_loop = tokio::spawn(run_call(
        caller_conn,
        caller_keys,
        Role::Caller,
        caller_peer,
        caller.io,
    ));
    let callee_loop = tokio::spawn(run_call(
        callee_conn,
        callee_keys,
        Role::Callee,
        callee_peer,
        callee.io,
    ));

    // Without sending any audio/text, keepalive PINGs (and the PONG replies) must
    // move bytes both ways. Poll a short while for the counters to rise.
    use std::sync::atomic::Ordering;
    let mut ok = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if caller_stats.bytes_recv.load(Ordering::Relaxed) > 0
            && callee_stats.bytes_recv.load(Ordering::Relaxed) > 0
        {
            ok = true;
            break;
        }
    }
    assert!(
        ok,
        "keepalive PING/PONG should move bytes in both directions during silence"
    );

    drop(caller.audio_out_tx);
    drop(callee.audio_out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), caller_loop).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), callee_loop).await;
}
