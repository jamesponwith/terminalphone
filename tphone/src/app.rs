//! Top-level orchestration: the call state machine wiring transport + proto +
//! crypto + audio (ARCHITECTURE "app.rs", SPEC §1).
//!
//! The heavy lifting of one call lives in [`App::run`]: bootstrap the chosen
//! [`Transport`], host or dial to obtain a [`Conn`], run the proto handshake to
//! derive [`CallKeys`], then drive the pipelined PTT loop. The loop is split into
//! a *send* task (capture → encode → seal → write `Audio` frames as produced)
//! and a *recv* task (read → open → decode → play), plus `Msg`/`Ping`/`Pong`/
//! `Hangup` handling, all coordinated over channels so neither direction blocks
//! the other (SPEC §3 latency; ARCHITECTURE "Data flow").
//!
//! The crypto + proto core is fully exercisable without Tor or audio hardware:
//! [`run_call`] takes any `Conn` + a [`CallHooks`] sink/source, so the loopback
//! integration test can push synthetic Opus frames and a text `Msg` through the
//! real seal/open pipeline (see `tests/loopback_call.rs`).

use futures::StreamExt;
use tokio::sync::mpsc;

use crate::audio::OpusFrame;
use crate::config::Config;
use crate::crypto::{CallKeys, Direction, Psk};
use crate::error::{Error, Result};
use crate::proto::{self, Frame, Hello, PeerInfo};
use crate::transport::{Conn, Identity, OnionAddr, Transport};

/// The call lifecycle (ARCHITECTURE diagram: Idle ─ Hosting ─ Dialing ─ InCall ─ Hangup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppState {
    /// No call; menus / idle.
    Idle,
    /// Onion service launched, awaiting an inbound caller.
    Hosting,
    /// Dialing a remote onion, awaiting connect + handshake.
    Dialing,
    /// Handshake complete; live half-duplex PTT call.
    InCall,
    /// Tearing down (graceful HANGUP, circuit teardown, key zeroization).
    Hangup,
}

/// What the user asked the binary to do this run.
#[derive(Debug, Clone)]
pub enum Command {
    /// Host an onion service and wait for a caller.
    Host,
    /// Dial the given remote onion.
    Dial(OnionAddr),
}

/// Which side of the handshake this peer plays. Determines the seal/open
/// [`Direction`] tags and the HELLO ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We dialed out (caller). We seal `CallerToCallee`, open `CalleeToCaller`.
    Caller,
    /// We accepted an inbound call (callee). Tags are mirrored.
    Callee,
}

impl Role {
    /// The direction tag we use when *sealing* outbound frames.
    pub fn send_dir(self) -> Direction {
        match self {
            Role::Caller => Direction::CallerToCallee,
            Role::Callee => Direction::CalleeToCaller,
        }
    }

    /// The direction tag we use when *opening* inbound frames.
    pub fn recv_dir(self) -> Direction {
        match self {
            Role::Caller => Direction::CalleeToCaller,
            Role::Callee => Direction::CallerToCallee,
        }
    }
}

/// The running application: holds config, the PSK, and the current state.
pub struct App {
    /// Loaded user configuration.
    cfg: Config,
    /// The pre-shared secret for this run.
    psk: Psk,
    /// Current state-machine position.
    state: AppState,
}

impl App {
    /// Construct from loaded config and PSK; starts in [`AppState::Idle`].
    pub fn new(cfg: Config, psk: Psk) -> Self {
        App {
            cfg,
            psk,
            state: AppState::Idle,
        }
    }

    /// The current state-machine position.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// The loaded config.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Drive one call to completion for `cmd`: bootstrap transport, host/dial,
    /// run the handshake, then the PTT/audio loop until hangup.
    pub async fn run<T: Transport>(&mut self, cmd: Command) -> Result<()> {
        // 1. Bootstrap the transport (warm at launch).
        let transport = T::bootstrap(&self.cfg.tor_config()).await?;

        // 2. Obtain a Conn and decide our role.
        let (conn, role) = match cmd {
            Command::Host => {
                self.state = AppState::Hosting;
                let identity = Identity {
                    key_dir: self.cfg.identity_dir(),
                    nickname: "terminalphone".to_string(),
                };
                let mut incoming = transport.host(&identity).await?;
                if let Some(addr) = transport.onion_address() {
                    tracing::info!(onion = %addr.host(), "hosting; share this .onion");
                }
                let conn = incoming
                    .next()
                    .await
                    .ok_or_else(|| Error::Transport("host: incoming stream ended".into()))??;
                (conn, Role::Callee)
            }
            Command::Dial(onion) => {
                self.state = AppState::Dialing;
                let conn = transport.dial(&onion).await?;
                (conn, Role::Caller)
            }
        };

        // 3. Handshake -> (CallKeys, PeerInfo). on suite mismatch, abort.
        let mut conn = conn;
        let my_hello = self.build_hello(&transport);
        let (keys, peer) = run_handshake(&mut conn, &self.psk, my_hello, role).await?;
        tracing::info!(onion = %peer.onion.host(), suite = ?peer.suite, "call established");

        self.state = AppState::InCall;

        // 4. Bring up audio + the TUI + the pipelined PTT loop. Audio is
        // cpal-backed and therefore hardware-dependent; on a headless host this
        // fails loudly rather than running a silent call. The TUI owns the
        // terminal and drives PTT / text / hangup; the call core seals/opens
        // frames over the wire.
        let local_onion = transport
            .onion_address()
            .map(|a| a.host().to_string())
            .unwrap_or_else(|| "unknown.onion".to_string());
        let outcome =
            run_interactive(&self.cfg, conn, keys, role, peer.clone(), &local_onion).await;

        // 5. Teardown. Drop of CallKeys zeroizes; transport drop tears circuits.
        self.state = AppState::Hangup;
        outcome
    }

    /// Build our HELLO from config + the transport's published onion (if any).
    fn build_hello<T: Transport>(&self, transport: &T) -> Hello {
        let onion = transport
            .onion_address()
            .unwrap_or_else(|| OnionAddr("unknown.onion".to_string()));
        Hello {
            onion,
            suite: self.cfg.aead_suite,
            opus: self.cfg.opus,
            nonce: crate::crypto::CallNonce::random(),
        }
    }
}

/// Run the role-appropriate proto handshake over `stream`, leaving the stream
/// open for the subsequent call loop (the handshake only borrows it).
pub async fn run_handshake<S>(
    stream: &mut S,
    psk: &Psk,
    my_hello: Hello,
    role: Role,
) -> Result<(CallKeys, PeerInfo)>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    match role {
        Role::Caller => proto::handshake_caller(stream, psk, my_hello).await,
        Role::Callee => proto::handshake_callee(stream, psk, my_hello).await,
    }
}

/// Source/sink the call loop pulls outbound payloads from and pushes inbound
/// payloads to. Decouples the crypto+proto core from audio hardware so tests can
/// substitute synthetic frames.
pub struct CallIo {
    /// Outbound encoded Opus frames to seal + send (from capture).
    pub audio_out: mpsc::Receiver<OpusFrame>,
    /// Outbound text messages to seal + send.
    pub msg_out: mpsc::Receiver<String>,
    /// Inbound decoded-ready Opus frames (to decode + play).
    pub audio_in: mpsc::Sender<OpusFrame>,
    /// Inbound text messages received from the peer.
    pub msg_in: mpsc::Sender<String>,
    /// Signalled by the user/UI to request a graceful hangup.
    pub hangup: mpsc::Receiver<()>,
}

/// Drive a live, interactive call: bridge the cpal [`AudioEngine`] and the TUI
/// to [`run_call`] over `conn`.
///
/// This is the production call path. It:
///   * brings up the cpal-backed engine (a missing device surfaces as a clean
///     [`Error::Audio`], never a panic);
///   * builds a [`CallIo`] and spawns the [`run_call`] core;
///   * enters the raw-mode TUI and translates [`crate::tui::UiEvent`]s into call
///     actions — PTT start/stop drives capture; text becomes a `MSG`; `q`/Ctrl-C
///     hangs up — while routing decoded inbound audio into playback and inbound
///     text + stats onto the call screen.
///
/// Returns when the user hangs up or the peer drops.
async fn run_interactive(
    cfg: &Config,
    conn: Conn,
    keys: CallKeys,
    role: Role,
    peer: PeerInfo,
    local_onion: &str,
) -> Result<()> {
    use crate::audio::{AudioConfig, AudioEngine};
    use crate::tui::{CallScreen, Tui, UiEvent};

    // Bring up audio first so a missing device fails before we touch the UI.
    let engine = AudioEngine::start(AudioConfig { opus: cfg.opus })?;

    // Channels into the call core.
    let (audio_out_tx, audio_out) = mpsc::channel::<OpusFrame>(64);
    let (msg_out_tx, msg_out) = mpsc::channel::<String>(8);
    let (audio_in_tx, mut audio_in_rx) = mpsc::channel::<OpusFrame>(64);
    let (msg_in_tx, mut msg_in_rx) = mpsc::channel::<String>(8);
    let (hangup_tx, hangup) = mpsc::channel::<()>(1);

    let io = CallIo {
        audio_out,
        msg_out,
        audio_in: audio_in_tx,
        msg_in: msg_in_tx,
        hangup,
    };

    let call = tokio::spawn(run_call(conn, keys, role, peer.clone(), io));

    // Inbound audio pump: opened frames -> playback engine (decode + jitter).
    // The engine is shared so the UI loop can also start/stop capture.
    let engine = std::sync::Arc::new(std::sync::Mutex::new(engine));
    let play_engine = engine.clone();
    let playback = tokio::spawn(async move {
        while let Some(frame) = audio_in_rx.recv().await {
            // play() takes &self; lock only to access the shared engine handle.
            let res = play_engine.lock().expect("engine lock").play(frame);
            if let Err(e) = res {
                tracing::warn!(error = %e, "playback enqueue failed");
            }
        }
    });

    // Enter the terminal UI.
    let mut tui = Tui::enter(cfg)?;
    let mut screen = CallScreen::from_peer(cfg, local_onion, &peer);
    let mut ui = tui.spawn(screen.clone());

    // Outbound capture pump task handle; present only while PTT is held.
    let mut capture_task: Option<tokio::task::JoinHandle<()>> = None;

    // The interactive event loop. Ends when the user hangs up, the peer drops
    // (call task finishes), or the UI input stream closes.
    let outcome = loop {
        tokio::select! {
            ev = ui.next_event() => {
                match ev {
                    Some(UiEvent::PttStart) => {
                        if capture_task.is_none() {
                            // Begin capture and forward encoded frames to the wire.
                            let rx = {
                                let mut eng = engine.lock().expect("engine lock");
                                eng.capture()
                            };
                            match rx {
                                Ok(mut rx) => {
                                    let out = audio_out_tx.clone();
                                    capture_task = Some(tokio::spawn(async move {
                                        while let Some(frame) = rx.recv().await {
                                            if out.send(frame).await.is_err() {
                                                break;
                                            }
                                        }
                                    }));
                                    screen.local_ptt = true;
                                    ui.render(screen.clone());
                                }
                                Err(e) => tracing::warn!(error = %e, "capture start failed"),
                            }
                        }
                    }
                    Some(UiEvent::PttStop) => {
                        if let Some(t) = capture_task.take() {
                            t.abort();
                        }
                        let _ = engine.lock().expect("engine lock").stop_capture();
                        screen.local_ptt = false;
                        ui.render(screen.clone());
                    }
                    Some(UiEvent::SendText(text)) => {
                        screen.messages.push(format!("you : {text}"));
                        if screen.messages.len() > 100 {
                            screen.messages.remove(0);
                        }
                        ui.render(screen.clone());
                        let _ = msg_out_tx.send(text).await;
                    }
                    Some(UiEvent::Hangup) | None => {
                        let _ = hangup_tx.send(()).await;
                        break Ok(());
                    }
                }
            }
            msg = msg_in_rx.recv() => {
                if let Some(text) = msg {
                    // Add message to history and re-render.
                    screen.messages.push(format!("peer: {text}"));
                    // Keep message history bounded to avoid unbounded growth.
                    if screen.messages.len() > 100 {
                        screen.messages.remove(0);
                    }
                    ui.render(screen.clone());
                }
            }
        }

        // If the call core has finished (peer hung up / error), stop.
        if call.is_finished() {
            break Ok(());
        }
    };

    // Wind everything down.
    if let Some(t) = capture_task.take() {
        t.abort();
    }
    let _ = engine.lock().expect("engine lock").stop_capture();
    ui.shutdown();
    drop(ui);
    drop(tui); // restores the terminal
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), call).await;
    playback.abort();

    outcome
}

/// Run the full pipelined call loop over `conn` with derived `keys`.
///
/// This is the crypto+proto heart of a call, independent of Tor and audio
/// hardware. It:
///   * seals each outbound `OpusFrame` as an `Audio` frame (per-direction seq in
///     the AAD) and writes it as produced (pipelined);
///   * seals outbound text as `Msg` frames;
///   * answers inbound `Ping` with `Pong`;
///   * opens inbound `Audio`/`Msg` and forwards the plaintext to the sinks;
///   * sends `Hangup` and returns cleanly when asked or when the peer hangs up.
///
/// Returns `Ok(())` on a graceful hangup (either side); a transport/proto error
/// otherwise. A peer-side close surfaces as `Ok(())` (treated as hangup).
pub async fn run_call(
    conn: Conn,
    keys: CallKeys,
    role: Role,
    _peer: PeerInfo,
    io: CallIo,
) -> Result<()> {
    use futures::io::AsyncReadExt as _;

    // Split the duplex stream so the read and write halves can be driven
    // concurrently (pipelined send while receiving — SPEC §3).
    let (reader, writer) = conn.split();

    let keys = std::sync::Arc::new(keys);
    let send_dir = role.send_dir();
    let recv_dir = role.recv_dir();

    let CallIo {
        audio_out,
        msg_out,
        audio_in,
        msg_in,
        hangup,
    } = io;

    // Channel by which the send half asks the write half to emit control frames
    // it generates in response to inbound traffic (e.g. PONG to a PING).
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<ControlOut>(8);

    let recv_keys = keys.clone();
    let recv_fut = recv_loop(
        reader,
        recv_keys,
        recv_dir,
        audio_in,
        msg_in,
        ctrl_tx.clone(),
    );
    let send_fut = send_loop(writer, keys, send_dir, audio_out, msg_out, hangup, ctrl_rx);

    // Whichever half finishes first decides the call outcome; the other is
    // dropped (its half of the stream closes, unblocking the peer).
    tokio::select! {
        r = recv_fut => r,
        r = send_fut => r,
    }
}

/// Control frames the receive half asks the send half to emit.
enum ControlOut {
    /// Answer an inbound PING.
    Pong,
}

/// Read frames, open them, and dispatch plaintext to the sinks. Returns
/// `Ok(())` on a graceful peer close or HANGUP; an error on a protocol/IO fault.
async fn recv_loop<R>(
    mut reader: R,
    keys: std::sync::Arc<CallKeys>,
    recv_dir: Direction,
    audio_in: mpsc::Sender<OpusFrame>,
    msg_in: mpsc::Sender<String>,
    ctrl_tx: mpsc::Sender<ControlOut>,
) -> Result<()>
where
    R: futures::AsyncRead + Unpin,
{
    loop {
        let frame = match proto::read_frame(&mut reader).await {
            Ok(f) => f,
            // A clean close or a broken pipe both mean the call is over.
            Err(Error::Closed) => return Ok(()),
            Err(Error::Io(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        match frame {
            Frame::Audio { seq, sealed } => {
                let aad = [FrameTag::Audio as u8];
                match keys.open(recv_dir, seq, &aad, &sealed) {
                    Ok(pt) => {
                        // Lost frames are tolerable; the jitter buffer copes.
                        let _ = audio_in.send(OpusFrame { data: pt }).await;
                    }
                    Err(Error::AuthFailed) => {
                        tracing::debug!(seq, "dropping unauthentic/replayed AUDIO frame");
                    }
                    Err(e) => return Err(e),
                }
            }
            Frame::Msg { sealed } => {
                // MSG shares the per-direction replay window with AUDIO, so it
                // must carry its own sequence rather than reusing seq 0 (which an
                // earlier AUDIO frame would have already consumed). The frozen
                // `Frame::Msg { sealed }` wire shape has no seq field, so the
                // 8-byte big-endian seq is prefixed (in plaintext) ahead of the
                // ciphertext, exactly as AUDIO prefixes its seq.
                let Some((seq, ct)) = split_seq_prefix(&sealed) else {
                    tracing::debug!("dropping MSG frame too short to hold a seq prefix");
                    continue;
                };
                let aad = [FrameTag::Msg as u8];
                match keys.open(recv_dir, seq, &aad, ct) {
                    Ok(pt) => {
                        let text = String::from_utf8_lossy(&pt).into_owned();
                        let _ = msg_in.send(text).await;
                    }
                    Err(Error::AuthFailed) => {
                        tracing::debug!(seq, "dropping unauthentic/replayed MSG frame");
                    }
                    Err(e) => return Err(e),
                }
            }
            Frame::Ping { .. } => {
                // Ask the send half to reply; ignore if it has gone away.
                let _ = ctrl_tx.send(ControlOut::Pong).await;
            }
            Frame::Hangup { .. } => return Ok(()),
            Frame::Pong { .. }
            | Frame::PttStart { .. }
            | Frame::PttStop { .. }
            | Frame::Cipher { .. } => {
                // Acknowledged but not acted on in M1.
            }
            Frame::Hello(_) => {
                return Err(Error::Proto("unexpected HELLO after handshake".into()));
            }
        }
    }
}

/// Seal and write outbound frames as they are produced. Returns `Ok(())` when
/// the user requests hangup or the capture/msg sources close.
async fn send_loop<W>(
    mut writer: W,
    keys: std::sync::Arc<CallKeys>,
    send_dir: Direction,
    mut audio_out: mpsc::Receiver<OpusFrame>,
    mut msg_out: mpsc::Receiver<String>,
    mut hangup: mpsc::Receiver<()>,
    mut ctrl_rx: mpsc::Receiver<ControlOut>,
) -> Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    let mut send_seq: u64 = 0;
    loop {
        tokio::select! {
            biased;

            _ = hangup.recv() => {
                let sealed = keys.seal(send_dir, next(&mut send_seq), &[FrameTag::Hangup as u8], &[]);
                let _ = proto::write_frame(&mut writer, &Frame::Hangup { sealed }).await;
                return Ok(());
            }

            maybe = audio_out.recv() => {
                match maybe {
                    Some(frame) => {
                        let seq = next(&mut send_seq);
                        let aad = [FrameTag::Audio as u8];
                        let sealed = keys.seal(send_dir, seq, &aad, &frame.data);
                        proto::write_frame(&mut writer, &Frame::Audio { seq, sealed }).await?;
                    }
                    None => {
                        let sealed = keys.seal(send_dir, next(&mut send_seq), &[FrameTag::Hangup as u8], &[]);
                        let _ = proto::write_frame(&mut writer, &Frame::Hangup { sealed }).await;
                        return Ok(());
                    }
                }
            }

            maybe = msg_out.recv() => {
                if let Some(text) = maybe {
                    // Draw from the shared monotonic counter so MSG and AUDIO
                    // never collide in the receiver's replay window, then prefix
                    // the seq (plaintext) ahead of the ciphertext.
                    let seq = next(&mut send_seq);
                    let aad = [FrameTag::Msg as u8];
                    let sealed = with_seq_prefix(seq, keys.seal(send_dir, seq, &aad, text.as_bytes()));
                    proto::write_frame(&mut writer, &Frame::Msg { sealed }).await?;
                }
            }

            maybe = ctrl_rx.recv() => {
                if let Some(ControlOut::Pong) = maybe {
                    let sealed = keys.seal(send_dir, next(&mut send_seq), &[FrameTag::Pong as u8], &[]);
                    proto::write_frame(&mut writer, &Frame::Pong { sealed }).await?;
                }
            }
        }
    }
}

/// Frame-type tag bound into the AEAD AAD so a frame sealed as one type cannot be
/// reinterpreted as another (matches `FrameType` wire ids; SPEC §5.2/§5.3).
#[derive(Clone, Copy)]
#[repr(u8)]
enum FrameTag {
    Audio = 0x02,
    Msg = 0x03,
    Pong = 0x07,
    Hangup = 0x08,
}

/// Allocate the next outbound sequence and advance the counter.
fn next(seq: &mut u64) -> u64 {
    let s = *seq;
    *seq = seq.wrapping_add(1);
    s
}

/// Prefix an 8-byte big-endian sequence ahead of a sealed payload, so frames
/// whose frozen wire shape carries no seq field (e.g. `Frame::Msg`) can still be
/// opened at the right sequence and tracked in the shared replay window.
fn with_seq_prefix(seq: u64, ciphertext: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ciphertext.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    out
}

/// Split an 8-byte big-endian sequence prefix off a sealed payload produced by
/// [`with_seq_prefix`]. Returns `None` if the payload is too short to hold one.
fn split_seq_prefix(payload: &[u8]) -> Option<(u64, &[u8])> {
    if payload.len() < 8 {
        return None;
    }
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&payload[..8]);
    Some((u64::from_be_bytes(seq_bytes), &payload[8..]))
}
