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
    /// Local PTT transitions to signal to the peer: `true` = started talking
    /// (emits `PTT_START`), `false` = stopped (emits `PTT_STOP`).
    pub ptt_out: mpsc::Receiver<bool>,
    /// Inbound decoded-ready Opus frames (to decode + play).
    pub audio_in: mpsc::Sender<OpusFrame>,
    /// Inbound text messages received from the peer.
    pub msg_in: mpsc::Sender<String>,
    /// Inbound call events surfaced to the UI (e.g. the remote PTT indicator).
    pub events_in: mpsc::Sender<CallEvent>,
    /// Shared byte counters updated by the send/recv loops, read by the UI.
    pub stats: std::sync::Arc<CallStats>,
    /// Signalled by the user/UI to request a graceful hangup.
    pub hangup: mpsc::Receiver<()>,
}

/// Events the call core surfaces to the UI as they happen on the wire.
#[derive(Debug, Clone, Copy)]
pub enum CallEvent {
    /// The peer started (`true`) or stopped (`false`) transmitting.
    RemotePtt(bool),
}

/// Live byte counters for the call, shared between the loops and the UI.
#[derive(Debug, Default)]
pub struct CallStats {
    /// Total bytes written to the wire (all frame types, incl. headers).
    pub bytes_sent: std::sync::atomic::AtomicU64,
    /// Total bytes read from the wire.
    pub bytes_recv: std::sync::atomic::AtomicU64,
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
    let engine = AudioEngine::start(AudioConfig {
        opus: cfg.opus,
        voice_effect: cfg.voice_effect,
    })?;

    // Channels into the call core.
    let (audio_out_tx, audio_out) = mpsc::channel::<OpusFrame>(64);
    let (msg_out_tx, msg_out) = mpsc::channel::<String>(8);
    let (ptt_out_tx, ptt_out) = mpsc::channel::<bool>(8);
    let (audio_in_tx, mut audio_in_rx) = mpsc::channel::<OpusFrame>(64);
    let (msg_in_tx, mut msg_in_rx) = mpsc::channel::<String>(8);
    let (events_in_tx, mut events_in_rx) = mpsc::channel::<CallEvent>(16);
    let (hangup_tx, hangup) = mpsc::channel::<()>(1);
    let stats = std::sync::Arc::new(CallStats::default());

    let io = CallIo {
        audio_out,
        msg_out,
        ptt_out,
        audio_in: audio_in_tx,
        msg_in: msg_in_tx,
        events_in: events_in_tx,
        stats: stats.clone(),
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
    // Reflect the actual PTT gesture (hold vs tap) in the footer hint.
    screen.ptt_hold = tui.keyboard_enhanced();
    let mut ui = tui.spawn(screen.clone());

    // Outbound capture pump task handle; present only while PTT is held.
    let mut capture_task: Option<tokio::task::JoinHandle<()>> = None;

    // Periodic refresh of the live byte counters onto the call screen.
    let mut stats_tick = tokio::time::interval(std::time::Duration::from_millis(500));
    stats_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                                    // Tell the peer we started talking.
                                    let _ = ptt_out_tx.send(true).await;
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
                        // Tell the peer we stopped.
                        let _ = ptt_out_tx.send(false).await;
                    }
                    Some(UiEvent::SendText(text)) => {
                        // Sending ends compose mode; clear the input line.
                        screen.composing = false;
                        screen.compose_buffer.clear();
                        screen.messages.push(format!("you : {text}"));
                        if screen.messages.len() > 100 {
                            screen.messages.remove(0);
                        }
                        ui.render(screen.clone());
                        let _ = msg_out_tx.send(text).await;
                    }
                    Some(UiEvent::Compose(state)) => {
                        // Live compose feedback: paint the in-progress line (or
                        // clear it when compose ends).
                        match state {
                            Some(buf) => {
                                screen.composing = true;
                                screen.compose_buffer = buf;
                            }
                            None => {
                                screen.composing = false;
                                screen.compose_buffer.clear();
                            }
                        }
                        ui.render(screen.clone());
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
            ev = events_in_rx.recv() => {
                if let Some(CallEvent::RemotePtt(on)) = ev {
                    // Live remote talking indicator.
                    screen.remote_ptt = on;
                    ui.render(screen.clone());
                }
            }
            _ = stats_tick.tick() => {
                // Refresh the live byte counters a couple times a second.
                use std::sync::atomic::Ordering;
                let sent = stats.bytes_sent.load(Ordering::Relaxed);
                let recv = stats.bytes_recv.load(Ordering::Relaxed);
                if sent != screen.bytes_sent || recv != screen.bytes_recv {
                    screen.bytes_sent = sent;
                    screen.bytes_recv = recv;
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
        ptt_out,
        audio_in,
        msg_in,
        events_in,
        stats,
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
        events_in,
        stats.clone(),
        ctrl_tx.clone(),
    );
    let send_fut = send_loop(
        writer, keys, send_dir, audio_out, msg_out, ptt_out, stats, hangup, ctrl_rx,
    );

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
#[allow(clippy::too_many_arguments)]
async fn recv_loop<R>(
    mut reader: R,
    keys: std::sync::Arc<CallKeys>,
    recv_dir: Direction,
    audio_in: mpsc::Sender<OpusFrame>,
    msg_in: mpsc::Sender<String>,
    events_in: mpsc::Sender<CallEvent>,
    stats: std::sync::Arc<CallStats>,
    ctrl_tx: mpsc::Sender<ControlOut>,
) -> Result<()>
where
    R: futures::AsyncRead + Unpin,
{
    use std::sync::atomic::Ordering;
    loop {
        let frame = match proto::read_frame(&mut reader).await {
            Ok(f) => f,
            // A clean close or a broken pipe both mean the call is over.
            Err(Error::Closed) => return Ok(()),
            Err(Error::Io(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        stats
            .bytes_recv
            .fetch_add(frame.wire_len() as u64, Ordering::Relaxed);
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
            Frame::Msg { seq, sealed } => {
                // MSG shares the per-direction replay window with AUDIO, so it
                // carries its own sequence (a real `Frame::Msg` field, drawn from
                // the same monotonic counter) rather than reusing seq 0 that an
                // earlier AUDIO frame would already have consumed.
                let aad = [FrameTag::Msg as u8];
                match keys.open(recv_dir, seq, &aad, &sealed) {
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
            // Control frames are sealed too: authenticate (open) each before
            // acting, so an attacker without the PSK cannot inject a HANGUP to
            // drop the call or spoof the remote PTT indicator (SPEC §5.3).
            Frame::Ping { seq, sealed } => {
                if keys
                    .open(recv_dir, seq, &[FrameTag::Ping as u8], &sealed)
                    .is_ok()
                {
                    let _ = ctrl_tx.send(ControlOut::Pong).await;
                } else {
                    tracing::debug!(seq, "dropping unauthentic/replayed PING");
                }
            }
            Frame::Hangup { seq, sealed } => {
                if keys
                    .open(recv_dir, seq, &[FrameTag::Hangup as u8], &sealed)
                    .is_ok()
                {
                    return Ok(());
                }
                tracing::debug!(seq, "dropping unauthentic HANGUP (call continues)");
            }
            Frame::PttStart { seq, sealed } => {
                if keys
                    .open(recv_dir, seq, &[FrameTag::PttStart as u8], &sealed)
                    .is_ok()
                {
                    let _ = events_in.send(CallEvent::RemotePtt(true)).await;
                } else {
                    tracing::debug!(seq, "dropping unauthentic/replayed PTT_START");
                }
            }
            Frame::PttStop { seq, sealed } => {
                if keys
                    .open(recv_dir, seq, &[FrameTag::PttStop as u8], &sealed)
                    .is_ok()
                {
                    let _ = events_in.send(CallEvent::RemotePtt(false)).await;
                } else {
                    tracing::debug!(seq, "dropping unauthentic/replayed PTT_STOP");
                }
            }
            Frame::Pong { seq, sealed } => {
                // Authenticate the keepalive ack; nothing else to do with it.
                let _ = keys.open(recv_dir, seq, &[FrameTag::Pong as u8], &sealed);
            }
            Frame::Cipher { .. } => {
                // Mid-call AEAD renegotiation is not yet acted on.
            }
            Frame::Hello(_) => {
                return Err(Error::Proto("unexpected HELLO after handshake".into()));
            }
        }
    }
}

/// Seal and write outbound frames as they are produced. Returns `Ok(())` when
/// the user requests hangup or the capture/msg sources close.
#[allow(clippy::too_many_arguments)]
async fn send_loop<W>(
    mut writer: W,
    keys: std::sync::Arc<CallKeys>,
    send_dir: Direction,
    mut audio_out: mpsc::Receiver<OpusFrame>,
    mut msg_out: mpsc::Receiver<String>,
    mut ptt_out: mpsc::Receiver<bool>,
    stats: std::sync::Arc<CallStats>,
    mut hangup: mpsc::Receiver<()>,
    mut ctrl_rx: mpsc::Receiver<ControlOut>,
) -> Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    let mut send_seq: u64 = 0;
    // Stops polling the PTT channel once the UI side closes it, so a closed
    // channel doesn't spin the select with immediate `None`s.
    let mut ptt_open = true;
    loop {
        tokio::select! {
            biased;

            _ = hangup.recv() => {
                let seq = next(&mut send_seq);
                let sealed = keys.seal(send_dir, seq, &[FrameTag::Hangup as u8], &[]);
                let _ = write_counted(&mut writer, &stats, Frame::Hangup { seq, sealed }).await;
                return Ok(());
            }

            maybe = audio_out.recv() => {
                match maybe {
                    Some(frame) => {
                        let seq = next(&mut send_seq);
                        let sealed = keys.seal(send_dir, seq, &[FrameTag::Audio as u8], &frame.data);
                        write_counted(&mut writer, &stats, Frame::Audio { seq, sealed }).await?;
                    }
                    None => {
                        let seq = next(&mut send_seq);
                        let sealed = keys.seal(send_dir, seq, &[FrameTag::Hangup as u8], &[]);
                        let _ = write_counted(&mut writer, &stats, Frame::Hangup { seq, sealed }).await;
                        return Ok(());
                    }
                }
            }

            maybe = msg_out.recv() => {
                if let Some(text) = maybe {
                    // Draw from the shared monotonic counter so MSG and AUDIO
                    // never collide in the receiver's replay window. The seq is a
                    // real `Frame::Msg` field carried on the wire (proto encodes
                    // it as an 8-byte prefix, exactly like AUDIO).
                    let seq = next(&mut send_seq);
                    let sealed = keys.seal(send_dir, seq, &[FrameTag::Msg as u8], text.as_bytes());
                    write_counted(&mut writer, &stats, Frame::Msg { seq, sealed }).await?;
                }
            }

            maybe = ptt_out.recv(), if ptt_open => {
                match maybe {
                    // `true` = started talking, `false` = stopped. Sealed (empty
                    // body) so the peer authenticates the indicator transition.
                    Some(talking) => {
                        let seq = next(&mut send_seq);
                        let frame = if talking {
                            let sealed = keys.seal(send_dir, seq, &[FrameTag::PttStart as u8], &[]);
                            Frame::PttStart { seq, sealed }
                        } else {
                            let sealed = keys.seal(send_dir, seq, &[FrameTag::PttStop as u8], &[]);
                            Frame::PttStop { seq, sealed }
                        };
                        write_counted(&mut writer, &stats, frame).await?;
                    }
                    None => ptt_open = false,
                }
            }

            maybe = ctrl_rx.recv() => {
                if let Some(ControlOut::Pong) = maybe {
                    let seq = next(&mut send_seq);
                    let sealed = keys.seal(send_dir, seq, &[FrameTag::Pong as u8], &[]);
                    write_counted(&mut writer, &stats, Frame::Pong { seq, sealed }).await?;
                }
            }
        }
    }
}

/// Write a frame and credit its wire size to `bytes_sent`.
async fn write_counted<W>(writer: &mut W, stats: &CallStats, frame: Frame) -> Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    proto::write_frame(writer, &frame).await?;
    stats.bytes_sent.fetch_add(
        frame.wire_len() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(())
}

/// Frame-type tag bound into the AEAD AAD so a frame sealed as one type cannot be
/// reinterpreted as another (matches `FrameType` wire ids; SPEC §5.2/§5.3).
#[derive(Clone, Copy)]
#[repr(u8)]
enum FrameTag {
    Audio = 0x02,
    Msg = 0x03,
    PttStart = 0x04,
    PttStop = 0x05,
    Ping = 0x06,
    Pong = 0x07,
    Hangup = 0x08,
}

/// Allocate the next outbound sequence and advance the counter.
fn next(seq: &mut u64) -> u64 {
    let s = *seq;
    *seq = seq.wrapping_add(1);
    s
}
