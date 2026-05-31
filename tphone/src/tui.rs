//! Raw-mode push-to-talk input loop and call-screen render (SPEC §5.5, crossterm).
//!
//! Terminal raw mode for PTT (no root). Two halves the app drives:
//!
//!   * an **input loop** ([`Tui::spawn`]) that reads crossterm key events on a
//!     blocking reader thread, maps them to [`UiEvent`]s with a small pure state
//!     machine ([`map_key`]), and forwards them over an async channel the call
//!     loop selects on. The configured PTT key press/hold/release becomes
//!     [`UiEvent::PttStart`]/[`UiEvent::PttStop`]; `t` opens a text-compose line
//!     that emits [`UiEvent::SendText`] on Enter; `q`/Ctrl-C become
//!     [`UiEvent::Hangup`].
//!   * a **renderer** ([`Tui::render`]) the app calls on every state change. It
//!     paints a fixed header (local + remote `.onion`, AEAD suite-match
//!     indicator, hop/anonymity mode, remote PTT state, ms/byte stats) and a
//!     scrolling chat/status area, flicker-free via absolute cursor positioning
//!     into the alt-screen.
//!
//! Terminal lifecycle is RAII: [`Tui::enter`] switches into raw mode + the
//! alternate screen and installs a panic hook; [`Drop`] (and the hook) restore
//! the terminal so a crash never leaves it wedged.

use std::io::Write as _;
use std::sync::Once;
use std::time::Duration;

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
    supports_keyboard_enhancement,
};
use crossterm::{execute, queue};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::proto::PeerInfo;

/// A UI intent surfaced to the app's call loop (the receive side of [`UiHandle`]).
///
/// These are the only inputs the call loop needs from the terminal: gate capture
/// on/off, send a text message, or hang up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiEvent {
    /// PTT key pressed (or, on terminals without key-release, a momentary press) —
    /// the app should begin capture and signal PTT-start to the peer.
    PttStart,
    /// PTT key released — the app should stop capture and flush the utterance.
    PttStop,
    /// The user composed and submitted a text line; seal + send it as `MSG`.
    SendText(String),
    /// The compose line changed: `Some(buffer)` while typing (the app should
    /// paint the in-progress line), `None` once compose mode ends. Carries the
    /// live buffer so the screen reflects each keystroke — without this the
    /// reader thread's compose state would be invisible until Enter.
    Compose(Option<String>),
    /// The user requested a graceful hangup (`q` / Ctrl-C).
    Hangup,
}

/// Compose-mode state threaded through [`map_key`]. Kept tiny and `Clone` so the
/// mapping stays a pure function of `(state, key) -> (state, events)` and is
/// trivially unit-testable without a terminal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputState {
    /// `Some(buffer)` while the user is typing a text line (after pressing the
    /// compose key); `None` in normal PTT mode.
    compose: Option<String>,
    /// Transmit state for *toggle* PTT (terminals that cannot report key
    /// release): each PTT-key press flips this. Unused in hold-to-talk mode.
    talking: bool,
}

impl InputState {
    /// A fresh state in normal (PTT) mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the user is currently composing a text line.
    pub fn composing(&self) -> bool {
        self.compose.is_some()
    }

    /// The in-progress compose buffer, if any (for rendering the input line).
    pub fn compose_buffer(&self) -> Option<&str> {
        self.compose.as_deref()
    }
}

/// Map one decoded key event to zero or more [`UiEvent`]s, mutating the compose
/// state machine. Pure (no I/O) so it can be exhaustively unit-tested.
///
/// Behavior:
///   * **Normal mode**: the configured `ptt_key` press → [`UiEvent::PttStart`],
///     release → [`UiEvent::PttStop`]; `t`/`T` enters compose mode; `q` or Ctrl-C
///     → [`UiEvent::Hangup`].
///   * **Compose mode**: printable chars append; Backspace deletes; Enter emits
///     [`UiEvent::SendText`] (dropping an empty line) and exits compose; Esc
///     cancels; Ctrl-C still → [`UiEvent::Hangup`]. PTT is intentionally inert
///     while composing so spaces type into the message.
///
/// Key *release* events are ignored except for the PTT key (so a held PTT key is
/// not mistaken for a quit on key-up).
///
/// `hold_ptt` selects the PTT model: `true` when the terminal reports key-release
/// events (kitty keyboard protocol — hold-to-talk), `false` otherwise, where we
/// fall back to tap-to-toggle since no release will ever arrive.
pub fn map_key(
    state: &mut InputState,
    ptt_key: char,
    hold_ptt: bool,
    code: KeyCode,
    modifiers: KeyModifiers,
    kind: KeyEventKind,
) -> Vec<UiEvent> {
    // Ctrl-C is an unconditional hangup in any mode, on press.
    if kind != KeyEventKind::Release
        && matches!(code, KeyCode::Char('c'))
        && modifiers.contains(KeyModifiers::CONTROL)
    {
        return vec![UiEvent::Hangup];
    }

    if state.compose.is_some() {
        return map_key_compose(state, code, kind);
    }
    map_key_normal(state, ptt_key, hold_ptt, code, kind)
}

/// Key mapping in normal (PTT) mode.
fn map_key_normal(
    state: &mut InputState,
    ptt_key: char,
    hold_ptt: bool,
    code: KeyCode,
    kind: KeyEventKind,
) -> Vec<UiEvent> {
    if let KeyCode::Char(c) = code
        && c == ptt_key
    {
        if hold_ptt {
            // Hold-to-talk: press → start, release → stop. Auto-repeat (a held
            // key) is ignored so it does not thrash the capture pump.
            return match kind {
                KeyEventKind::Release => vec![UiEvent::PttStop],
                KeyEventKind::Press => vec![UiEvent::PttStart],
                KeyEventKind::Repeat => Vec::new(),
            };
        }
        // No key-release available (legacy terminals): tap-to-toggle. Only a
        // real press flips state; release never arrives and auto-repeat (also
        // reported as Press on legacy terminals) would thrash — but a deliberate
        // tap is the documented gesture here.
        if kind != KeyEventKind::Press {
            return Vec::new();
        }
        state.talking = !state.talking;
        return if state.talking {
            vec![UiEvent::PttStart]
        } else {
            vec![UiEvent::PttStop]
        };
    }

    // All remaining handlers are press-only.
    if kind == KeyEventKind::Release {
        return Vec::new();
    }

    match code {
        // Enter compose mode; the PTT key itself can't double as compose.
        KeyCode::Char('t') | KeyCode::Char('T') if ptt_key != 't' && ptt_key != 'T' => {
            state.compose = Some(String::new());
            vec![UiEvent::Compose(Some(String::new()))]
        }
        KeyCode::Char('q') => vec![UiEvent::Hangup],
        _ => Vec::new(),
    }
}

/// Key mapping while composing a text line.
fn map_key_compose(state: &mut InputState, code: KeyCode, kind: KeyEventKind) -> Vec<UiEvent> {
    if kind == KeyEventKind::Release {
        return Vec::new();
    }
    let buf = state
        .compose
        .as_mut()
        .expect("map_key_compose called outside compose mode");
    match code {
        KeyCode::Char(c) => {
            buf.push(c);
            vec![UiEvent::Compose(Some(buf.clone()))]
        }
        KeyCode::Backspace => {
            buf.pop();
            vec![UiEvent::Compose(Some(buf.clone()))]
        }
        KeyCode::Enter => {
            let text = state.compose.take().unwrap_or_default();
            if text.is_empty() {
                // Empty line: just leave compose mode (no message sent).
                vec![UiEvent::Compose(None)]
            } else {
                // SendText implies compose has ended; the app clears the line.
                vec![UiEvent::SendText(text)]
            }
        }
        KeyCode::Esc => {
            state.compose = None;
            vec![UiEvent::Compose(None)]
        }
        _ => Vec::new(),
    }
}

/// A render snapshot the app pushes to the TUI on every state change.
///
/// All fields are owned/Copy so a snapshot can cross the render channel without
/// borrowing the app's live call state.
#[derive(Debug, Clone)]
pub struct CallScreen {
    /// Our own onion address (local identity).
    pub local_onion: String,
    /// The peer's onion address (from their HELLO).
    pub remote_onion: String,
    /// `true` when our suite matched the peer's (always true post-handshake, but
    /// surfaced for the indicator).
    pub suite_match: bool,
    /// Human label of the negotiated AEAD suite (e.g. "AES-256-GCM").
    pub suite_label: String,
    /// Human label of the hop / anonymity mode (e.g. "anon 3+3", "speed 1+3").
    pub hop_mode: String,
    /// Whether the remote is currently transmitting (their PTT held).
    pub remote_ptt: bool,
    /// Whether *we* are currently transmitting (local PTT held).
    pub local_ptt: bool,
    /// One-way latency estimate in ms (0 until measured).
    pub latency_ms: u32,
    /// Bytes sent so far this call.
    pub bytes_sent: u64,
    /// Bytes received so far this call.
    pub bytes_recv: u64,
    /// Whether the user is composing a text line (drives the input prompt).
    pub composing: bool,
    /// The in-progress compose buffer (shown after the prompt).
    pub compose_buffer: String,
    /// Whether PTT is hold-to-talk (`true`, terminal reports key-release) or
    /// tap-to-toggle (`false`). Drives the footer hint so the gesture matches.
    pub ptt_hold: bool,
    /// Recent messages in the call (one per line, newest last). Truncated to fit screen.
    pub messages: Vec<String>,
}

impl Default for CallScreen {
    fn default() -> Self {
        CallScreen {
            local_onion: String::new(),
            remote_onion: String::new(),
            suite_match: true,
            suite_label: String::new(),
            hop_mode: String::new(),
            remote_ptt: false,
            local_ptt: false,
            latency_ms: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            composing: false,
            compose_buffer: String::new(),
            ptt_hold: true,
            messages: Vec::new(),
        }
    }
}

impl CallScreen {
    /// Seed a screen from the handshake [`PeerInfo`] and the local config, filling
    /// the static header fields. Stats/PTT/compose start at their defaults and are
    /// updated by the app over the life of the call.
    pub fn from_peer(cfg: &Config, local_onion: &str, peer: &PeerInfo) -> Self {
        CallScreen {
            local_onion: local_onion.to_string(),
            remote_onion: peer.onion.host().to_string(),
            suite_match: cfg.aead_suite == peer.suite,
            suite_label: suite_label(peer.suite),
            hop_mode: hop_mode_label(cfg),
            ..Default::default()
        }
    }
}

/// Human-readable AEAD suite label for the header.
fn suite_label(suite: crate::crypto::AeadSuite) -> String {
    match suite {
        crate::crypto::AeadSuite::Aes256Gcm => "AES-256-GCM".to_string(),
        crate::crypto::AeadSuite::ChaCha20Poly1305 => "ChaCha20-Poly1305".to_string(),
    }
}

/// Human-readable hop / anonymity posture label from config (SPEC §5.1, ADR-0005).
fn hop_mode_label(cfg: &Config) -> String {
    use crate::config::SpeedMode;
    match cfg.speed_mode {
        SpeedMode::FullAnonymity => "full anonymity (3+3)".to_string(),
        SpeedMode::SpeedFirst => "speed-first (reduced hops)".to_string(),
        SpeedMode::SingleHopService => "single-hop service (IP-revealing!)".to_string(),
    }
}

/// Handle the app uses to drive the TUI: receive [`UiEvent`]s and push render
/// snapshots. Returned by [`Tui::spawn`].
///
/// Dropping the handle does not stop the input thread on its own; call
/// [`UiHandle::shutdown`] (or drop the owning [`Tui`]) to tear the terminal down.
pub struct UiHandle {
    /// Inbound UI events from the key reader thread.
    events: mpsc::Receiver<UiEvent>,
    /// Outbound render snapshots to the terminal (drained by the render task).
    renders: mpsc::Sender<CallScreen>,
    /// Set on shutdown so the reader thread can observe the request between polls.
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl UiHandle {
    /// Await the next [`UiEvent`], or `None` once the input loop has ended.
    pub async fn next_event(&mut self) -> Option<UiEvent> {
        self.events.recv().await
    }

    /// Push a new render snapshot; the screen repaints on the render task. A
    /// closed channel (terminal torn down) is ignored.
    pub fn render(&self, screen: CallScreen) {
        let _ = self.renders.try_send(screen);
    }

    /// Request the input loop to stop at its next poll boundary.
    pub fn shutdown(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Owns the terminal raw-mode + alt-screen session for the duration of a call and
/// the background tasks that read keys and repaint the screen.
pub struct Tui {
    /// The configured PTT key.
    ptt_key: char,
    /// `true` when the terminal supports the kitty keyboard protocol (key-release
    /// reporting was pushed in [`Tui::enter`]). Enables hold-to-talk PTT and must
    /// be popped on restore.
    keyboard_enhanced: bool,
    /// `true` while raw mode + alt-screen are active (so `Drop` restores once).
    active: bool,
    /// Stop flag shared with the reader thread (also held by [`UiHandle`]).
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Join handle for the blocking key-reader thread (joined on `Drop`).
    reader: Option<std::thread::JoinHandle<()>>,
}

/// Ensures the terminal-restoring panic hook is installed at most once.
static PANIC_HOOK: Once = Once::new();

impl Tui {
    /// Enter raw mode + the alternate screen and install the restore-on-panic
    /// hook. The returned guard restores the terminal on drop.
    pub fn enter(cfg: &Config) -> Result<Self> {
        install_panic_hook();
        enable_raw_mode().map_err(|e| Error::Io(std::io::Error::other(e)))?;
        let mut out = std::io::stdout();
        execute!(out, EnterAlternateScreen, EnableBracketedPaste, Hide)
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;
        // Request key-release/repeat reporting where the terminal speaks the
        // kitty keyboard protocol (Ghostty, kitty, foot, WezTerm…). This is what
        // makes hold-to-talk PTT possible. Terminals without it (Terminal.app,
        // iTerm2) report only key-press, so we leave the flag off and the input
        // loop falls back to tap-to-toggle PTT.
        let keyboard_enhanced = supports_keyboard_enhancement().unwrap_or(false);
        if keyboard_enhanced {
            let _ = execute!(
                out,
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::REPORT_EVENT_TYPES)
            );
        }
        Ok(Tui {
            ptt_key: cfg.ptt_key,
            keyboard_enhanced,
            active: true,
            stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reader: None,
        })
    }

    /// Whether hold-to-talk PTT is available (the terminal reports key-release).
    /// `false` means the input loop uses tap-to-toggle PTT instead.
    pub fn keyboard_enhanced(&self) -> bool {
        self.keyboard_enhanced
    }

    /// Start the background input loop and render task, returning a [`UiHandle`]
    /// the app selects on. Consumes the terminal-reading responsibility; the
    /// [`Tui`] guard is retained by the caller purely for its `Drop` lifecycle.
    ///
    /// `initial` seeds the first paint so the header is visible before any event.
    pub fn spawn(&mut self, initial: CallScreen) -> UiHandle {
        let (ev_tx, ev_rx) = mpsc::channel::<UiEvent>(64);
        let (rd_tx, mut rd_rx) = mpsc::channel::<CallScreen>(8);

        // Render task: paint `initial`, then repaint on each pushed snapshot. This
        // runs on the tokio runtime; the actual writes are quick and infrequent
        // (one per state change), so they do not contend with the audio path.
        let _ = render_screen(&initial);
        tokio::spawn(async move {
            while let Some(screen) = rd_rx.recv().await {
                let _ = render_screen(&screen);
            }
        });

        // Key-reader thread: crossterm's `event::read` is blocking, so it lives on
        // its own OS thread and forwards mapped events over the async channel. It
        // polls with a short timeout so the stop flag is observed promptly.
        let ptt_key = self.ptt_key;
        let hold_ptt = self.keyboard_enhanced;
        let stop = self.stop.clone();
        let reader_stop = stop.clone();
        let handle = std::thread::spawn(move || {
            reader_loop(ptt_key, hold_ptt, ev_tx, reader_stop);
        });
        self.reader = Some(handle);

        UiHandle {
            events: ev_rx,
            renders: rd_tx,
            stop,
        }
    }

    /// Render `screen` synchronously (used by tests / callers that drive the paint
    /// themselves rather than via the render task).
    pub fn render(&mut self, screen: &CallScreen) -> Result<()> {
        render_screen(screen)
    }

    /// Restore the terminal now (idempotent). Also invoked by `Drop`.
    fn restore(&mut self) {
        if self.active {
            self.active = false;
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut out = std::io::stdout();
            if self.keyboard_enhanced {
                let _ = execute!(out, PopKeyboardEnhancementFlags);
            }
            let _ = execute!(out, Show, DisableBracketedPaste, LeaveAlternateScreen);
            let _ = disable_raw_mode();
        }
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.restore();
    }
}

/// The blocking key-reader loop run on a dedicated thread. Polls crossterm with a
/// short timeout, maps each key via the pure [`map_key`] state machine, and sends
/// the resulting events. Exits when the stop flag is set, on `Hangup`, or when the
/// receiver is dropped.
fn reader_loop(
    ptt_key: char,
    hold_ptt: bool,
    tx: mpsc::Sender<UiEvent>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut state = InputState::new();
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        match event::poll(Duration::from_millis(50)) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => break,
        }
        let Ok(Event::Key(KeyEvent {
            code,
            modifiers,
            kind,
            ..
        })) = event::read()
        else {
            continue;
        };
        for ev in map_key(&mut state, ptt_key, hold_ptt, code, modifiers, kind) {
            let hangup = ev == UiEvent::Hangup;
            // `blocking_send` cannot be used from here without a runtime guarantee;
            // `try_send` drops on a momentarily-full channel, which is acceptable
            // for PTT edges (the next edge corrects state) and never for Hangup —
            // so retry Hangup briefly to ensure it lands.
            if hangup {
                let mut sent = false;
                for _ in 0..20 {
                    if tx.try_send(UiEvent::Hangup).is_ok() {
                        sent = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = sent;
                return;
            }
            let _ = tx.try_send(ev);
        }
    }
}

/// Paint the full call screen into the alt-screen with absolute cursor moves so
/// each repaint overwrites the previous frame in place (flicker-free).
fn render_screen(s: &CallScreen) -> Result<()> {
    let mut out = std::io::stdout();
    // Map a crossterm error into our IO error variant.
    let io = |e: std::io::Error| Error::Io(e);

    queue!(out, MoveTo(0, 0), Clear(ClearType::All)).map_err(|e| io(std::io::Error::other(e)))?;

    let suite_ind = if s.suite_match { "OK" } else { "MISMATCH" };
    let header = [
        "TerminalPhone — secure push-to-talk".to_string(),
        format!("you   : {}", s.local_onion),
        format!("peer  : {}", s.remote_onion),
        format!(
            "cipher: {} [{}]   hops: {}",
            s.suite_label, suite_ind, s.hop_mode
        ),
        format!(
            "stats : {} ms   tx {}   rx {}",
            s.latency_ms,
            human_bytes(s.bytes_sent),
            human_bytes(s.bytes_recv),
        ),
        format!(
            "ptt   : local {}   remote {}",
            if s.local_ptt { "[REC]" } else { " --- " },
            if s.remote_ptt {
                "[RECORDING]"
            } else {
                "  idle     "
            },
        ),
        "─".repeat(60),
    ];
    for (row, line) in header.iter().enumerate() {
        queue!(out, MoveTo(0, row as u16), crossterm::style::Print(line))
            .map_err(|e| io(std::io::Error::other(e)))?;
    }

    // Message area: display recent messages between header and footer.
    // Reserve 2 rows for footer (footer + blank line).
    let header_end = header.len() as u16;
    let footer_row = if let Ok((_, height)) = crossterm::terminal::size() {
        if height > 10 { height - 2 } else { header_end + 2 }
    } else {
        header_end + 5
    };

    let msg_rows = if footer_row > header_end + 1 {
        (footer_row - header_end - 2) as usize
    } else {
        0
    };

    // Display the most recent messages that fit on screen.
    if msg_rows > 0 && !s.messages.is_empty() {
        let start_msg = s.messages.len().saturating_sub(msg_rows);
        for (offset, msg) in s.messages[start_msg..].iter().enumerate() {
            let row = header_end + 1 + offset as u16;
            let truncated = if msg.len() > 78 {
                format!("{}…", &msg[..75])
            } else {
                msg.clone()
            };
            queue!(out, MoveTo(0, row), crossterm::style::Print(&truncated))
                .map_err(|e| io(std::io::Error::other(e)))?;
        }
    }

    // Footer: either the compose line or the key hints. The PTT hint matches the
    // active gesture so users on legacy terminals know to tap rather than hold.
    let footer = if s.composing {
        format!("msg> {}", s.compose_buffer)
    } else if s.ptt_hold {
        "[hold PTT key = talk]   [t = text]   [q / Ctrl-C = hangup]".to_string()
    } else {
        "[tap PTT key = talk on/off]   [t = text]   [q / Ctrl-C = hangup]".to_string()
    };
    queue!(out, MoveTo(0, footer_row), crossterm::style::Print(footer))
        .map_err(|e| io(std::io::Error::other(e)))?;

    out.flush().map_err(Error::Io)?;
    Ok(())
}

/// Compact human-readable byte count for the stats line.
fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

/// Install a panic hook (once) that restores the terminal before the default hook
/// prints the panic, so a crash mid-call never leaves the terminal in raw/alt
/// mode.
fn install_panic_hook() {
    PANIC_HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let mut out = std::io::stdout();
            // Best-effort: pop keyboard enhancement (harmless if never pushed)
            // before restoring the screen so a panic never wedges the terminal.
            let _ = execute!(out, PopKeyboardEnhancementFlags);
            let _ = execute!(out, Show, DisableBracketedPaste, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            default(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const PTT: char = ' ';

    fn press(c: char) -> (KeyCode, KeyModifiers, KeyEventKind) {
        (KeyCode::Char(c), KeyModifiers::NONE, KeyEventKind::Press)
    }
    fn release(c: char) -> (KeyCode, KeyModifiers, KeyEventKind) {
        (KeyCode::Char(c), KeyModifiers::NONE, KeyEventKind::Release)
    }

    // Most tests exercise hold-to-talk semantics (terminal reports key-release).
    const HOLD: bool = true;
    const TOGGLE: bool = false;

    fn feed(
        state: &mut InputState,
        ptt: char,
        hold_ptt: bool,
        (code, m, kind): (KeyCode, KeyModifiers, KeyEventKind),
    ) -> Vec<UiEvent> {
        map_key(state, ptt, hold_ptt, code, m, kind)
    }

    #[test]
    fn ptt_press_and_release_maps_to_start_stop() {
        let mut st = InputState::new();
        assert_eq!(feed(&mut st, PTT, HOLD, press(' ')), vec![UiEvent::PttStart]);
        assert_eq!(feed(&mut st, PTT, HOLD, release(' ')), vec![UiEvent::PttStop]);
    }

    #[test]
    fn ptt_hold_ignores_auto_repeat() {
        let mut st = InputState::new();
        let repeat = (KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Repeat);
        assert_eq!(feed(&mut st, PTT, HOLD, press(' ')), vec![UiEvent::PttStart]);
        // A held key auto-repeats; it must not re-trigger capture.
        assert_eq!(feed(&mut st, PTT, HOLD, repeat), Vec::<UiEvent>::new());
        assert_eq!(feed(&mut st, PTT, HOLD, release(' ')), vec![UiEvent::PttStop]);
    }

    #[test]
    fn ptt_toggle_flips_on_each_press() {
        // On terminals without key-release, each press toggles transmit.
        let mut st = InputState::new();
        assert_eq!(
            feed(&mut st, PTT, TOGGLE, press(' ')),
            vec![UiEvent::PttStart]
        );
        // No release is ever delivered; if one were, it is inert.
        assert_eq!(feed(&mut st, PTT, TOGGLE, release(' ')), Vec::<UiEvent>::new());
        assert_eq!(
            feed(&mut st, PTT, TOGGLE, press(' ')),
            vec![UiEvent::PttStop]
        );
        assert_eq!(
            feed(&mut st, PTT, TOGGLE, press(' ')),
            vec![UiEvent::PttStart]
        );
    }

    #[test]
    fn custom_ptt_key_is_honored() {
        let mut st = InputState::new();
        assert_eq!(feed(&mut st, 'x', HOLD, press('x')), vec![UiEvent::PttStart]);
        assert_eq!(feed(&mut st, 'x', HOLD, release('x')), vec![UiEvent::PttStop]);
        // Space is inert when it is not the PTT key.
        assert_eq!(feed(&mut st, 'x', HOLD, press(' ')), Vec::<UiEvent>::new());
    }

    #[test]
    fn q_and_ctrl_c_hang_up() {
        let mut st = InputState::new();
        assert_eq!(feed(&mut st, PTT, HOLD, press('q')), vec![UiEvent::Hangup]);
        let ctrl_c = (
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(feed(&mut st, PTT, HOLD, ctrl_c), vec![UiEvent::Hangup]);
    }

    #[test]
    fn release_of_non_ptt_key_is_ignored() {
        let mut st = InputState::new();
        // A 'q' *release* must not hang up (only press does).
        assert_eq!(feed(&mut st, PTT, HOLD, release('q')), Vec::<UiEvent>::new());
    }

    #[test]
    fn t_enters_compose_and_enter_sends() {
        let mut st = InputState::new();
        // Entering compose emits a Compose(Some("")) so the screen shows the line.
        assert_eq!(
            feed(&mut st, PTT, HOLD, press('t')),
            vec![UiEvent::Compose(Some(String::new()))]
        );
        assert!(st.composing());
        // Each keystroke emits the live buffer so typing is visible.
        let mut typed = String::new();
        for c in "hi there".chars() {
            typed.push(c);
            assert_eq!(
                feed(&mut st, PTT, HOLD, press(c)),
                vec![UiEvent::Compose(Some(typed.clone()))]
            );
        }
        let evs = feed(
            &mut st,
            PTT,
            HOLD,
            (KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Press),
        );
        assert_eq!(evs, vec![UiEvent::SendText("hi there".to_string())]);
        assert!(!st.composing(), "compose mode exits after send");
    }

    #[test]
    fn space_types_into_message_while_composing() {
        let mut st = InputState::new();
        feed(&mut st, PTT, HOLD, press('t'));
        // Space must NOT toggle PTT in compose mode; it appends to the buffer.
        assert_eq!(
            feed(&mut st, PTT, HOLD, press(' ')),
            vec![UiEvent::Compose(Some(" ".to_string()))]
        );
        assert_eq!(st.compose_buffer(), Some(" "));
    }

    #[test]
    fn backspace_and_esc_in_compose() {
        let mut st = InputState::new();
        feed(&mut st, PTT, HOLD, press('t'));
        feed(&mut st, PTT, HOLD, press('a'));
        feed(&mut st, PTT, HOLD, press('b'));
        assert_eq!(
            feed(
                &mut st,
                PTT,
                HOLD,
                (KeyCode::Backspace, KeyModifiers::NONE, KeyEventKind::Press),
            ),
            vec![UiEvent::Compose(Some("a".to_string()))]
        );
        assert_eq!(st.compose_buffer(), Some("a"));
        let evs = feed(
            &mut st,
            PTT,
            HOLD,
            (KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Press),
        );
        assert_eq!(evs, vec![UiEvent::Compose(None)]);
        assert!(!st.composing(), "Esc cancels compose without sending");
    }

    #[test]
    fn empty_message_is_not_sent() {
        let mut st = InputState::new();
        feed(&mut st, PTT, HOLD, press('t'));
        let evs = feed(
            &mut st,
            PTT,
            HOLD,
            (KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Press),
        );
        // Empty line just leaves compose mode; no SendText.
        assert_eq!(evs, vec![UiEvent::Compose(None)]);
        assert!(!st.composing());
    }

    #[test]
    fn ctrl_c_hangs_up_even_while_composing() {
        let mut st = InputState::new();
        feed(&mut st, PTT, HOLD, press('t'));
        let ctrl_c = (
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(feed(&mut st, PTT, HOLD, ctrl_c), vec![UiEvent::Hangup]);
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(3 * 1024 * 1024), "3.0 MiB");
    }
}
