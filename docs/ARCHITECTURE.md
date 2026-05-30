# TerminalPhone v2 — Architecture

Companion to `SPEC.md`. This is the **how** (module layout, boundaries, data
flow); the spec is the **what/why**.

## Runtime shape

Single binary crate, **Tokio** async runtime. arti runs in-process on Tokio.
Audio is inherently callback/thread-driven (cpal fires on an OS audio thread), so
the audio subsystem owns dedicated threads and bridges to the async core via
bounded channels. Crypto is synchronous and cheap (microseconds) — called inline.

```
                ┌──────────────────────────────────────────────┐
                │                   app (state machine)         │
                │   Idle ─ Hosting ─ Dialing ─ InCall ─ Hangup  │
                └───────┬───────────────┬───────────────┬───────┘
                        │               │               │
              ┌─────────▼──────┐ ┌──────▼──────┐ ┌──────▼───────┐
              │   transport    │ │    proto    │ │    audio     │
              │ (Transport tr) │ │ frame codec │ │ capture/codec│
              │   arti impl    │ │ + handshake │ │  /playback   │
              └─────────┬──────┘ └──────┬──────┘ └──────┬───────┘
                        │               │               │
                        └──────► crypto (HKDF + AEAD) ◄──┘
```

## Module layout

```
src/
  main.rs            CLI parse, data-dir resolution, runtime + crypto-provider init, launch app
  app.rs             top-level orchestration; call state machine; wires subsystems
  config.rs          TOML load/save; data-dir paths; defaults
  error.rs           crate Error enum (thiserror); Result alias

  transport/
    mod.rs           Transport trait: bootstrap, host(identity) -> Incoming, dial(onion) -> Conn
    arti.rs          arti impl (onion service hosting + dialing); identity key persistence;
                     hop/speed config; keepalive; warm-bootstrap
  proto.rs           wire frame enum + length-prefixed codec; HELLO handshake; seq/AAD binding

  crypto.rs          PSK load/gen; passphrase-at-rest (Argon2id); HKDF per-call key;
                     AeadSuite (AES-256-GCM | ChaCha20-Poly1305); seal/open; nonce counters

  audio/
    mod.rs           AudioEngine: owns threads; exposes async send/recv of PCM frames
    capture.rs       cpal input + resample to opus rate; PTT-gated frame production
    codec.rs         audiopus encode/decode; opus param config
    playback.rs      cpal output + jitter buffer; smooth playout

  tui.rs             raw-mode PTT input; call screen render; menus
```

## Key boundaries

### `Transport` trait — the arti firewall
All Tor knowledge lives behind one trait. This is deliberate insurance: if arti's
onion-service *hosting* ever regresses, a `SystemTorTransport` (spawn `tor`, talk
SOCKS) drops in without touching crypto/audio/proto. M1 ships only `ArtiTransport`.

```rust
trait Transport {
    async fn bootstrap(cfg: &TorConfig) -> Result<Self>;
    async fn host(&self, id: &Identity) -> Result<Incoming>;   // stream of inbound Conn
    async fn dial(&self, onion: &OnionAddr) -> Result<Conn>;   // one outbound Conn
}
// Conn: AsyncRead + AsyncWrite (the onion DataStream), framed by proto.rs
```

### `proto` — the only thing that touches the wire
Owns the frame format (§5.3 of SPEC). Exposes a typed `Frame` enum and a
codec (`tokio_util::codec`-style) over a `Conn`. The handshake (`HELLO` exchange,
nonce swap) lives here and hands a derived-key context to `crypto`.

### `crypto` — stateless seal/open + a per-call key context
No I/O. Given the call key (from HKDF over the two HELLO nonces) it seals/opens
frames with a per-direction counter. Reused identically on both call sides.

### `audio` — threads behind an async facade
`AudioEngine::capture()` yields sealed-ready Opus frames while PTT is held;
`AudioEngine::play(frame)` enqueues into the jitter buffer. The app never touches
cpal directly.

## Data flow: one PTT press

1. TUI detects PTT-down → `app` sends `PTT_START`, tells `audio` to capture.
2. `capture` produces Opus frames → `app` seals each via `crypto` → `proto`
   writes `AUDIO` frames to the `Conn` **as they arrive** (pipelined).
3. Peer's `proto` reads frames → `crypto` opens → `audio` playback jitter buffer
   → speaker, starting after the configured lead.
4. PTT-up → `PTT_STOP` flushes the utterance.

## Error & shutdown
- `error.rs` centralizes errors (`thiserror`); user-facing messages are explicit
  (esp. cipher mismatch, bootstrap failure, dial failure).
- Graceful `HANGUP` on both sides; `Drop` guarantees circuit teardown and
  zeroization of key material (`zeroize`).

## Testing strategy
- Unit: crypto vectors (seal/open round-trip, replay rejection, nonce uniqueness);
  proto codec round-trip; HKDF determinism across two sides.
- Integration: in-process loopback `Transport` mock (no Tor) for the full
  audio→proto→crypto→proto→audio path.
- E2E: two real instances over Tor (the M0 spike, promoted to a harness).
- CI matrix: macOS + Linux; `fmt`, `clippy -D warnings`, `test`.
