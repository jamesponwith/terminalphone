# TerminalPhone v2 — Roadmap

Milestones with explicit exit criteria. Work items live in beads (`bd ready`,
`bd graph --all`). This file is the human-readable map; beads is the source of
truth for status.

## M0 — arti spike ✅ (done)
Prove in-process onion-service hosting + dialing round-trips bytes.
**Exit:** `rs-spike serve` mints a `.onion`; `rs-spike dial` returns `ROUNDTRIP: OK`. ✔

## M1 — Vertical slice (the core call)
A real, snappy, encrypted PTT call between two instances over Tor.
- Project skeleton (modules, `Transport` trait, error types).
- `ArtiTransport`: host + dial, persisted identity, warm bootstrap.
- `crypto`: HKDF per-call key, AES-256-GCM seal/open, nonce counters, replay window.
- `proto`: frame codec + `HELLO` handshake (nonce swap, suite negotiation).
- `audio`: cpal capture + audiopus encode/decode + jitter-buffer playback.
- Pipelined PTT loop (capture→seal→send while talking; recv→open→decode→play).
- Minimal TUI (host/dial, PTT, call screen).
- **Exit:** two instances hold a clear two-way PTT call over Tor; release-to-hear
  is Tor-bound (no local-pipeline stall); cipher-mismatch is surfaced, not silent.

## M2 — Security & robustness hardening
- Secret-at-rest (Argon2id passphrase wrap) + plaintext migration.
- Replay/nonce hardening + fuzzing of `proto`.
- Speed/anonymity hop modes + gated single-hop-service warning ([ADR-0005]).
- Reconnect/keepalive, graceful HANGUP, key zeroization.
- In-call encrypted text (`MSG`).
- **Exit:** clean external review of the crypto/proto paths; soak test stable.

## M3 — Feature parity with v1.1.6
Port the v1 surface onto the v2 core: caller ID exchange, QR identity sharing,
PTT chime, voice changer, circuit-hop display, country exclusion, configurable
opus/cipher mid-call, auto-listen.
- **Exit:** every advertised v1.1.6 feature has a v2 equivalent or a documented drop.

## M4 — Group relay
Zero-knowledge N-caller relay (forward sealed AUDIO/MSG/PING, filter control,
no PSK), live caller count, single-hop relay option.
- **Exit:** 3–5 caller group call works; relay never sees plaintext.

## M5 — Platform reach
Android/Termux audio path, Snowflake/pluggable-transport bridging, reproducible
builds + signed release artifacts (so a binary is as auditable as the script was).
- **Exit:** Termux build talks to a desktop build; reproducible-build doc published.

## Cross-cutting (parallel to all milestones)
- CI matrix + lint/test gates.
- Threat-model doc kept current as design evolves.
- Forward-secrecy decision (X25519 ECDH) — pending ADR.

[ADR-0005]: adr/0005-speed-first-anonymity-default.md
