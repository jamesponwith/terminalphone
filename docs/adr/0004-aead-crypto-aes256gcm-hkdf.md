# ADR-0004 — AEAD (AES-256-GCM) + per-call HKDF key

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
v1 encrypts each message with AES-256-CBC via an `openssl` subprocess, running
**PBKDF2 (10 000 iters) per message** (`terminalphone.sh:859`), with an *optional*
separate HMAC-SHA256 pass for integrity. Three problems: (1) CBC without a MAC is
malleable — without the opt-in HMAC, a circuit attacker can flip bits; (2)
per-message PBKDF2 + process spawns are a per-message latency tax; (3) the cipher
key and HMAC key are the same secret.

## Decision
Use an **AEAD**: **AES-256-GCM** (hardware-accelerated via AES-NI / ARMv8 crypto;
ChaCha20-Poly1305 fallback for non-AES-hardware targets). Derive the session key
**once per call** via `HKDF-SHA256(PSK, salt = caller_nonce || callee_nonce,
info = "terminalphone/v2 call-key")`, where each side contributes a random 32-byte
nonce in the `HELLO` handshake. Per-frame 96-bit nonce = `direction tag || u64
counter`. Bind the frame sequence into the AEAD AAD for replay rejection.

## Consequences
- **Positive:** a **perf + security twofer** — one hardware-accelerated pass gives
  confidentiality *and* integrity (deletes the separate HMAC step and the CBC
  malleability gap), and moving PBKDF2 out of the per-message path makes
  per-frame crypto microseconds. Per-call keys mean a unique key every call.
- **Negative / costs:** GCM nonce reuse is catastrophic — demands disciplined
  per-direction counters and a hard invariant against reuse.
- **Risks & mitigations:** nonce misuse → enforce via type-state counters + unit
  tests asserting uniqueness; never derive a nonce from data. No forward secrecy
  from PSK alone → optional X25519 ECDH into HKDF is a backlog ADR.

## Alternatives considered
- **Keep AES-256-CBC + mandatory HMAC (encrypt-then-MAC):** secure if done right,
  but two passes, more footguns, and no perf win. AEAD is strictly better here.
- **XChaCha20-Poly1305 (192-bit nonce, random nonces):** removes counter
  discipline via random nonces; viable, but AES-GCM wins on hardware accel on both
  target platforms. Kept ChaCha20-Poly1305 as the no-AES-hardware fallback.
- **Per-message KDF (status quo):** rejected — pure latency tax.
