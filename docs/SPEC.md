# TerminalPhone v2 — Technical Specification

> Status: **draft** · Supersedes the v1.x bash implementation (`terminalphone.sh`).
> Tracking: issues live in beads (`bd ready`); decisions in `docs/adr/`.

## 1. Overview

TerminalPhone is anonymous, end-to-end-encrypted push-to-talk voice + text over
Tor hidden services. Your `.onion` is your identity — no servers, accounts, or
phone numbers. v2 reimplements the v1 bash script as a **single self-contained
Rust binary** that embeds Tor (via `arti`), the Opus codec, audio I/O, and
crypto — eliminating the v1 dependency surface (`tor`, `socat`, `openssl`,
`sox`, `opus-tools`) and the shell-glue bugs that came with it.

### 1.1 Goals
- **One binary, no system deps.** Download, run, talk. (See [ADR-0001], [ADR-0002].)
- **Snappy.** Drive every non-Tor latency term to ~0 so Tor is the only wait. (§3)
- **Strong by default.** Authenticated encryption, per-call keys. ([ADR-0004])
- **Cross-platform.** Linux, macOS, Android/Termux from one codebase.
- **Feature parity** with v1.1.6 over time (relay/group, voice changer, QR, etc.).

### 1.2 Non-goals
- Real-time full-duplex telephony. Tor latency makes it unusable; v1 proved this.
  We stay **half-duplex push-to-talk**. ([ADR-0003])
- Protecting a compromised endpoint. If the device is owned, plaintext is exposed.
- Defeating a global passive adversary doing end-to-end traffic correlation.

## 2. Threat model

| Adversary | We defend? | Mechanism |
|---|---|---|
| Network observer (ISP, Wi-Fi) | Yes | All traffic is Tor; no clearnet. IPs hidden. |
| Tor circuit / relay attacker injecting or replaying frames | Yes | AEAD (AES-256-GCM) + per-frame counter in AAD. Forged/replayed frames fail auth. |
| Passive content eavesdropper | Yes | E2E AEAD with a pre-shared secret, key never on the wire. |
| Party you call learning your IP | **Configurable** | Anonymous by default; opt-in speed mode trades hops. Single-hop *service* (IP-revealing) is gated behind an explicit warning. ([ADR-0005]) |
| Global passive adversary (traffic correlation) | No | Out of scope; documented limitation. |
| Compromised endpoint | No | Out of scope. |
| Loss of the pre-shared secret | Partial | No forward secrecy in M1 (PSK only). Optional X25519 ECDH for FS is a backlog decision (§6.4). |

The pre-shared secret is exchanged **out of band** (in person, Signal, etc.).

## 3. Latency budget (the perf contract)

Per-message, "you release PTT → peer hears first sound", on an established call:

| Term | v1 bash | v2 target | Beatable? |
|---|---|---|---|
| Local encode + encrypt | ~50–200 ms (process spawns, **PBKDF2 per msg**, temp files) | **<5 ms** | Yes → ~0 |
| Transmit your message | starts on PTT release | **overlapped with talking** ([ADR-0003]) | Yes → ~0 |
| **Tor one-way** | ~0.5–1.5 s, jittery | same | **No — physics** |
| Receiver decrypt + decode | ~50–150 ms | **<5 ms** | Yes → ~0 |
| Receiver buffer before play | n/a | tunable jitter window | design knob |
| *(call setup, one-time)* | 3–10 s cold rendezvous | **hidden via pre-warm + dir cache** | Yes → invisible |

**Strategy:** in-process pipeline (no fork/exec, no temp files), derive the call
key **once** (not per message), overlap transmit with speech, and pre-warm the
Tor circuit at launch so the first word never pays setup cost. Validated by the
M0 spike: cold dial (~36 s) was almost entirely the dialer's *own* one-time
bootstrap; connect-after-bootstrap was a few seconds.

## 4. Components

```
mic → capture → Opus encode → AEAD seal → frame → [onion DataStream] → frame → AEAD open → Opus decode → jitter buffer → speaker
                                              ▲                                  ▲
                                         arti transport (in-process Tor)    per-call key (HKDF)
```

See `docs/ARCHITECTURE.md` for the module layout and trait boundaries.

## 5. Subsystem specs

### 5.1 Transport ([ADR-0002])
- **arti** (`arti-client` 0.42, "Arti 1.7") embedded in-process. No `tor` daemon,
  no torrc, no socat.
- **Identity:** the onion service long-term key is persisted under the app data
  dir; the `.onion` is its public form and is the user's stable identity.
- **Hosting (callee):** `launch_onion_service` → accept `RendRequest` →
  `handle_rend_requests` → accept the app-port stream → `DataStream`.
- **Dialing (caller):** `client.connect((onion, PORT))` → `DataStream`.
- **Lifecycle:** bootstrap once at launch (background), cache directory state to
  disk, keep circuits warm with `PING/PONG` keepalive, single persistent
  connection per call, graceful `HANGUP`.
- **Hops / speed ([ADR-0005]):** speed-first default reduces hops; full-anonymity
  toggle restores 3+3. The IP-revealing single-hop *service* mode is a separate,
  explicitly-warned opt-in (never silent).
- **Abstraction:** all Tor access sits behind a `Transport` trait so a
  "native-crypto-but-system-tor" fallback is a single-impl swap if arti hosting
  regresses.

### 5.2 Crypto ([ADR-0004])
- **AEAD:** AES-256-GCM (hardware-accelerated: AES-NI / ARMv8 crypto).
  ChaCha20-Poly1305 fallback for targets without AES hardware.
- **Key derivation:** session key = `HKDF-SHA256(PSK, salt = caller_nonce ||
  callee_nonce, info = "terminalphone/v2 call-key")`. Each side contributes a
  random 32-byte nonce in the handshake → **unique key per call**, derived
  **once**, never per message.
- **Nonce discipline:** 96-bit GCM nonce = `4-byte direction tag || 8-byte
  monotonic per-direction counter`. Never reused under a given key.
- **Replay / integrity:** the monotonic frame sequence is bound into the AEAD
  AAD; the receiver enforces a forward window. Forged, modified, or replayed
  frames fail the tag and are dropped silently.
- **Secret at rest:** PSK optionally encrypted with a passphrase (Argon2id KDF,
  AES-256-GCM) — stronger than v1's PBKDF2-100k. Plaintext-secret migration on
  first run.
- **Cipher negotiation:** AEAD suite id exchanged in `HELLO`; mismatch aborts the
  call with a clear error (not a silent failure).

### 5.3 Wire protocol
Length-prefixed binary frames over the onion `DataStream`:

```
┌────────┬────────┬──────────────┬───────────────┐
│ ver:u8 │ type:u8│ len:u32 (BE) │ payload[len]  │
└────────┴────────┴──────────────┴───────────────┘
```

| type | name | payload | sealed? |
|---|---|---|---|
| 0x01 | HELLO | onion addr, AEAD suite id, opus params, 32-byte call nonce, flags | no (pre-key) |
| 0x02 | AUDIO | seq, sealed Opus frame(s) | yes |
| 0x03 | MSG | sealed UTF-8 text | yes |
| 0x04 | PTT_START / 0x05 PTT_STOP | sealed control | yes |
| 0x06 | PING / 0x07 PONG | keepalive | yes |
| 0x08 | HANGUP | sealed control | yes |
| 0x09 | CIPHER | re-negotiate AEAD suite mid-call | yes |

`HELLO` is the only unsealed frame (it bootstraps the key). Everything after is
AEAD-sealed; an attacker without the PSK cannot inject any post-handshake frame.

### 5.4 Audio pipeline ([ADR-0003], [ADR-0007])
- **Capture:** `cpal` (CoreAudio/ALSA/AAudio), mono, resampled to the Opus rate.
- **Codec:** `audiopus` (libopus). Default **16 kHz wideband mono, ~24 kbps VBR,
  20–40 ms frames** — better intelligibility than v1's 8 kHz/16 kbps at a similar
  Tor footprint (~3 KB/s). Configurable down to 8 kHz for constrained links.
- **Pipelined send:** while PTT is held, each Opus frame is sealed and written to
  the stream immediately (transmit overlaps speech). On release, an end-of-utterance
  marker flushes.
- **Receive / playback:** frames are decrypted and decoded into a small **jitter
  buffer**; playback starts once a tunable lead (default ~one utterance, or a
  configurable lead time) is buffered, then streams smoothly. This preserves
  v1's "no clipping" guarantee while removing the transmit-after-release delay.
- **PTT status / chime:** remote recording indicator and optional chime, as v1.

### 5.5 PTT / TUI
- Terminal raw mode for push-to-talk (no root). Configurable PTT key.
- Call screen: remote `.onion`, AEAD suite match indicator, ms-level stats,
  remote PTT state, circuit/hops summary.
- Menus: host/listen, dial, settings, identity/QR.

### 5.6 Group relay (feature-parity, later)
Zero-knowledge relay that bridges N callers: forwards sealed `AUDIO`/`MSG`/`PING`,
filters control signals, never holds the PSK. Carried forward from v1.1.5+.

## 6. Persistence, config, open questions

### 6.1 Data layout (`$DATA_DIR`)
- `identity/` — onion service key material (0600).
- `arti/` — cached directory/consensus + state (fast warm starts).
- `secret` — PSK (optionally passphrase-wrapped).
- `config.toml` — user settings.

### 6.2 Config
TOML: AEAD suite, opus params, PTT key, hop/speed mode, jitter lead, relay opts.

### 6.3 Compatibility
v2 wire format is **not** compatible with v1.x (new AEAD framing). v2 is a clean
break; v1 remains on its branch.

### 6.4 Open questions / backlog decisions
- **Forward secrecy:** optional X25519 ECDH mixed into HKDF, authenticated by the
  PSK. Strong upgrade, modest cost — pending ADR.
- **Jitter strategy:** fixed lead vs adaptive (measure circuit RTT, tune buffer).
- **Padding / traffic shaping:** whether to pad frame sizes to blunt the
  size-fingerprint of pipelined streaming (trades bandwidth for analysis
  resistance).
- **Termux audio:** AAudio via `cpal` vs a Termux:API bridge fallback.

[ADR-0001]: adr/0001-rewrite-to-single-rust-binary.md
[ADR-0002]: adr/0002-in-process-tor-via-arti.md
[ADR-0003]: adr/0003-pipelined-store-and-forward-audio.md
[ADR-0004]: adr/0004-aead-crypto-aes256gcm-hkdf.md
[ADR-0005]: adr/0005-speed-first-anonymity-default.md
[ADR-0007]: adr/0007-audio-stack-cpal-audiopus.md
