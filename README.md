# TerminalPhone

Anonymous, end-to-end-encrypted push-to-talk voice and text over Tor hidden services.

TerminalPhone is a **single, self-contained binary** that lets two parties hold
an anonymous, encrypted voice + text call over the Tor network. It operates as a
walkie-talkie: you hold a key to record, and your speech is encoded, encrypted,
and streamed to the remote party as you talk; the receiver buffers and plays it
back smoothly. No server infrastructure, no accounts, no phone numbers. Your Tor
onion-service `.onion` address is your identity.

> **v2 — Rust rewrite.** This is a ground-up reimplementation of the original v1
> Bash script as one Rust binary that **embeds Tor in-process** (via
> [`arti`](https://gitlab.torproject.org/tpo/core/arti)), the Opus codec, audio
> I/O, and authenticated crypto. It eliminates the entire v1 dependency surface
> (`tor`, `socat`, `openssl`, `sox`, `opus-tools`) and the shell-glue bugs that
> came with it. The v1 script is preserved as `terminalphone.sh` — see
> [v1 (legacy)](#v1-legacy). The v2 wire format is a clean break and is **not**
> compatible with v1.

---

## Table of Contents

- [Why v2](#why-v2)
- [Status](#status)
- [Build](#build)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Commands](#commands)
  - [Options](#options)
  - [In-Call Controls](#in-call-controls)
- [How It Works](#how-it-works)
  - [Wire Protocol](#wire-protocol)
- [Security Model](#security-model)
  - [Threat Model](#threat-model)
- [Speed vs. Anonymity](#speed-vs-anonymity)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [v1 (legacy)](#v1-legacy)
- [License](#license)

---

## Why v2

The v1 walkie-talkie was a ~150 KB Bash script that shelled out to `tor`,
`socat`, `openssl`, `sox`, and `opus-tools`. It worked, but every voice message
paid for process spawns, temp files, and a fresh PBKDF2 key derivation, and the
install surface was large. v2 reimplements the same idea natively:

- **One binary, no system deps.** Download, run, talk. Tor is embedded via
  `arti` — no `tor` daemon, no `torrc`, no `socat`.
- **Snappy.** Every non-Tor latency term is driven toward zero (in-process
  pipeline, key derived once per call, transmit overlapped with speech, warm
  circuits) so Tor's ~0.5–1.5 s one-way is the *only* thing you wait on.
- **Strong by default.** Authenticated encryption (AES-256-GCM) with a unique
  per-call key. No silent failures on a cipher or secret mismatch.
- **Cross-platform from one codebase.** Linux and macOS today; Android/Termux on
  the roadmap.

See `docs/SPEC.md` for the full specification and `docs/adr/` for the decision
record behind each of these.

---

## Status

This is an in-progress rewrite. Milestones are tracked in `docs/ROADMAP.md`;
issue status is authoritative in beads (`bd ready`).

| Milestone | Scope | State |
|---|---|---|
| **M0** | arti onion-service spike (host + dial round-trip) | ✅ done |
| **M1** | Vertical slice: a real encrypted two-way PTT call over Tor | ✅ core complete |
| **M2** | Security & robustness: speed/anonymity modes, in-call text, secret-at-rest, codec fuzzing | 🚧 mostly landed |
| **M3** | Feature parity with v1.1.6 (QR + voice changer landed; relay, chime, hop display, … remain) | 🚧 in progress |
| **M4** | Zero-knowledge group relay (N callers) | ⏳ planned |
| **M5** | Android/Termux audio, pluggable-transport bridges, signed reproducible builds | ⏳ planned |

**Working today:** hosting and dialing a real onion service over embedded Tor, a
clear two-way push-to-talk call with authenticated per-call encryption, in-call
encrypted text, the gated single-hop-service warning, passphrase-protected
secret-at-rest (Argon2id), a voice changer, QR identity sharing, and a headless
self-test that exercises the whole encode → seal → wire → open → decode pipeline
without a microphone or a Tor circuit.

**Not yet ported from v1:** group relay mode, PTT chime presets, circuit-hop
display, country exclusion, Snowflake bridges, and the Termux/Android audio path.
These are the remaining M3–M5 queue.

---

## Build

TerminalPhone v2 is a Cargo workspace. You need a recent stable Rust toolchain
(`rustup` recommended).

```bash
git clone https://gitlab.com/here_forawhile/terminalphone.git
cd terminalphone

cargo build --workspace            # first build compiles arti — slow, one-time
cargo run -p tphone --bin terminalphone -- selftest   # headless pipeline proof
```

The `selftest` should print:

```
selftest: OK — tone + message round-tripped exactly
```

Use `--release` for real calls so audio and crypto stay well under the latency
budget:

```bash
cargo build --release --workspace
```

The resulting binary is `terminalphone` (crate `tphone`). For day-to-day work,
`cargo run -p tphone --bin terminalphone -- <command>` is equivalent to running
the built binary directly.

---

## Quick Start

A real call is two machines, each running `terminalphone`, talking half-duplex
over a Tor onion service.

```
1. Build:               cargo build --release --workspace
2. Machine A hosts:     cargo run --release -p tphone --bin terminalphone -- host
                        → prints its <56-char-base32>.onion address
3. Share the .onion + the shared secret with B, out of band
4. Machine B dials:     cargo run --release -p tphone --bin terminalphone -- dial <onion>
5. Both: hold the PTT key (SPACE) to talk; press q to hang up
```

Both sides must hold the **same pre-shared secret (PSK)**. On first run, a
random 32-byte PSK is generated at `<data-dir>/secret` (mode `0600`); copy it to
the other machine (or provision both from the same value) **out of band** — in
person, over Signal, etc., never over the call you are setting up. A PSK mismatch
derives different call keys and the first sealed frame fails authentication with
a clear error; it does **not** silently connect.

> **First connect is slow, once.** The first run on a machine downloads a Tor
> consensus (~30–90 s) and publishes the onion descriptor (~30–90 s). Subsequent
> runs reuse the cached consensus and the persisted onion identity, so **your
> `.onion` is stable across runs** and connects are fast.

See `docs/RUNBOOK.md` for the full self-test → local loopback → two-machine
procedure.

---

## Usage

```
terminalphone — anonymous E2E push-to-talk over Tor

USAGE:
    terminalphone [OPTIONS] host
    terminalphone [OPTIONS] dial <onion>
    terminalphone [OPTIONS] selftest
```

### Commands

| Command | Description |
|---|---|
| `host` | Host an onion service and wait for a caller. Prints your `.onion`. |
| `dial <onion>` | Dial a remote `.onion` and start a call. |
| `qr <onion>` | Render a `.onion` as a scannable terminal QR code and exit (offline; no Tor/audio). |
| `selftest` | Run a headless integrated loopback self-test (no Tor, no audio). |

### Options

| Option | Description |
|---|---|
| `-h`, `--help` | Print usage and exit. |
| `--data-dir <path>` | Data directory. Default: `$TERMINALPHONE_DIR`, else `$HOME/.terminalphone`. |
| `--speed <mode>` | `speed_first` (default), `full_anonymity`, or `single_hop_service`. See [Speed vs. Anonymity](#speed-vs-anonymity). |
| `--log <level>` | `trace`, `debug`, `info` (default), `warn`, `error`. Also honors `RUST_LOG`. |

**Environment:** set `TERMINALPHONE_PASSPHRASE` to protect the on-disk secret.
On first run the generated PSK is stored encrypted (Argon2id + AES-256-GCM); if a
plaintext secret already exists it is migrated to the wrapped format in place; an
already-wrapped secret is unlocked with it (or via an interactive prompt on a
TTY). See [Security Model](#security-model).

### In-Call Controls

Once the handshake completes, both sides enter a raw-mode TUI call screen showing
your local `.onion`, the remote peer's `.onion`, the AEAD-suite match indicator,
the hop/speed posture, live stats, and the remote PTT (recording) state.

| Key | Action |
|---|---|
| Hold **PTT key** (default SPACE) | Record and transmit voice. Transmit overlaps your speech; the utterance flushes on release. |
| **T** | Enter compose mode to type an encrypted text message. |
| **Enter** | Send the composed message (empty lines are dropped); exits compose. |
| **Esc** | Cancel compose. |
| **Q** or **Ctrl-C** | Graceful hang up — sends `HANGUP`, tears down the circuit, zeroizes key material. |

On terminals that report key-release events, PTT is **hold-to-talk**. On
terminals that cannot (e.g. some mobile keyboards), it degrades to **tap-to-toggle**.

---

## How It Works

TerminalPhone uses a **pipelined store-and-forward** model: while you hold the
PTT key, each captured audio frame is encoded, sealed, and written to the onion
stream *immediately* (transmit overlaps speech); the receiver decrypts and
decodes into a small jitter buffer and begins playback once a short lead
(default 250 ms) is buffered, then streams smoothly. This keeps v1's
"no-clipping" guarantee while removing the v1 transmit-after-release delay.

```
mic → capture → Opus encode → AEAD seal → frame → [onion DataStream] → frame → AEAD open → Opus decode → jitter buffer → speaker
                                              ▲                                  ▲
                                    arti transport (in-process Tor)        per-call key (HKDF)
```

Audio defaults to **16 kHz wideband mono, ~24 kbps VBR, 20 ms frames** (~3 KB/s)
— better intelligibility than v1's 8 kHz/16 kbps at a similar Tor footprint, and
configurable down to 8 kHz for constrained links.

### Wire Protocol

Length-prefixed binary frames over the onion `DataStream`:

```
┌────────┬─────────┬──────────────┬───────────────┐
│ ver:u8 │ type:u8 │ len:u32 (BE) │ payload[len]  │
└────────┴─────────┴──────────────┴───────────────┘
```

| Type | Name | Sealed? | Purpose |
|---|---|---|---|
| `HELLO` | handshake | no (pre-key) | onion addr, AEAD suite id, opus params, 32-byte call nonce, flags |
| `AUDIO` | voice | yes | seq + sealed Opus frame(s) |
| `MSG` | text | yes | sealed UTF-8 message |
| `PTT_START` / `PTT_STOP` | control | yes | remote recording state |
| `PING` / `PONG` | keepalive | yes | keep the circuit warm during silence |
| `HANGUP` | control | yes | graceful disconnect |
| `CIPHER` | control | yes | re-negotiate AEAD suite mid-call |

`HELLO` is the only unsealed frame — it bootstraps the key exchange. Everything
after it is AEAD-sealed, so an attacker without the PSK cannot inject any
post-handshake frame.

---

## Security Model

**Encryption.** All audio and text is sealed with an AEAD cipher
(**AES-256-GCM** by default, hardware-accelerated where available;
**ChaCha20-Poly1305** as a fallback for targets without AES hardware) before it
enters the Tor network — independent of Tor's own transport encryption.

**Per-call key.** The session key is derived **once per call**:
`HKDF-SHA256(PSK, salt = caller_nonce ‖ callee_nonce, info = "terminalphone/v2 call-key")`.
Each side contributes a fresh random 32-byte nonce in the handshake, so every
call gets a unique key. The PSK itself never touches the wire. (v1 derived a key
from PBKDF2 *per message*; v2 derives once and reuses an AEAD context.)

**Nonce discipline & replay resistance.** Each direction uses a 96-bit GCM nonce
of `4-byte direction tag ‖ 8-byte monotonic counter` — never reused under a given
key. The monotonic frame sequence is bound into the AEAD AAD, and the receiver
enforces a forward window. Forged, modified, replayed, or out-of-window frames
fail the tag and are dropped silently.

**Transport.** All data is routed through Tor onion-service circuits. Neither
party's IP is exposed by default, there is no clearnet traffic, and the
connection cannot be attributed to either party by a network observer.

**No silent failures.** The AEAD suite is exchanged in `HELLO`; a mismatch — or a
PSK mismatch — aborts the call with an explicit error rather than connecting
silently.

**Secret at rest.** The PSK can be encrypted on disk with a passphrase
(`TERMINALPHONE_PASSPHRASE`): the key is wrapped with **AES-256-GCM** under an
**Argon2id**-stretched key-encryption key (stronger than v1's PBKDF2), with the
format header bound in as AAD. A plaintext secret is migrated to the wrapped
format in place the first time a passphrase is provided. Without a passphrase the
secret is a bare 32-byte key at mode `0600`.

**Cleanup.** Graceful `HANGUP` tears down the circuit on both sides, and key
material is zeroized (`zeroize`) on drop.

### Threat Model

| Adversary | Defended? | Mechanism |
|---|---|---|
| Network observer (ISP, Wi-Fi) | Yes | All traffic is Tor; no clearnet; IPs hidden. |
| Tor circuit / relay attacker injecting or replaying frames | Yes | AEAD + per-frame counter bound in AAD; forged/replayed frames fail auth. |
| Passive content eavesdropper | Yes | E2E AEAD with a pre-shared secret; key never on the wire. |
| Party you call learning your IP | Configurable | Anonymous by default; single-hop *service* is IP-revealing and gated behind an explicit warning. |
| Global passive adversary (end-to-end traffic correlation) | No | Out of scope; documented limitation. |
| Compromised endpoint | No | Out of scope; if the device is owned, plaintext is exposed. |
| Loss of the pre-shared secret | Partial | No forward secrecy yet (PSK only); X25519 ECDH is a backlog decision. |

**Limitations:**

- The PSK must be exchanged **out of band** through a secure channel.
- **No forward secrecy** (M1): if the PSK is compromised, past and future calls
  using it can be decrypted. Optional X25519 ECDH mixed into the HKDF is a
  pending design decision.
- The protocol does not protect a **compromised endpoint**.
- **Passphrase-at-rest** is opt-in (`TERMINALPHONE_PASSPHRASE`). With no
  passphrase set, the secret is stored as a bare 32-byte key at mode `0600`.

---

## Speed vs. Anonymity

Per [ADR-0005], the hop/speed posture is selectable via `--speed` (or `speed_mode`
in `config.toml`):

| Mode | Meaning |
|---|---|
| `speed_first` *(default)* | Speed-first posture using standard, location-anonymous onion circuits. Never auto-trades your anonymity for speed. |
| `full_anonymity` | Standard full-anonymity onion circuits (3+3 hops), explicitly selected. |
| `single_hop_service` | **IP-REVEALING. Gated, never silent.** A single-hop onion *service* exposes the hosting machine's real IP to the rendezvous path. Selecting it prints an explicit warning and requires confirmation; **hosting refuses outright** to prevent accidental deanonymization. Only consider it when the host IP is already public and non-sensitive. |

---

## Configuration

State lives under the data directory (`--data-dir`, else `$TERMINALPHONE_DIR`,
else `$HOME/.terminalphone`):

```
<data-dir>/
  identity/      Onion-service long-term key material (0600) — your stable .onion
  arti/          Cached Tor consensus + state (fast warm starts)
  secret         Pre-shared secret (PSK), 32 bytes, mode 0600
  config.toml    User settings
```

`config.toml` (all fields optional; defaults shown):

| Key | Default | Description |
|---|---|---|
| `aead_suite` | `Aes256Gcm` | AEAD cipher (`Aes256Gcm` or `ChaCha20Poly1305`). |
| `ptt_key` | `' '` (SPACE) | Push-to-talk key. |
| `speed_mode` | `SpeedFirst` | Hop/anonymity posture (see above). |
| `voice_effect` | `off` | Outgoing voice changer: `off`, `robot`, `tremolo`, `overdrive`, `telephone`, `whisper`. |
| `jitter_lead_ms` | `250` | Playback lead buffered before audio starts. |
| `app_port` | `7777` | Application port carried inside the onion circuit. |
| `[opus]` `sample_rate` | `16000` | Audio sample rate in Hz (`8000` for constrained links). |
| `[opus]` `channels` | `1` | Channel count (mono). |
| `[opus]` `bitrate` | `24000` | Opus target bitrate in bits/sec. |
| `[opus]` `frame_ms` | `20` | Opus frame duration in ms. |

---

## Architecture

A single binary crate on a Tokio async runtime, with arti running in-process.
All Tor knowledge sits behind a `Transport` trait, so a system-`tor` fallback is
a single-impl swap if arti hosting ever regresses.

```
src/
  main.rs       CLI parse, data-dir resolution, runtime + crypto-provider init
  app.rs        call state machine; pipelined send/recv tasks
  config.rs     TOML load/save; data-dir paths; defaults
  crypto.rs     PSK; HKDF per-call key; AES-256-GCM | ChaCha20-Poly1305 seal/open
  proto.rs      wire frame codec + HELLO handshake; seq/AAD binding
  transport/    Transport trait + arti impl (onion host/dial, identity, keepalive)
  audio/        cpal capture/playback + audiopus codec + jitter buffer + voice DSP
  qr.rs         render a .onion as a terminal QR for identity sharing
  tui.rs        raw-mode PTT input; call-screen render
```

The full design — module boundaries, data flow, and testing strategy — is in
`docs/ARCHITECTURE.md`. The decision record is in `docs/adr/`.

---

## Troubleshooting

**First Tor bootstrap is slow.** On first launch, arti downloads the full network
consensus, and `host` then publishes the onion descriptor — together ~1–3
minutes. Subsequent launches use cached consensus + the persisted identity and
are much faster. Run with `--log debug` (or `RUST_LOG=debug`) to watch progress.

**Call connects but audio is silent / errors immediately.** Almost always a
**PSK mismatch** — both sides must hold the identical secret. v2 surfaces this as
an explicit authentication error rather than connecting silently; confirm the
`secret` files match.

**`Error::Audio` at startup.** No working microphone or speaker was found. The
binary reports this cleanly (no panic), but you cannot talk without an audio
device. Verify your default input/output devices.

**Single-hop warning on `dial`.** Expected if `--speed single_hop_service` is set
— it is IP-revealing by design and requires confirmation. Hosting in this mode is
refused outright.

**Verify the build without hardware.** `cargo run -p tphone --bin terminalphone --
selftest` and `cargo test --workspace` exercise the whole crypto/proto/audio
pipeline with no Tor circuit and no audio device. See `docs/RUNBOOK.md`.

---

## v1 (legacy)

The original v1.1.6 implementation — a single self-contained Bash script — is
preserved in this repo as `terminalphone.sh` (MIT). It is feature-complete for
its model but **frozen**; new work happens on the v2 Rust binary described above.
v1 and v2 are **not** wire-compatible. The v1 dependency-install flow, in-call
controls, relay mode, and full feature list are documented in the script's own
menus and the project history.

<details>
<summary>v1 pastebin mirrors</summary>

[V1.0.0](https://bin.disroot.org/?e1356291b098cb75#FMQ4gxFwgdr3rjR1dpGS2csLmDPzDEkQW16fQ5P2Vt4y) ·
[V1.0.1](https://bin.disroot.org/?d3bc0b8976113f58#AuUm4ev4vfeVmPyrh2KjAdhDP6WN4UX6yKQh9ERGD5Qt) ·
[V1.0.2](https://bin.disroot.org/?6bc5b2fd046de1d7#G7TmnytrMeaM5AZYWth6BjjdqUb9RDf3K9erHUExKcGX) ·
[V1.0.3](https://bin.disroot.org/?c5010f039e4693fd#Brp1w7LRQH9d5Ye5npZDPxNVR855SW9QUAk9cJaUuLYX) ·
[V1.0.4](https://bin.disroot.org/?1831f6b78e349142#7zaAMVPNJL3MfbGJzjtm6cCPcvQftf4ULXupdne5dRKw) ·
[V1.0.5](https://bin.disroot.org/?edfcfc844987ed03#56LuBbqbkfNDXfHpydyaB3VcWYhYenX18dtSvNumERY9) ·
[V1.0.6](https://bin.disroot.org/?6c7b4774108b0c1c#GQPst46zjAYidndmNvytforX7MK2LyHanL4d829vVcv4) ·
[V1.0.7](https://bin.disroot.org/?047003637623b4fa#EwmaysciDpiDkht8xV7ce3QcR9oxFXaxSikh4cLheXBB) ·
[V1.0.8](https://bin.disroot.org/?06e38bd64e6fbdad#88MYs3dmq9rSMkmocpW3NYaaG4YfSdRCc9LJnEEzqGYp) ·
[V1.0.9](https://bin.disroot.org/?950218a9a7c71c66#E7Z94VCGBZozrfXYhGwKyAdMeTxuavg92tA1pn2DbrrB) ·
[V1.1.0](https://bin.disroot.org/?0b0da14f31521b3a#B1c23J8xFoZZKErvGG28PgbtfgtMUcDABWmQEoSZfXgh) ·
[V1.1.1](https://bin.disroot.org/?d8e2d4f0300eb5af#9Y1C8CkcH9jAmv1fh4GZs1yYpJmWCG5xG3SvDYdwnJam) ·
[V1.1.2](https://bin.disroot.org/?b1059616f880925f#8ef2oscZXUkPAsJZwGfWvLPQagVAk5GgW4DyssmLvQpG) ·
[V1.1.3](https://bin.disroot.org/?b02658801518aaa7#JE6CsBLWUwAnTdBqeHgeXL7QF5UExgi9rnygcfyMZjCJ) ·
[V1.1.4](https://bin.disroot.org/?d31248fc44c287a0#HQELFWFEMpM9kfTZSGDXTdGFMVKTejox5CajF9Vm4Www) ·
[V1.1.5](https://bin.disroot.org/?284b723ed6aad15f#8VCrrri6yRpdg3uVDSY94wpx7LYkw5uYhm4Vbhka83sM) ·
[V1.1.5.1](https://bin.disroot.org/?26aaef1eff20c271#4GxQQPSDhrszTu1RmERySNVqD2fZW5GZwm3JeL1parpB) ·
[V1.1.6](https://bin.disroot.org/?ae8270578cd9e081#BbcDLU49XqhecvwviHRcdfrZ4vhKdL2AMeKaT5v9oLV1)

</details>

---

## License

MIT
