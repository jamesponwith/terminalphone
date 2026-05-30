# TerminalPhone v2 — Runbook

Operational guide for exercising the M1 call core: a headless self-test, a
local no-Tor loopback smoke, and a real two-machine call over Tor onion
services. Companion to `docs/SPEC.md` (the what/why) and
`docs/ARCHITECTURE.md` (the module map).

All commands are run from the workspace root
(`/Users/phall/workspace/terminalphone`). The binary is `terminalphone`
(crate `tphone`, `cargo run -p tphone --bin terminalphone`). Use
`--release` for real calls so audio encode/decode and crypto stay well under
the SPEC §3 latency budget; debug builds are fine for the self-test and tests.

The CLI surface (exactly what `terminalphone --help` prints today):

```
terminalphone — anonymous E2E push-to-talk over Tor

USAGE:
    terminalphone host
    terminalphone dial <onion>
    terminalphone selftest

COMMANDS:
    host            Host an onion service and wait for a caller.
    dial <onion>    Dial a remote .onion and start a call.
    selftest        Run a headless integrated loopback self-test (no Tor/audio).

OPTIONS:
    -h, --help      Print this help.
```

There are **no** `--speed` / `--data-dir` / `--log` CLI flags in M1. The data
directory is resolved by `config::default_data_dir()`, and the hop/speed
posture (`SpeedMode`) is read from `config.toml` under that data dir (default:
speed-first). See "Speed vs anonymity" below for how to change it.

---

## (a) Headless self-test (no Tor, no audio device)

The fastest confidence check. Runs the full integrated loopback path —
crypto seal/open, the proto HELLO handshake + key agreement, and the
**synthetic** audio path (tone capture → Opus encode → seal → wire → open →
Opus decode → play into an in-memory sink) plus a text message — with no
microphone, speaker, terminal, or Tor circuit. Ideal for CI.

```sh
cargo run -p tphone --bin terminalphone -- selftest
```

Expected: exit code `0` and the line:

```
selftest: OK — tone + message round-tripped exactly
```

The same path is asserted by an integration test
(`tests/selftest_integration.rs`):

```sh
cargo test -p tphone --test selftest_integration
```

---

## (b) Local two-process loopback smoke (no Tor)

Exercises the **entire** call pipeline — audio → proto → crypto → proto →
audio — end to end over the in-process `LoopbackTransport` (an in-memory
duplex pipe; no circuit, no network rendezvous). This is the canonical local
smoke for the call core, including a negative test that a peer with the wrong
PSK cannot open any frame:

```sh
cargo test -p tphone --test loopback_call
```

Expected: both `loopback_full_pipeline_round_trips_audio_and_msg` and
`wrong_psk_peer_cannot_open_frames` pass.

> Note: there is no separate "two terminals on one box without Tor" runtime
> path. `LoopbackTransport` rendezvous is in-process only, so the loopback
> integration test *is* the local two-endpoint smoke. For two real OS
> processes you must use the Tor path in (c).

To run the whole suite (unit + integration + doctests):

```sh
cargo test --workspace
```

---

## (c) Real two-machine call over Tor

This is the real product: two machines, each running `terminalphone`, talking
half-duplex push-to-talk over a Tor onion service. Your `.onion` is your
identity — no server, no account.

### Prerequisites (both machines)

1. **A shared pre-shared secret (PSK).** Both sides must hold the *same* PSK,
   exchanged **out of band** (in person, Signal, etc. — never over the call
   you are about to set up). The PSK lives under the data dir (`secret`); a
   first run generates one if absent, so copy A's `secret` to B (or provision
   both from the same value) before calling. A PSK mismatch derives different
   call keys and the first sealed frame fails authentication with a clear
   error — it does **not** silently connect.
2. **Working microphone and speaker.** A missing device surfaces as a clean
   `Error::Audio` (no panic), but then you cannot talk.
3. **Outbound network access** for Tor bootstrap.

### Step 1 — Machine A hosts

```sh
cargo run --release -p tphone --bin terminalphone -- host
```

- The **first** run on a machine downloads a Tor consensus (~30–90 s) and then
  publishes the onion-service descriptor to the HSDirs (another ~30–90 s).
  Subsequent runs are fast: the consensus is cached on disk and the onion
  identity key is reused, so **the same `.onion` persists across runs**
  (warm-start; the arti `cache_dir`/`state_dir` live under the data dir).
- It logs the address to share:

  ```
  onion service published      onion=<56-char-base32>.onion
  hosting; share this .onion   onion=<56-char-base32>.onion
  ```

- **Share that full `.onion` with B out of band.**

### Step 2 — Machine B dials

```sh
cargo run --release -p tphone --bin terminalphone -- dial <56-char-base32>.onion
```

B bootstraps its own Tor client (same one-time cost on first run), connects to
A's onion service on the app port, and runs the HELLO handshake.

### Step 3 — On the call (both machines)

Once the handshake completes, both enter the raw-mode TUI call screen, which
shows:

- **your** local `.onion` and the **remote** peer's `.onion` (caller-id —
  exchanged in the unsealed HELLO and rendered in the header on both sides),
- the AEAD-suite match indicator (confirm the suites agree),
- the hop/speed posture and live stats, including the remote PTT (recording)
  state.

**Confirm the pre-shared secret matches** by verifying the call establishes and
audio decodes cleanly; a suite/key mismatch aborts with an explicit error
rather than connecting silently.

Controls:

- **Hold the PTT key to talk** (half-duplex; transmit overlaps your speech and
  flushes the utterance on release).
- **Type** to compose and send an encrypted text `MSG`.
- **`q` or Ctrl-C** to hang up: sends a graceful `HANGUP`, tears down the
  circuit, and zeroizes key material.

Keepalive `PING`/`PONG` runs automatically inside the call loop to keep the
circuit warm during silence.

---

## Speed vs anonymity (`SpeedMode`, via `config.toml`)

Per [ADR-0005], the hop/speed posture is a config value (`speed_mode` in
`config.toml` under the data dir), not yet a CLI flag. Values:

| `speed_mode`         | Meaning |
|----------------------|---------|
| `SpeedFirst` (default) | Speed-first posture. On the arti 0.42 line there is **no safe public knob to reduce client-side hops** without risking IP exposure, so this runs standard onion circuits and logs the fallback. The service stays location-anonymous. Speed-first never auto-trades your anonymity. |
| `FullAnonymity`      | Standard full-anonymity onion circuits (3+3), explicitly selected. |
| `SingleHopService`   | **IP-REVEALING service mode. GATED — never silent.** Selecting it logs a warning that the single-hop *service* posture would reveal the hosting machine's real IP to the rendezvous path. Hosting in this mode is **refused** in `host()` (it would dox the host). Do **not** use it if you need to hide the host's IP; only consider it when the host IP is already public and non-sensitive. |

> **WARNING — single-hop service:** a single-hop onion *service* exposes the
> host machine's real IP address. TerminalPhone refuses to host in this mode
> precisely to prevent accidental deanonymization. It is never the default and
> is never enabled implicitly.

---

## Other useful invocations

```sh
# Confirm the M0 arti spike still builds (reference impl for the transport):
cargo build -p rs-spike

# See verbose Tor/bootstrap logging while diagnosing a slow first connect
# (logging is wired through tracing/RUST_LOG; there is no --log flag in M1):
RUST_LOG=debug cargo run -p tphone --bin terminalphone -- host
```

---

## Pre-flight verification (CI / before a release)

```sh
cargo build --workspace --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo run -p tphone --bin terminalphone -- selftest
cargo run -p tphone --bin terminalphone -- --help
cargo build -p rs-spike
```

All of the above should exit `0`. The `host`/`dial` paths additionally require
real hardware + Tor and are validated by the two-machine procedure in (c).
