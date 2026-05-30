# ADR-0001 — Rewrite v1 bash → single self-contained Rust binary

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
v1 is a 142 KB Bash script (`terminalphone.sh`, v1.1.6) that shells out to six
external binaries (`tor`, `socat`, `openssl`, `sox`, `opus-tools`, ALSA/CoreAudio).
That dependency surface — not Bash — is where the real pain lives: version drift,
per-platform branching (macOS/ALSA/Termux), torrc/SOCKS juggling, and silent shell
regressions (e.g. the v1.0.5 stderr-redirect bug, the v1.0.3 no-salt issue). The
owner wants to "take it to the next level": faster, more robust, genuinely
dependency-free.

## Decision
Reimplement as **one self-contained Rust binary**. Rust chosen for: native Tor
via `arti` ([ADR-0002]), memory-safe crypto on a security-sensitive codebase,
hardware-accelerated AEAD, mature cross-platform audio, and a single static-ish
artifact per platform.

## Consequences
- **Positive:** kills the external-dependency drift and shell-glue bug class;
  in-process pipeline unlocks the perf targets (`SPEC.md` §3); one codebase for
  Linux/macOS/Android.
- **Negative / costs:** loses the script's `cat`-able, zero-toolchain
  auditability — a real loss for a paranoid-by-design tool. Binary won't be
  "tiny" (~8–15 MB with arti + opus). Larger up-front build.
- **Risks & mitigations:** opacity → commit to **reproducible builds + signed
  releases + prominent source** (M5) so the binary is as trustworthy as the
  script. Big rewrite → **vertical-slice-first** sequencing (`ROADMAP.md`) to
  prove the hard parts before porting features.

## Alternatives considered
- **Keep bash, optimize in place:** ceiling too low; can't escape process-spawn
  and external-dep latency, or the platform branching.
- **Compiled launcher that still shells out:** "tiny" but not self-contained —
  just renames the script. Rejected (the dependency surface is the problem).
- **Go / Zig / C:** Go has no `arti`-equivalent and rougher audio; Zig/C give up
  memory safety on crypto code. Rust dominates for *this* app.

[ADR-0002]: 0002-in-process-tor-via-arti.md
