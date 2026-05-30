# ADR-0007 — Audio stack: cpal + audiopus (libopus)

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
v1 shells out to `sox`/ALSA (`rec`/`play`/`arecord`/`aplay`) for capture and
playback and `opus-tools` (`opusenc`/`opusdec`) for the codec — per-message
process spawns and heavy per-platform branching. v2 needs in-process,
cross-platform capture/playback and Opus encode/decode with no subprocesses.

## Decision
- **Capture/playback:** `cpal` — cross-platform audio (CoreAudio on macOS, ALSA on
  Linux, AAudio/Oboe on Android) with a uniform Rust API.
- **Codec:** `audiopus` (safe bindings to libopus).
- **Defaults:** 16 kHz wideband mono, ~24 kbps VBR, 20–40 ms frames (better
  intelligibility than v1's 8 kHz/16 kbps at a comparable Tor footprint;
  configurable down to 8 kHz). Resample mic input to the Opus rate in `capture`.

## Consequences
- **Positive:** no subprocesses, no temp files; uniform code path across
  platforms; tight control over buffering for the jitter strategy ([ADR-0003]).
- **Negative / costs:** cpal device/format quirks vary per backend; Android/Termux
  audio is the known rough edge.
- **Risks & mitigations:** Termux audio → evaluate cpal/AAudio vs a Termux:API
  bridge fallback in M5 (`SPEC.md` §6.4). libopus build → `audiopus` vendors it;
  verify static linking per target in CI.

## Alternatives considered
- **Keep sox/opus-tools subprocesses:** rejected with ADR-0001 (spawn latency,
  external deps, branching).
- **PortAudio / rodio / direct platform APIs:** PortAudio adds a C dep; `rodio` is
  playback-oriented (weaker capture story); raw platform APIs multiply
  per-OS code. `cpal` is the best capture+playback fit.

[ADR-0003]: 0003-pipelined-store-and-forward-audio.md
