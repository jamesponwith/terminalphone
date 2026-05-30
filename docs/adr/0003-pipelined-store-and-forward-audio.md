# ADR-0003 — Pipelined store-and-forward audio

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
Perf is a principal goal: talking should feel as instant as Tor allows. The
dominant latency term is Tor itself (~0.5–1.5 s one-way, jittery; `SPEC.md` §3).
v1 already learned the hard lesson that **full-duplex live streaming is unusable
over Tor** (CHANGELOG v1.0.3) — jitter wrecks it. v1's walkie-talkie model
(record fully → encode → encrypt → send on release) is robust and gives "no
clipping," but its time-to-first-audio includes the *entire* talk duration **plus**
the full post-release transmit time.

## Decision
Keep the half-duplex push-to-talk model, but make it **pipelined**: encode +
seal + transmit each Opus frame **as the user speaks** (transmit overlaps speech,
so it's ~done at PTT release), while the **receiver buffers** into a small jitter
window before smooth playout. Not live full-duplex; not blob-after-release.

## Consequences
- **Positive:** removes the "transmit after release" latency term almost entirely
  (`SPEC.md` §3) while preserving smooth, no-clip playback and the irregular
  traffic pattern that aids traffic-analysis resistance.
- **Negative / costs:** more complex than blob send (frame sequencing, an
  end-of-utterance flush, a jitter buffer to tune).
- **Risks & mitigations:** under-buffering → mid-utterance gaps. Mitigate with a
  tunable lead (default ≈ one utterance / configurable lead time); adaptive
  jitter sizing is a backlog item (`SPEC.md` §6.4).

## Alternatives considered
- **Blob store-and-forward (v1):** simplest, but pays full transmit time after
  release. Rejected for the perf goal.
- **True low-latency streaming + jitter buffer (play-as-arrive):** lowest
  time-to-first-audio, but reintroduces the exact stall/clip failure mode v1 hit
  over Tor and weakens traffic-analysis resistance. Rejected as default; may
  return as an opt-in "low-latency mode."
