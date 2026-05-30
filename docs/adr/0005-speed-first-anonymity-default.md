# ADR-0005 — Speed-first hop default with gated single-hop service

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
Onion hops are the single biggest latency term — a connection to a hidden service
traverses ~6 relays (3 per side via a rendezvous point). Reducing hops is the only
lever that touches the Tor floor itself. v1 already exposes
`HiddenServiceSingleHopMode` for relay operators. There are **two distinct knobs**
with very different safety:
- **Client-side hop reduction** (your outbound dial): mildly weakens *your* path
  anonymity.
- **Single-hop *service* mode** (non-anonymous hidden service): lets the peer you
  call — or anyone who becomes an introduction point — **discover your real IP**.
  This is categorically more dangerous for a "nobody knows who you are" tool.

## Decision
Default to **speed-first**: reduced hops out of the box for snappiness, with a
**max-anonymity toggle** to restore full 3+3. **However**, the IP-revealing
single-hop *service* mode is **never silent** — it is a separate, explicit opt-in
behind a clear "this reveals your IP address" warning. Speed-first ≠ auto-dox.

## Consequences
- **Positive:** grabs the biggest available latency win for the common case;
  power users can dial anonymity up or speed further up deliberately.
- **Negative / costs:** a speed-first default is a surprising stance for a Tor
  privacy tool; documentation must make the tradeoff legible.
- **Risks & mitigations:** users misunderstanding the exposure → the dangerous
  knob is gated + warned, and the call screen surfaces the active hop/anonymity
  mode so the current posture is always visible.

## Alternatives considered
- **Anonymous-by-default + speed toggle:** safest default, but leaves the biggest
  perf win off by default. Rejected in favor of speed-first given perf is a
  principal goal — with the hard gate on the IP-revealing knob as the safety net.
- **Full anonymity only (no knob):** simplest/safest story, but permanently
  forfeits the largest latency lever. Rejected.
