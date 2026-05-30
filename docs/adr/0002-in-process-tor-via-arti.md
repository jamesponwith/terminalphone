# ADR-0002 — Embed Tor in-process via arti

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
v1 drives Tor by spawning the `tor` daemon with a generated torrc (hidden-service
block), then bridging bytes with `socat` (a `TCP-LISTEN` for inbound, a `SOCKS4A`
dial for outbound) and screen-scraping the control port for circuit info. This is
most of v1's operational complexity and bug surface. We need Tor for both roles:
**hosting** an onion service (the user's `.onion` identity) and **dialing** peers.

## Decision
Embed **arti** (`arti-client` 0.42 / "Arti 1.7"), the Tor Project's official Rust
Tor, as a library. `launch_onion_service` + `handle_rend_requests` replace the
torrc hidden-service + `socat TCP-LISTEN`; `client.connect((onion, port))`
replaces `socat SOCKS4A`. No daemon, no torrc, no socat, no control-port scraping.
All Tor access sits behind a `Transport` trait.

## Consequences
- **Positive:** deletes the entire shell-glue layer; circuit/identity managed as
  typed objects; warm-bootstrap + dir caching enable the "hide setup cost" perf
  lever.
- **Negative / costs:** arti is a large dependency (~300 crates, multi-minute
  first build, several MB).
- **Risks & mitigations:** onion-service **hosting** is arti's newer surface.
  **Mitigated and de-risked:** hosting is non-experimental since arti 1.2, and the
  M0 spike proved host+dial round-trips on 0.42. The `Transport` trait keeps a
  `SystemTorTransport` fallback one impl away if hosting ever regresses.

## Alternatives considered
- **Spawn system `tor` from Rust:** safer Tor, but reintroduces an external dep
  and torrc/SOCKS management — the thing we're trying to delete. Kept only as the
  trait-level fallback.
- **Stay with socat/tor (status quo):** rejected with ADR-0001.

## Validation
M0 spike (`rs-spike/`): `serve` minted a `.onion` in-process (~21 s); `dial`
returned `ROUNDTRIP: OK`. Gate passed.
