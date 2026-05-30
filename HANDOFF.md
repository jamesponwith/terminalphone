# HANDOFF — start here (read once, act, then delete)

> **This is a one-time onboarding artifact, not living documentation.**
> Work through it once, then delete it (see the last section). The durable
> sources are `AGENTS.md` and `docs/` — this file only exists to point you at them.

## What this is

TerminalPhone v2 — a ground-up **Rust rewrite** of the v1 bash walkie-talkie
(anonymous, encrypted push-to-talk voice over Tor) into **one self-contained
binary**. Tor is embedded via `arti`, audio via `cpal` + `audiopus`, and all
traffic is AEAD-encrypted with per-call keys.

Read in this order before writing code:
1. **`AGENTS.md`** — how we work + the beads issue/sync workflow (most important)
2. **`docs/SPEC.md`** — what we're building, threat model, the latency contract
3. **`docs/ARCHITECTURE.md`** — module layout + the `Transport` trait seam
4. **`docs/ROADMAP.md`** — milestones M0–M5 and their exit criteria
5. **`docs/adr/`** — every significant decision, with the *why*
6. **`docs/RUNBOOK.md`** — how to actually run it (selftest + a real Tor call)

## Branch layout

- `main` — v1.x bash (`terminalphone.sh`, frozen)
- `rust-rewrite` — v2 core (crypto / proto / transport / audio scaffolding)
- `m1-finish` — stacked on `rust-rewrite`: audio engine, TUI, runnable app ← **work here**

## Day 1

```bash
git checkout m1-finish          # the current integration branch
git pull
bd bootstrap                    # clone the issue DB from the remote — do NOT run `bd init`
cargo build --workspace         # first build compiles arti (slow, one-time)
cargo test --workspace          # expect all green
cargo run -p tphone --bin terminalphone -- selftest   # headless full-pipeline proof
```

Then pick up work:

```bash
bd ready                        # the dependency-ordered "what's next" queue
bd show <id>                    # details + acceptance criteria
bd update <id> --claim          # atomically claim it (assignee + in_progress)
```

## Where things stand

The snapshot below ages — trust the live sources first:

```bash
bd list --status closed --type task    # what's actually done
bd ready                                # what's actually next
git log --oneline -15
```

As of handoff: the M1 call **core** (crypto, proto, audio codec, loopback
transport, the pipelined PTT call loop) is implemented and tested; the live
`cpal` audio engine + TUI make the binary runnable, and `selftest` proves the
whole encode→seal→transport→open→decode pipeline headlessly. **The last mile is
yours:** a real two-machine Tor call (a real mic + a second Tor node) — follow
`docs/RUNBOOK.md`. M2 (passphrase-at-rest, fuzzing, reconnect) and M3 (v1
feature parity) are the open queue.

## Team sync (you + the owner)

Issues live in Dolt and sync separately from code — full details in `AGENTS.md`
("Team sync"). Short version: `bd dolt pull` before you start, `bd dolt push`
when you finish, and **claim before working** so you two never double-grab a task.

## When you've finished onboarding — delete this file

This was a one-shot orientation; don't let it rot into stale docs.

```bash
git rm HANDOFF.md && git commit -m "docs: remove consumed handoff"
```

Everything durable lives in `AGENTS.md` and `docs/`. Welcome aboard.
