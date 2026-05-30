# ADR-0006 — Beads for issue & decision tracking

- **Status:** accepted
- **Date:** 2026-05-29
- **Deciders:** project owner
- **Bead:** tp-xxxx

## Context
A multi-milestone rewrite with real dependency structure needs durable, queryable
task tracking that survives across agent sessions — not ad-hoc markdown TODOs.

## Decision
Use **beads** (`bd`, a Dolt-backed dependency-graph issue tracker designed for
agents). The work breakdown lives as beads issues with `blocks`/`parent-child`
edges; ADRs are mirrored as first-class `decision` beads. Issue prefix `tp-`.
`bd ready` drives "what's next"; `bd graph` visualizes execution order.

## Consequences
- **Positive:** dependency-aware "ready work" queue; decisions and tasks in one
  graph; git-native (Dolt under `refs/dolt/data`); agent-friendly CLI.
- **Negative / costs:** another tool + its sync model (Dolt push/pull) to learn;
  `.beads/issues.jsonl` is a passive export, **not** the source of truth.
- **Risks & mitigations:** confusion vs git history → follow beads' guidance (use
  `bd` for tasks, `bd remember` for project knowledge; don't hand-edit the JSONL).

## Alternatives considered
- **Markdown TODO / GitHub Issues / Linear:** no native dependency graph in-repo,
  or a web UI context-switch. Beads keeps the graph next to the code and CLI-first.
