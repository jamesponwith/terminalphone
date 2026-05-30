# Architecture Decision Records

Each ADR captures one significant, hard-to-reverse decision: the context, the
choice, and the consequences. Format: see `0000-template.md` (lightweight Nygard).

Each ADR is mirrored as a beads `decision` issue (`bd list --type decision`) so
the decision graph lives alongside the work graph. The bead ID is noted in each
ADR header once created.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-rewrite-to-single-rust-binary.md) | Rewrite v1 bash → single self-contained Rust binary | accepted |
| [0002](0002-in-process-tor-via-arti.md) | Embed Tor in-process via arti (vs system tor / shell-out) | accepted |
| [0003](0003-pipelined-store-and-forward-audio.md) | Pipelined store-and-forward audio (vs streaming / blob) | accepted |
| [0004](0004-aead-crypto-aes256gcm-hkdf.md) | AEAD (AES-256-GCM) + per-call HKDF key | accepted |
| [0005](0005-speed-first-anonymity-default.md) | Speed-first hop default with gated single-hop service | accepted |
| [0006](0006-beads-for-issue-tracking.md) | Beads for issue & decision tracking | accepted |
| [0007](0007-audio-stack-cpal-audiopus.md) | Audio stack: cpal + audiopus (libopus) | accepted |

## Conventions
- Number sequentially, zero-padded (`0001`).
- Never delete an ADR; supersede it (new ADR, mark old `superseded by`).
- An ADR is *accepted* once the decision is acted on in code or plan.
