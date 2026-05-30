# TerminalPhone v2 — Agent Instructions

TerminalPhone v2 is a ground-up **Rust rewrite** of the v1 bash walkie-talkie
(anonymous encrypted push-to-talk voice over Tor) into **one self-contained
binary**. Tor is embedded via `arti`; audio via `cpal`+`audiopus`; crypto is
AEAD with per-call keys.

**Read these first, in order:**
1. [`docs/SPEC.md`](docs/SPEC.md) — what we're building, threat model, the latency contract
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout + the `Transport` trait boundary
3. [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones (M0 spike ✅ → M1 vertical slice → …)
4. [`docs/adr/`](docs/adr/) — every significant decision, with the *why*

Then run `bd prime` and `bd ready`.

---

## Issue tracking is beads (`bd`)

We track **all** work and decisions in beads. Issue prefix is `tp-`.
`bd ready` is the source of truth for "what's next" — not this file, not memory.

- **Issue types:** `epic` (milestones M1–M5 + CI), `task` (work), `decision` (ADRs — mirrored from `docs/adr/`; closed = recorded).
- **Dependencies:** `blocks` (task→task ordering) and `parent-child` (epic→task grouping). The M1 vertical slice is fully decomposed; start at the top of `bd ready`.
- Do **not** use TodoWrite / markdown TODO lists — use `bd`.
- Use `bd remember` for durable project knowledge — not scratch `MEMORY.md` files.

### Beads gotchas (learned the hard way — see `bd recall`)
- `bd create --graph` **auto-imports `.beads/issues.jsonl` first**; a stale export revives deleted issues. Empty it before any clean recreate.
- `--dry-run` on `--graph` **persists on success** (only rolls back on error). Don't rely on it as a preview.
- Graph edge `{from_key, to_key, type:blocks}` means **from_key DEPENDS ON to_key** (to_key finishes first) — not "from blocks to."
- `bd close` takes `-r "<reason>"`, not a positional arg.
- Count with `bd count`, not by grepping `tp-` over JSON (dep refs inflate it).

---

## Team sync — two contributors (READ THIS)

Issue history lives in **Dolt under `refs/dolt/data`** on origin
(`github.com/jamesponwith/terminalphone`), synced with `bd dolt pull/push`.
Dolt does **cell-level merges**, so concurrent issue edits don't collide.
`.beads/issues.jsonl` is a *passive export* — never hand-edit it or treat it as
the source of truth.

**First-time setup (fresh clone / new machine):**
```bash
git pull
bd bootstrap          # clones the issue DB from refs/dolt/data
# do NOT run `bd init` in an existing clone — it creates a divergent empty DB
```

**Every work session:**
```bash
# --- start ---
git pull --rebase
bd dolt pull                          # grab the latest issue graph
bd ready                              # pick the top item

# --- during ---
bd update <id> --claim                # atomically claim (assignee + in_progress)
# ...do the work...
bd close <id> -r "<what shipped>"     # close with a reason
bd create "<follow-up>" -t task -p 2  # file new work as you discover it

# --- end ---
bd dolt push                          # publish issue changes (cell-level merged)
git add -A && git commit && git push  # code + the issues.jsonl export
```

**Rules of thumb:**
- **Pull before you start, push when you finish** — both `git` *and* `bd dolt`.
- **Claim before working** so you and your collaborator never double-grab a task.
- A `refs/dolt/data` ref is *data*, not a branch — ignore any GitHub "create a PR" nag for it; never merge it.

---

## Current state
- **M0** — arti onion-service spike ✅ (`rs-spike/`): in-process hosting + dial round-trips over Tor.
- **M1** — vertical slice decomposed and ready. Entry point: **`tp-n4t` Project skeleton** (top of `bd ready`).

---

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
