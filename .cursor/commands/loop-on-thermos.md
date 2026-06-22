---
description: Loop simplify → thermos → fix → verify until target severity levels are clean (default P0, P1); one commit per resolved finding.
---

# Loop on Thermos

Loop until there are no issues at the target severity levels **and** verification passes.

This is an **in-session agent loop** (like loop-on-ci), not the `/loop` skill's background shell ticker. Continue in the same chat until the exit condition is met.

## Target levels

Read severity levels from text the user provides after `/loop-on-thermos`.

- **Default:** `P0`, `P1` when no levels are specified.
- **Examples:** `/loop-on-thermos P0` · `/loop-on-thermos P0 P1 P2` · `/loop-on-thermos P1,P2`
- **Parsing:** Accept space- or comma-separated tokens; normalize to uppercase (`P0`–`P3` or whatever `/thermos` emits). Reject invalid tokens and ask the user to retry.
- **Priority order:** P0 → P1 → P2 → P3 (fix higher severity first).
- **Out of scope:** Issues at levels not in the target list (e.g. if targets are `P0` only, ignore P1+).

| Invocation                  | Target levels        |
| --------------------------- | -------------------- |
| `/loop-on-thermos`          | `P0`, `P1` (default) |
| `/loop-on-thermos P0`       | `P0` only            |
| `/loop-on-thermos P0 P1 P2` | `P0`, `P1`, `P2`     |
| `/loop-on-thermos P1,P2`    | `P1`, `P2`           |

## Optional commands

Before each phase, resolve the command (in order):

1. `.cursor/commands/<name>.md` in this repo
2. `~/.cursor/commands/<name>.md` (global)
3. Attached skill or command in the session

| Phase    | Command    | If missing                            |
| -------- | ---------- | ------------------------------------- |
| Simplify | `simplify` | Skip with one-line note               |
| Thermos  | `thermos`  | **Stop** — cannot determine exit      |
| Verify   | `verifier` | Fall back to `make lint && make test` |

For thermos, also accept the thermos plugin skill if no command file exists.

## Prerequisites

- Clean working tree or explicit user consent to commit on the current branch.
- Run `make lint && make test` before each commit (see [AGENTS.md](../../AGENTS.md)).

## Loop

Each iteration runs four phases. Repeat until thermos reports **zero issues at every target level** and verification passes.

### 0. Initialize

1. **Parse target levels** from the invocation (default `P0`, `P1`).
2. Record loop iteration count (start at 1). Echo the active target levels in the first status line.
3. Resolve review scope: `git merge-base HEAD main` (or user-provided base); collect `git diff` + changed file contents.
4. If no diff vs base, stop with a short message.

### 1. Simplify (optional)

If the simplify command is available, follow it on the current branch diff scope.

- If simplify produced changes, commit as one batch: `chore: simplify <scope>`
- If unavailable, note `Simplify: skipped` and continue.

### 2. Thermos (required)

Follow the thermos command or thermos plugin skill. Do not duplicate its workflow here.

Normalize every finding to P0–P3:

| Level  | Thermo signals (examples)                                                                                         |
| ------ | ----------------------------------------------------------------------------------------------------------------- |
| **P0** | Security vuln, data loss, breaking functionality/devex, feature-flag leak, high-confidence correctness bug        |
| **P1** | High-impact contract break, code-quality approval-bar blockers (1k-line sprawl, spaghetti growth, boundary leaks) |
| **P2** | Moderate maintainability / edge-case issues                                                                       |
| **P3** | Low-impact nits                                                                                                   |

Each finding must include: `#`, severity, `file:line`, one-line title, evidence snippet, suggested fix (if known).

### 3. Fix

Extract only issues matching the **target levels**. Ignore all other levels unless the user explicitly expands scope mid-run.

Produce a **triage table** ordered by severity first (P0 → P3 among targets), then high impact / low fix risk. Present the queue briefly; proceed unless the user redirects. Findings marked **intentional/accepted** or **invalid on re-check** move to "Deferred" and do not block exit.

For **one** target-level finding at a time (highest severity first):

1. Re-read cited `file:line`; skip if evidence no longer matches (note why).
2. Implement the **smallest correct fix** for that finding only.
3. Run `make lint && make test`.
4. **Commit** — one git commit per finding:

   ```text
   fix(review): resolve thermos #N — <short title>
   ```

5. Move to the next queued finding **without** re-running thermos mid-queue.

Repeat step 3 until the fix queue is empty, then continue to step 4.

### 4. Verify

If the verifier command or [`.claude/agents/verifier.md`](../../.claude/agents/verifier.md) is available, follow it. Otherwise run `make lint && make test`.

- If verification fails, fix and commit, then re-run step 4.
- If verification passes and step 2 reported zero target-level issues → go to **Done**.
- If verification passes but target-level issues may remain, increment iteration count and return to step 1.

## Commit rules

- Commit only when an issue is fully resolved.
- Follow repo commit style (`type(scope): description` per CLAUDE.md).
- Do not push unless the user asks.
- Never use `--no-verify` or skip hooks.
- If a pre-commit hook modifies files, fix and create a **new** commit (do not amend unless amend rules apply).

## Progress reporting

After each iteration, briefly report:

- Simplify: ran / skipped
- Issue fixed (ID/title, severity)
- Commit SHA and message
- Verify: pass / fail
- Remaining count per target level

Use this output template each iteration:

```markdown
## Loop-on-thermos — iteration N (targets: P0, P1)

### Pipeline

- Simplify: ran | skipped
- Thermos: N findings in scope
- Verify: pass | fail

### Findings in scope

| #   | Sev | File | Title | Triage |
| --- | --- | ---- | ----- | ------ |

### Outside target levels (informational)

| #   | Sev | File | Title |
| --- | --- | ---- | ----- |

### This iteration

- Fixed: #… (commit abc1234)
- Deferred: #… (reason)

### Status

- Target levels: P0, P1
- Remaining per level: P0=N, P1=N, …
- Outside targets (not blocking): N
- Next: <fix #X | verify | re-loop | done>
```

## Done

When thermos reports no issues at any target level **and** verification passes:

- Summarize all commits made in the loop
- List any remaining issues outside target levels (informational only)
- Confirm the loop is complete
- Do **not** auto-push unless the user asks.

## Guardrails

- One finding per commit; no drive-by refactors.
- Do not "fix" target-level findings that are intentional scope — defer with rationale instead.
- **Stuck handling:** after **5 full loop cycles** with the same target-level finding persisting, stop and ask the user.
- **Max scope creep:** if a fix requires touching >3 files or a design change, pause triage and ask before proceeding.
