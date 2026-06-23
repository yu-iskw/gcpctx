# ADR 0008: Process-scoped execution via `gcpctx run`

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** Maintainers

## Context

Shell activation (`eval "$(gcpctx activate)"`) mutates the parent shell environment. Coding agents launched as one-shot processes (for example `claude`, `codex`) benefit from **per-project credentials confined to that process** without polluting the parent shell or unrelated terminals. ADR-0006 deferred IDE extensions; ADR-0003 deferred a credential broker daemon.

## Decision

Add **`gcpctx run -- COMMAND [ARGS...]`** that:

1. Runs the same activation path as `activate` (discover config, approval, `ensure_initialized`, GAC policy).
2. Builds a child environment from `ActivationResult.exports` and `unsets` via `child_environ()`.
3. Runs the child via `run_command()` in `src/gcpctx/runner.py` with inherited stdio (parent exits with the child return code).

The parent shell is **not** modified. Missing `.gcpctx.toml` is a hard error (exit 2), not a hook-style noop.

**Stable invariants:**

- Inherits ADR-0003 (`CLOUDSDK_CONFIG` isolation), ADR-0004 (impersonation), ADR-0005 (approval), ADR-0006 (GAC unset by default in run mode).
- Diagnostics and warnings go to stderr only.
- No token broker or background refresh supervisor; ADC refresh remains library-side (google-auth).

## Consequences

- Agents can be launched with `gcpctx run -- claude` after `gcpctx approve`.
- Non-interactive run requires pre-approval (fail-closed, exit 3).
- Unix-first; Windows parity deferred.

## Alternatives considered

- **Shell activate only:** Rejected for one-shot agents — credentials leak to the whole shell session.
- **Credential broker daemon:** Deferred — operational complexity (ADR-0003).
- **subprocess.run parent:** Accepted — inherits stdio for interactive CLIs; avoids `exec` security linter noise while parent shell stays unchanged.

## Trade-offs

- `run` always runs gcloud init (unlike hook eval's `skip_gcloud_init`); debounce still applies via cached state.
- Child must use ADC or `CLOUDSDK_CONFIG`; tools ignoring both still need separate guidance.

## References

- ADR-0003 (isolation)
- ADR-0004 (impersonation / ADC refresh)
- ADR-0005 (approval)
- ADR-0006 (shell contract; `run` complements hook/activate)
