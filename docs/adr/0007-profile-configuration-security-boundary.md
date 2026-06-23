# ADR 0007: Profile configuration security boundary

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** Maintainers

## Context

`.gcpctx.toml` declares profiles, projects, service accounts, and optional environment overrides. Without validation and limits, a malicious config could inject shell metacharacters, arbitrary environment variables, or route secrets through `env` tables.

## Decision

Treat `.gcpctx.toml` as **untrusted input**. Version 1 schema is validated strictly:

- Profile names: alphanumeric plus `_.-`
- Project IDs and service account emails: conservative patterns
- `default_profile` must exist in `profiles`
- `profiles.*.env` keys are **allowlisted** in v0.1 (`CLOUDSDK_CORE_DISABLE_PROMPTS`, `CLOUDSDK_CORE_PROJECT`, `CLOUDSDK_COMPUTE_REGION`, `CLOUDSDK_COMPUTE_ZONE` only)

Context IDs are derived deterministically from canonical root, profile, project, service account, config SHA-256, and schema version. Including the config hash means identity changes allocate **new** isolated state instead of mutating old contexts.

## Consequences

- Arbitrary secret injection via `env` is blocked in v0.1.
- Config edits change the config hash → approval invalidation and new context directory (ADR-0005).
- Shell rendering only emits validated values with robust quoting.

## Alternatives considered

- **Arbitrary `env` keys:** Rejected — turns repo config into a general env/secret router.
- **Unsafe flag for extra env keys:** Deferred — explicit escape hatch possible in v0.2.
- **Context ID without config hash:** Rejected — stale state after SA/project change.

## Trade-offs

- Less flexibility for exotic `CLOUDSDK_*` overrides until allowlist expands.
- Strict validation may reject valid but unusual GCP resource names at the conservative regex boundary.

## References

- ADR-0005 (config-hash in approvals)
- ADR-0006 (shell quoting of validated values)
