# Doctor check: `state_permissions`

Strict-only: verifies approvals, config, cache, and audit paths have safe ownership/modes.

**Remediation:** `chmod 700 ~/.cache/gcpctx && chmod 600 ~/.config/gcpctx/approvals.json`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `state_permissions`.
