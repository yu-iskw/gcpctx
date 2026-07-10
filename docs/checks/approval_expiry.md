# Doctor check: `approval_expiry`

Reports remembered approvals that have passed their TTL and need re-approval.

**Remediation:** `gcpctx approve`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `approval_expiry`.
