# Doctor check: `approval`

Requires a matching, unexpired first-use approval for this directory/profile identity.

**Remediation:** `gcpctx approve`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `approval`.
