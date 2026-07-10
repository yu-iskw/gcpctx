# Doctor check: `impersonation`

Reads gcloud impersonation property and compares it to the profile service account.

**Remediation:** `gcpctx reload`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `impersonation`.
