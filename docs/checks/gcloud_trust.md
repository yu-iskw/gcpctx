# Doctor check: `gcloud_trust`

Validates the gcloud binary path against trust policy (allowlists, cwd placement, permissions).

**Remediation:** `gcpctx config "$(which gcloud)"`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `gcloud_trust`.
