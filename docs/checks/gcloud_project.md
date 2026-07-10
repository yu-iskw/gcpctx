# Doctor check: `gcloud_project`

Reads gcloud `core/project` in the isolated config and compares it to the profile project.

**Remediation:** `gcpctx reload`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `gcloud_project`.
