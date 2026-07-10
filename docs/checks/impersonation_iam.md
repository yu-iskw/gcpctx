# Doctor check: `impersonation_iam`

Strict-only: probes IAM token minting for the profile service account via gcloud.

**Remediation:** `Grant roles/iam.serviceAccountTokenCreator on the service account`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `impersonation_iam`.
