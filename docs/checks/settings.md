# Doctor check: `settings`

Warns when deprecated keys such as global `gcloud_path` remain in `settings.toml`.

**Remediation:** `Remove deprecated keys from ~/.config/gcpctx/settings.toml`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `settings`.
