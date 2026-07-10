# Doctor check: `ambient_cloudsdk`

Checks that the process `CLOUDSDK_CONFIG` matches the expected managed context directory.

**Remediation:** `eval "$(gcpctx activate --shell zsh)"`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `ambient_cloudsdk`.
