# Doctor check: `env_project`

Fails when ambient `CLOUDSDK_CORE_PROJECT` disagrees with the profile project identity.

**Remediation:** `eval "$(gcpctx activate --shell zsh)"`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `env_project`.
