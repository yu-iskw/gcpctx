# Doctor check: `gac`

Flags `GOOGLE_APPLICATION_CREDENTIALS` when set, because it can override managed ADC.

**Remediation:** `unset GOOGLE_APPLICATION_CREDENTIALS`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `gac`.
