# Doctor check: `config`

Validates that `.gcpctx.toml` exists under the project root and parses against the supported schema.

**Remediation:** `gcpctx create`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `config`.
