# Doctor check: `expected_context`

Ensures the derived isolated `CLOUDSDK_CONFIG` path lives under the gcpctx cache (ADR-0003).

**Remediation:** `eval "$(gcpctx activate --shell zsh)"`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `expected_context`.
