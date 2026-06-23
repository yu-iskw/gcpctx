# ADR 0006: Shell activation and environment contract

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** Maintainers

## Context

`gcpctx` integrates with zsh and bash via hooks that `eval` emitted shell code. Human-readable output on stdout would break activation. Prior `CLOUDSDK_CONFIG` and `GOOGLE_APPLICATION_CREDENTIALS` values must be restored on deactivate. `GOOGLE_APPLICATION_CREDENTIALS` overrides ADC discovery and can break isolation expectations.

## Decision

v0.1 integrates via **zsh `chpwd` and bash `PROMPT_COMMAND` hooks** (no IDE extension). Commands that emit shell code (`activate`, `deactivate`, `hook eval`, `use --shell`) write **only valid shell assignments to stdout**; diagnostics go to stderr.

Before activation, backup:

- `GCPCTX_PREV_CLOUDSDK_CONFIG`
- `GCPCTX_PREV_GOOGLE_APPLICATION_CREDENTIALS`

On deactivation, restore or unset originals. In hook mode, `GOOGLE_APPLICATION_CREDENTIALS` is unset by default (with backup). Non-interactive activation fails if GAC is set unless `--allow-google-application-credentials` is passed. All exported values use safe single-quote escaping.

**Stable invariants:**

- `hook eval` stdout is shell-code-only.
- Deactivation restores prior cloud credential environment.

## Consequences

- Shell hooks are brittle if stdout is polluted; tests enforce quoting and `bash -n` syntax.
- Users with a pre-set GAC see warnings or must opt in explicitly.
- Profile switching uses `gcpctx-use` wrapper or manual `eval`.

## Alternatives considered

- **VSCode/Cursor extension:** Deferred — inherited env sufficient for v0.1.
- **direnv integration:** Open question for v0.2.
- **PowerShell:** Out of scope for v0.1.
- **Keep GAC when set:** Rejected as default — breaks ADC isolation semantics.

## Trade-offs

- Requires users to install shell hooks or run manual `eval`.
- Hook runs on every directory change (mitigated by gcloud init debounce).

## References

- ADR-0003 (inherited environment)
- ADR-0004 (ADC vs gcloud)
