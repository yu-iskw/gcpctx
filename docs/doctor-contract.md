# Doctor JSON contract (v0.3)

`gcpctx doctor --json` is the canonical compliance gate for CI, IDE startup, and agent preflight. It is separate from `gcpctx status --json`, which reports activation state only.

## Top-level fields

| Field        | Type                     | Description                                    |
| ------------ | ------------------------ | ---------------------------------------------- |
| `version`    | string                   | Package version (e.g. `0.5.0`)                 |
| `status`     | `ok` \| `warn` \| `fail` | Aggregate outcome                              |
| `profile`    | string \| null           | Active profile when config resolves            |
| `context_id` | string \| null           | Stable context identifier when config resolves |
| `exit_code`  | integer                  | Process exit code (see below)                  |
| `checks`     | array                    | Per-check results                              |

## Check object

| Field         | Type                           | Description                             |
| ------------- | ------------------------------ | --------------------------------------- |
| `id`          | string                         | Stable check identifier                 |
| `severity`    | `error` \| `warning` \| `info` | Classification                          |
| `status`      | `pass` \| `warn` \| `fail`     | Check outcome                           |
| `message`     | string                         | Human-readable summary                  |
| `evidence`    | object                         | Safe diagnostic fields (paths, reasons) |
| `remediation` | object \| null                 | `command` and/or `docs`                 |

## Exit codes

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| 0    | OK                                               |
| 1    | Generic/unexpected error                         |
| 2    | No `.gcpctx.toml` or activation context mismatch |
| 3    | Approval required or expired                     |
| 4    | Policy or credential-surface violation           |
| 5    | Unsafe filesystem state                          |
| 6    | gcloud trust failure                             |
| 7    | ADC not initialized                              |
| 8    | IAM impersonation failure                        |
| 9    | Config or settings schema error                  |
| 10   | Unsupported platform                             |

Doctor uses `max(exit_code)` across failing checks.

## Check catalog

| Check id            | Exit when failing                                   | Strict only |
| ------------------- | --------------------------------------------------- | ----------- |
| `config`            | 2 or 9                                              | no          |
| `profile`           | 2                                                   | no          |
| `policy`            | 4                                                   | no          |
| `settings`          | 1 (warn-only; does not fail non-interactive doctor) | no          |
| `gcloud_trust`      | 6                                                   | no          |
| `approval`          | 3                                                   | no          |
| `approval_expiry`   | 3                                                   | no          |
| `expected_context`  | 2                                                   | no          |
| `ambient_cloudsdk`  | 2                                                   | no          |
| `env_project`       | 2                                                   | no          |
| `gcloud_project`    | 6                                                   | no          |
| `impersonation`     | 6                                                   | no          |
| `adc`               | 7                                                   | no          |
| `gac`               | 4                                                   | no          |
| `state_permissions` | 5                                                   | yes         |
| `impersonation_iam` | 8                                                   | yes         |

## Strict mode

With `--strict` or `policy.mode = "strict"`:

- Warnings are elevated to failures.
- `settings` deprecation warnings never change the process exit code (aggregate may still be `warn`).
- `state_permissions` and `impersonation_iam` checks run.
- Non-interactive runs fail on warnings even without `--strict` on the CLI when policy is strict.

## Example

```json
{
  "version": "0.5.0",
  "status": "fail",
  "profile": "dev",
  "context_id": "sha256:abc123…",
  "exit_code": 6,
  "checks": [
    {
      "id": "gcloud_trust",
      "severity": "error",
      "status": "fail",
      "message": "gcloud path is not in policy allowlist",
      "evidence": {
        "path": "/tmp/repo/gcloud",
        "reason": "trust_validation_failed"
      },
      "remediation": {
        "command": "gcpctx config \"$(which gcloud)\"",
        "docs": "docs/checks/gcloud_trust.md"
      }
    }
  ]
}
```

Per-check remediation docs live under [docs/checks/](checks/).
