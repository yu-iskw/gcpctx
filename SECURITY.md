# Security Policy

## Supported platforms

gcpctx **v0.2** provides its security guarantees on **POSIX systems only** (Linux and macOS). Windows is **not supported**; the CLI fails closed on `win32` until filesystem ACL checks are implemented.

Shell integration targets **bash** and **zsh**.

## Threat model

### Trust boundaries

| Boundary                                   | Trust level               | Notes                                                                                                   |
| ------------------------------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------- |
| `.gcpctx.toml` in a repository             | **Untrusted**             | Validated strictly; cannot override project identity or credential paths                                |
| `~/.config/gcpctx/` and `~/.cache/gcpctx/` | **Trusted user state**    | Atomic writes, advisory locks, symlink rejection, `0600`/`0700` permissions                             |
| `gcloud` binary                            | **Conditionally trusted** | Resolved path validated; optional per-project pin in `.gcpctx.toml` via `gcpctx config set-gcloud-path` |
| `policy.toml`                              | **User/org policy**       | Optional allowlists and strict mode                                                                     |

### Threats mitigated in v0.2

- **Project split-brain** — `CLOUDSDK_CORE_PROJECT` is always set from `profile.project`; config cannot override it.
- **State tampering** — Approvals and context state use atomic replace, `O_NOFOLLOW`, and file locking.
- **Symlink attacks** — Config and managed state paths reject symlinks on read/write.
- **PATH hijacking** — gcloud path trust checks (repo-local binary, world-writable parents, optional allowlist).
- **Stale trust** — Remembered approvals expire (default 30 days) and bind gcloud path/fingerprint in strict mode.
- **False credential readiness** — Shell hooks do not export credential surface unless ADC is initialized (when policy requires it).

### Out of scope

gcpctx does not replace Google IAM design, repository branch protection, endpoint MDM, or org-wide PAM. Use IAM Conditions, audit logs, and workstation policy alongside this tool.

## v0.2 acceptance criteria

1. No config-controlled environment variable can alter effective project, credential file, ADC path, or `CLOUDSDK_CONFIG`.
2. Approval and context-state writes are atomic, locked, symlink-safe, and owner-only.
3. gcloud binary trust is checked and included in remembered approvals (schema v2).
4. `gcpctx doctor --strict --json` fails CI/agent startup when posture is unsafe.
5. PyPI releases use Trusted Publishing (OIDC); SBOM and provenance artifacts attach to GitHub Releases.

## Compliance gate

For CI, IDE startup, or agent preflight:

```bash
gcpctx doctor --strict --json
```

Non-zero exit indicates an actionable security finding. See check names in JSON output (`gcloud_trust`, `state_permissions`, `impersonation_iam`, `approval_expiry`, etc.).

## Policy file

Optional `~/.config/gcpctx/policy.toml` or `$GCPCTX_POLICY_PATH` enables org-style constraints (project allowlists, approval TTL, strict hook ADC requirement). See README for schema.

## Reporting a vulnerability

If you believe you have found a security vulnerability in gcpctx:

1. **Do not** open a public GitHub issue for sensitive reports.
2. Email the maintainer via the contact on [PyPI](https://pypi.org/project/gcpctx/) or open a private security advisory on GitHub if enabled for this repository.
3. Include reproduction steps, impact assessment, and affected version.

We aim to acknowledge reports within 5 business days.

## Secure development

- No `shell=True` for subprocess invocation.
- No logging of ADC contents, tokens, or `GOOGLE_APPLICATION_CREDENTIALS` paths in audit events.
- Audit log is append-oriented with owner-only permissions enforced on each write.
- Run `make lint` and vulnerability scans before release (see CONTRIBUTING.md).
