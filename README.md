# gcpctx

Directory-scoped Google Cloud service account impersonation contexts for terminals, IDEs, and coding agents.

## What is gcpctx?

`gcpctx` automatically activates an isolated Google Cloud SDK and Application Default Credentials (ADC) environment when you enter a directory with a `.gcpctx.toml` file. Each profile maps to a GCP project and an impersonated service account. Activation exports a dedicated `CLOUDSDK_CONFIG` so your global `~/.config/gcloud` is never mutated.

## Why directory-scoped impersonation?

Developers and coding agents often inherit broad or wrong GCP credentials from the parent shell. `gcpctx` scopes authentication to the repository you are working in, with first-use approval and config-hash invalidation when trust-relevant settings change.

## Installation

Choose one of these options:

| Method                            | Best for                                             |
| --------------------------------- | ---------------------------------------------------- |
| [`uvx`](#run-with-uvx-no-install) | Try without installing, CI one-offs, pinned versions |
| [`pipx`](#pipx)                   | Daily CLI use on your machine                        |
| [From source](#from-source)       | Contributing or unreleased builds                    |

### Run with `uvx` (no install)

[`uvx`](https://docs.astral.sh/uv/guides/tools/) runs `gcpctx` in an ephemeral environment—no global install required.

```bash
# Latest from PyPI (when published)
uvx gcpctx --help

# Pin a version
uvx gcpctx@0.2.0 status

# Run from a local checkout (before publish)
uvx --from /path/to/gcpctx gcpctx --help
```

Typical workflow with `uvx`:

```bash
cd my-repo
uvx gcpctx init-project \
  --project my-dev-project \
  --service-account agent-dev@my-dev-project.iam.gserviceaccount.com

uvx gcpctx approve
eval "$(uvx gcpctx activate --shell zsh)"

uvx gcpctx status
uvx gcpctx doctor
```

Shell hooks installed via `gcpctx init zsh` call `gcpctx` on your `PATH`. After choosing `uvx`, either add a shell alias (`alias gcpctx='uvx gcpctx'`) or install with `pipx` / `uv tool install` for hook integration.

### pipx

```bash
pipx install gcpctx
gcpctx --help
```

### From source

```bash
git clone <repo-url> && cd gcpctx
uv sync
uv run gcpctx --help
# optional: uv tool install -e .
```

## Quick start

```bash
# 1. Create project config
gcpctx init-project --project my-dev-project \
  --service-account agent-dev@my-dev-project.iam.gserviceaccount.com

# 2. Approve and activate (zsh example)
gcpctx approve
eval "$(gcpctx activate --shell zsh)"

# 3. Verify
gcpctx status
gcloud config list
```

## `.gcpctx.toml` example

```toml
version = 1
default_profile = "dev"

[profiles.dev]
project = "my-dev-project"
service_account = "agent-dev@my-dev-project.iam.gserviceaccount.com"
quota_project = "my-billing-project"
region = "asia-northeast1"
```

## Shell integration

```bash
gcpctx init zsh   # or: gcpctx init bash
exec $SHELL       # reload shell
```

The hook runs `gcpctx hook eval` on every directory change. **Stdout is shell code only**; diagnostics go to stderr.

Manual activation without hooks:

```bash
eval "$(gcpctx activate --shell zsh)"
eval "$(gcpctx deactivate --shell zsh)"  # restore prior env
```

Switch profile (after `gcpctx init` installs the wrapper):

```bash
gcpctx-use prod-readonly
```

## IDE usage (VS Code, Cursor, JetBrains)

Integrated terminals **inherit the parent shell environment**. Subprocesses started by the IDE (build tasks, debuggers, test runners) see the same `CLOUDSDK_CONFIG`, ADC, and `GCPCTX_*` variables as your shell.

### Recommended setup

1. Install shell hooks (`gcpctx init zsh`) or manually `eval "$(gcpctx activate --shell zsh)"` in your login shell.
2. Open the IDE **from that shell** (`cursor .`, `code .`) so new integrated terminals start activated.
3. Confirm with `gcpctx status` in an integrated terminal.

### Verify isolation

```bash
gcpctx status
gcpctx doctor
gcpctx doctor --json   # machine-readable for scripts
```

Doctor checks that `CLOUDSDK_CONFIG` lives under `~/.cache/gcpctx/contexts/`, gcloud project/impersonation match your profile, and ADC is initialized.

**`GOOGLE_APPLICATION_CREDENTIALS`**

In hook mode, `GOOGLE_APPLICATION_CREDENTIALS` is unset while active (previous value restored on deactivate) so ADC impersonation is not overridden. If you must keep a key file in non-interactive sessions, pass `--allow-google-application-credentials` to `activate`.

## Coding agents (Cursor, Claude Code, Codex, Copilot)

Agents run in terminals or sandboxes that inherit environment variables. Use either **shell activation** (whole session) or **`gcpctx run`** (one process only).

### Process-scoped launch (recommended for agents)

Run a command with per-project credentials **without** changing your parent shell:

```bash
gcpctx approve
gcpctx run -- claude
uvx gcpctx run -- codex ...
gcpctx run --profile dev -- gcloud storage ls
```

- Requires `.gcpctx.toml` in the current directory tree (exit 2 if missing).
- Pre-approve for non-interactive terminals (`gcpctx approve`).
- `GOOGLE_APPLICATION_CREDENTIALS` is unset in the child by default (same as hook mode).
- Access tokens are short-lived; client libraries refresh ADC automatically (no gcpctx supervisor).

### Shell activation (whole session)

1. Add `.gcpctx.toml` to the repo (`gcpctx init-project`).
2. **Approve once** interactively, or pre-approve for automation:

   ```bash
   gcpctx approve   # remembered approval for this directory/profile
   ```

3. Activate in the shell that launches the agent:

   ```bash
   eval "$(gcpctx activate --shell zsh)"
   ```

4. Agents and their subprocesses inherit isolated credentials.

### Non-interactive / fail-closed

Without a matching approval, `gcpctx activate` exits with code **3** in non-interactive mode (typical agent terminals). Pre-run `gcpctx approve` in CI or document that users must activate interactively once.

### Agent-friendly diagnostics

```bash
gcpctx doctor --json
gcpctx status --json
```

Parse JSON for `active`, `cloudsdk_config`, `approval`, and per-check status from doctor.

**When `GOOGLE_APPLICATION_CREDENTIALS` is required**

Some tools insist on a key file path. Use `--allow-google-application-credentials` only when necessary; prefer impersonated ADC otherwise.

## Security model (v0.2)

- **POSIX only** — Windows is unsupported; the CLI fails closed until ACL checks land.
- First-use approval with remember + **TTL** (default 30 days); schema v2 binds **gcloud path and fingerprint**
- Config SHA-256 binding invalidates approval when project, service account, or config changes
- **Immutable project identity** — `CLOUDSDK_CORE_PROJECT` always matches `profile.project` (cannot set via `env`)
- Isolated `CLOUDSDK_CONFIG` under `~/.cache/gcpctx/contexts/`
- Atomic, locked, symlink-safe writes for approvals and context state (`0600`/`0700`)
- gcloud binary trust validation (repo-local shadowing, world-writable parents, optional allowlist)
- Service account impersonation only (no long-lived key files in repo config)
- `GOOGLE_APPLICATION_CREDENTIALS` unset by default in hook mode (restored on deactivate)
- Optional **`policy.toml`** for org-style allowlists and strict mode
- **`gcpctx doctor --strict --json`** for CI/agent compliance gates
- Append-only **`audit.jsonl`** for security events (no credential material)

See [SECURITY.md](SECURITY.md) and [Architecture decision records](docs/adr/) (ADR-0003 through ADR-0009).

### Upgrading from v0.1

- Remove any `[profiles.*.env] CLOUDSDK_CORE_PROJECT` entries — use `profile.project` instead.
- Service account emails must use the same GCP project as `profile.project` (e.g. `agent@my-dev-project.iam.gserviceaccount.com` for `project = "my-dev-project"`). Cross-project impersonation is not supported in v0.2.
- Re-run `gcpctx approve` after upgrade (approval schema v2 adds gcloud binding and expiry).
- Pin gcloud if needed: `gcpctx config set-gcloud-path "$(which gcloud)"` (optional; pinning overrides PATH — run `gcpctx config unset-gcloud-path` if you move gcloud after Homebrew or mise upgrades)

### Policy file (optional)

`~/.config/gcpctx/policy.toml` or `$GCPCTX_POLICY_PATH`:

```toml
version = 1
[policy]
mode = "strict"
approval_ttl_days = 30
require_initialized_adc_for_hook = true
[allow]
projects = ["dev-*"]
[gcloud]
allowed_paths = ["/opt/google-cloud-sdk/bin/gcloud"]
```

### Strict doctor

```bash
gcpctx doctor --strict --json
```

Non-zero exit when isolation, approval, ADC, IAM impersonation, or filesystem posture is unsafe.

## Troubleshooting

| Symptom                         | Fix                                                               |
| ------------------------------- | ----------------------------------------------------------------- |
| `approval required` in CI/agent | Run `gcpctx approve` once, or activate interactively              |
| Wrong project                   | `gcpctx status`; check `.gcpctx.toml`                             |
| Stale credentials               | `gcpctx refresh` or `gcpctx reset`                                |
| `gcloud` not found              | Install [Google Cloud SDK](https://cloud.google.com/sdk)          |
| ADC issues                      | `gcpctx doctor`                                                   |
| IDE terminal not activated      | Activate in parent shell before launching IDE, or use shell hooks |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for developer setup, tests, and architecture notes.
