# {{ project_name }}

A production-ready Python package using modern tooling.

## Features

- **Package Management**: [uv](https://github.com/astral-sh/uv)
- **Build System**: [Hatchling](https://hatch.pypa.io/latest/)
- **Linting & Formatting**: [Trunk](https://trunk.io/) (Ruff, Pyright, Pylint, Bandit; Ruff is also the formatter)
- **Testing**: [pytest](https://docs.pytest.org/)
- **CI/CD**: GitHub Actions

## Security & Quality

This template enforces high security and maintainability standards:

- **[GitHub CodeQL](https://codeql.github.com/)**: Deep analysis using the `security-and-quality` suite to track code health and catch vulnerabilities.
- **Complexity Guardrails**: Cyclomatic complexity is capped at **10** per function (enforced via Ruff `C901`).
- **Trunk Linters**: [Bandit](https://github.com/PyCQA/bandit) (security), [Semgrep](https://semgrep.dev/) (patterns), [Trivy](https://github.com/aquasecurity/trivy) (IaC/Secret scanning), and [OSV-Scanner](https://github.com/google/osv-scanner) (dependencies).

## Development

Conventions, build commands, and AI-agent instructions: see [AGENTS.md](AGENTS.md). Claude Code–specific config lives in `CLAUDE.md` (it imports [AGENTS.md](AGENTS.md)) and in [`.claude/`](.claude/).

```bash
make setup-tools  # mise install --locked + mise run trunk-install
make setup        # setup-tools + Python venv (uv)
make lint         # mise run lint (Trunk)
make format       # mise run format-trunk + ssort
make test         # Run pytest test suite
make scan-vulnerabilities  # Trivy, OSV-Scanner, Grype (serial via mise)
make codeql       # Local CodeQL (x64 or Rosetta on ARM64; see AGENTS.md)
```

On Linux or macOS **ARM64**, CodeQL from `mise.lock` is an x64 bundle. `make setup-tools` skips the version check; use x64 hosts or emulation for `make codeql`.
