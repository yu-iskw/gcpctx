# Copyright 2025 yu-iskw
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Typer CLI for gcpctx."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Literal

import typer
from rich.console import Console
from rich.table import Table

from gcpctx import activation, cleanup
from gcpctx.approvals import add_approval, revoke_approval
from gcpctx.config import (
    load_project_config,
    render_init_project_toml,
    resolve_existing_gcloud_binary,
    set_project_gcloud_path,
    unset_project_gcloud_path,
    validate_init_project_inputs,
)
from gcpctx.discovery import config_path, find_project_root
from gcpctx.doctor import run_doctor, status_info
from gcpctx.errors import (
    ConfigNotFoundError,
    ConfigValidationError,
    GcpctxError,
    UnsupportedPlatformError,
)
from gcpctx.exit_codes import ExitCode
from gcpctx.gcloud_trust import resolve_trusted_gcloud
from gcpctx.logging import log_stderr
from gcpctx.models import ActivationRequest, ActivationResult
from gcpctx.policy import load_policy
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context
from gcpctx.runner import run_command
from gcpctx.security import ensure_file, is_posix_platform
from gcpctx.shell import (
    render_init_for_shell,
    render_shell,
)

app = typer.Typer(
    name="gcpctx",
    help="Directory-scoped Google Cloud service account impersonation contexts.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Fail closed on unsupported platforms before any subcommand runs."""
    try:
        if not is_posix_platform():
            msg = (
                "gcpctx requires a POSIX platform (Linux or macOS). "
                "Windows is not supported until filesystem ACL checks are implemented."
            )
            raise UnsupportedPlatformError(msg)  # noqa: TRY301
    except UnsupportedPlatformError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc


init_app = typer.Typer(help="Install shell integration.")
hook_app = typer.Typer(help="Shell hook commands.")
config_app = typer.Typer(help="Project gcloud settings.")
app.add_typer(init_app, name="init")
app.add_typer(hook_app, name="hook")
app.add_typer(config_app, name="config")

ShellOpt = Annotated[
    Literal["bash", "zsh"],
    typer.Option("--shell", help="Target shell (bash or zsh)."),
]


def _require_project_context(
    cwd: Path | None = None,
    profile: str | None = None,
) -> ResolvedProjectContext:
    """Resolve project context or exit with config error."""
    try:
        return resolve_project_context((cwd or Path.cwd()).resolve(), profile)
    except ConfigNotFoundError:
        typer.echo("No .gcpctx.toml found", err=True)
        raise typer.Exit(code=int(ExitCode.CONFIG_NOT_FOUND)) from None
    except GcpctxError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc


def _run_activation(request: ActivationRequest) -> ActivationResult:
    """Activate and log warnings to stderr."""
    result = activation.activate(request)
    for warning in result.warnings:
        log_stderr(f"warning: {warning}")
    return result


def _shell_from_option(shell: str) -> Literal["bash", "zsh"]:
    if shell not in {"bash", "zsh"}:
        typer.echo(f"unsupported shell: {shell}", err=True)
        raise typer.Exit(code=1)
    if shell == "bash":
        return "bash"
    return "zsh"


def _handle_error(exc: Exception) -> None:
    if isinstance(exc, GcpctxError):
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo(str(exc), err=True)
    raise typer.Exit(code=1) from exc


def _emit_shell(result: ActivationResult, shell: Literal["bash", "zsh"]) -> None:
    code = render_shell(result, shell)
    sys.stdout.write(code)
    if code:
        sys.stdout.write("\n")


_INIT_RC: dict[Literal["bash", "zsh"], str] = {
    "zsh": "~/.zshrc",
    "bash": "~/.bashrc",
}


def _emit_init(shell: Literal["bash", "zsh"]) -> None:
    sys.stdout.write(render_init_for_shell(shell))
    _emit_init_instructions(_INIT_RC[shell])


@app.command()
def profiles(
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """List profiles in the nearest .gcpctx.toml."""
    work = (cwd or Path.cwd()).resolve()
    root = find_project_root(work)
    if root is None:
        typer.echo("No .gcpctx.toml found", err=True)
        raise typer.Exit(code=2)
    config = load_project_config(root, policy=load_policy())
    typer.echo(f"Profiles in {config_path(root)}\n")
    for name, prof in config.profiles.items():
        marker = "*" if name == config.default_profile else " "
        typer.echo(f"{marker} {name:<15} {prof.project:<20} {prof.service_account}")


@app.command()
def activate(
    shell: ShellOpt = "zsh",
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
    allow_google_application_credentials: Annotated[
        bool,
        typer.Option("--allow-google-application-credentials"),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Emit shell code to activate gcpctx in the current shell."""
    shell_name = _shell_from_option(shell)
    try:
        result = _run_activation(
            ActivationRequest(
                cwd=(cwd or Path.cwd()).resolve(),
                shell_name=shell_name,
                profile=profile,
                interactive=sys.stdin.isatty(),
                allow_google_application_credentials=allow_google_application_credentials,
            )
        )
        if json_output:
            typer.echo(result.model_dump_json())
            return
        _emit_shell(result, shell_name)
    except GcpctxError as exc:
        _handle_error(exc)


@app.command()
def deactivate(
    shell: ShellOpt = "zsh",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Emit shell code to deactivate gcpctx."""
    shell_name = _shell_from_option(shell)
    result = activation.deactivate()
    if json_output:
        typer.echo(result.model_dump_json())
        return
    _emit_shell(result, shell_name)


@hook_app.command("eval")
def hook_eval(
    shell: Annotated[str, typer.Argument(help="bash or zsh")],
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Evaluate hook for directory changes (shell code on stdout only)."""
    shell_name = _shell_from_option(shell)
    work = (cwd or Path.cwd()).resolve()
    try:
        if find_project_root(work) is None:
            result = activation.missing_config_result()
        else:
            result = _run_activation(
                ActivationRequest(
                    cwd=work,
                    shell_name=shell_name,
                    hook_mode=True,
                    skip_gcloud_init=True,
                    interactive=sys.stdin.isatty(),
                )
            )
        _emit_shell(result, shell_name)
    except GcpctxError as exc:
        _emit_shell(activation.deactivate(), shell_name)
        _handle_error(exc)


@app.command()
def status(
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show active gcpctx context."""
    info = status_info((cwd or Path.cwd()).resolve())
    if json_output:
        typer.echo(json.dumps(info, indent=2))
        return
    if info.get("active") != "true":
        typer.echo("gcpctx inactive")
        return
    typer.echo("gcpctx active\n")
    for key in (
        "root",
        "profile",
        "project",
        "service_account",
        "cloudsdk_config",
        "adc",
        "approval",
    ):
        if key in info:
            display_key = key.replace("_", " ")
            label_colon = f"{display_key.title()}:"
            typer.echo(f"{label_colon:<18} {info[key]}")


@app.command()
def doctor(
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    strict: Annotated[bool, typer.Option("--strict", help="Fail on warnings.")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run diagnostic checks."""
    result = run_doctor(
        (cwd or Path.cwd()).resolve(),
        profile=profile,
        strict=strict,
    )
    if json_output:
        typer.echo(result.model_dump_json(indent=2))
        raise typer.Exit(code=result.exit_code)
    console = Console()
    table = Table("Check", "Status", "Message", "Remediation")
    for check in result.checks:
        table.add_row(
            check.id,
            check.status,
            check.message,
            check.remediation.display_text() if check.remediation else "",
        )
    console.print(table)
    raise typer.Exit(code=result.exit_code)


@app.command()
def approve(
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Remember approval for the current directory/profile."""
    try:
        ctx = _require_project_context(cwd, profile)
        policy = load_policy()
        trust = resolve_trusted_gcloud(ctx.root, policy=policy, configured_path=ctx.gcloud_path)
        add_approval(ctx, mode="remembered", policy=policy, gcloud_trust=trust)
        typer.echo(f"Remembered approval for profile {ctx.profile_name!r} at {ctx.root}")
    except GcpctxError as exc:
        _handle_error(exc)


@app.command()
def revoke(
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Revoke remembered approval."""
    ctx = _require_project_context(cwd, profile)
    removed = revoke_approval(ctx)
    if removed:
        typer.echo(f"Revoked approval for profile {ctx.profile_name!r}")
    else:
        typer.echo("No matching approval found", err=True)
        raise typer.Exit(code=3)


@app.command()
def refresh(
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Force re-initialization of gcloud and ADC."""
    try:
        _run_activation(
            ActivationRequest(
                cwd=(cwd or Path.cwd()).resolve(),
                shell_name="zsh",
                profile=profile,
                interactive=False,
                force_refresh=True,
            )
        )
        typer.echo("Context refreshed")
    except GcpctxError as exc:
        _handle_error(exc)


@app.command()
def reset(
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Delete isolated context and reinitialize."""
    root = find_project_root((cwd or Path.cwd()).resolve())
    if root is None:
        typer.echo("No .gcpctx.toml found", err=True)
        raise typer.Exit(code=2)
    ctx_id = os.environ.get("GCPCTX_CONTEXT_ID")
    if ctx_id:
        cleanup.remove_context(ctx_id)
    try:
        result = _run_activation(
            ActivationRequest(
                cwd=root,
                shell_name="zsh",
                profile=profile,
                interactive=False,
                force_refresh=True,
            )
        )
        typer.echo(f"Reset context {result.context_id}")
    except GcpctxError as exc:
        _handle_error(exc)


@app.command()
def clean(  # noqa: PLR0912, PLR0913
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
    all_contexts: Annotated[
        bool,
        typer.Option("--all-contexts", help="Remove all isolated context directories."),
    ] = False,
    approvals: Annotated[
        bool,
        typer.Option("--approvals", help="Remove remembered approvals store."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print paths that would be removed."),
    ] = False,
    reinit: Annotated[
        bool,
        typer.Option("--reinit", help="Re-initialize after project-scoped clean."),
    ] = False,
) -> None:
    """Remove isolated gcloud cache and/or approvals (never touches global gcloud config)."""
    try:
        if reinit and (all_contexts or approvals):
            msg = "--reinit requires project-scoped clean (omit --all-contexts and --approvals)"
            typer.echo(msg, err=True)
            raise typer.Exit(code=2)
        context_id: str | None = None
        work = (cwd or Path.cwd()).resolve()
        removed: list[Path] = []
        if all_contexts:
            removed.extend(cleanup.remove_all_contexts(dry_run=dry_run))
        if approvals:
            removed.extend(cleanup.remove_approvals(dry_run=dry_run))
        if not all_contexts and not approvals:
            ctx = _require_project_context(cwd, profile)
            context_id = ctx.context_id()
            removed.extend(cleanup.remove_context(context_id, dry_run=dry_run))
        if not removed:
            typer.echo("nothing to clean")
        else:
            prefix = "would remove" if dry_run else "removed"
            for path in removed:
                typer.echo(f"{prefix} {path}")
        if reinit and context_id is not None and not dry_run:
            _run_activation(
                ActivationRequest(
                    cwd=work,
                    shell_name="zsh",
                    profile=profile,
                    interactive=False,
                    force_refresh=True,
                )
            )
    except GcpctxError as exc:
        _handle_error(exc)


@app.command("use")
def use_profile(
    profile_name: Annotated[str, typer.Argument(help="Profile to activate.")],
    shell: ShellOpt = "zsh",
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Emit shell code to switch profile (source in parent shell)."""
    shell_name = _shell_from_option(shell)
    try:
        result = _run_activation(
            ActivationRequest(
                cwd=(cwd or Path.cwd()).resolve(),
                shell_name=shell_name,
                profile=profile_name,
                interactive=sys.stdin.isatty(),
            )
        )
        _emit_shell(result, shell_name)
    except GcpctxError as exc:
        _handle_error(exc)


@app.command(context_settings={"allow_extra_args": True})
def run(
    ctx: typer.Context,
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
    allow_google_application_credentials: Annotated[
        bool,
        typer.Option("--allow-google-application-credentials"),
    ] = False,
    force_refresh: Annotated[
        bool,
        typer.Option("--force-refresh", help="Force gcloud/ADC re-initialization."),
    ] = False,
) -> None:
    """Run a command with per-project credentials (parent shell unchanged)."""
    if not ctx.args:
        typer.echo("usage: gcpctx run [--profile NAME] -- COMMAND [ARGS...]", err=True)
        raise typer.Exit(code=2)
    cmd = list(ctx.args)
    if cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        typer.echo("usage: gcpctx run [--profile NAME] -- COMMAND [ARGS...]", err=True)
        raise typer.Exit(code=2)
    try:
        result = _run_activation(
            ActivationRequest(
                cwd=(cwd or Path.cwd()).resolve(),
                shell_name="zsh",
                profile=profile,
                interactive=sys.stdin.isatty(),
                run_mode=True,
                allow_google_application_credentials=allow_google_application_credentials,
                force_refresh=force_refresh,
            )
        )
        if not result.active:
            typer.echo("activation failed", err=True)
            raise typer.Exit(code=2)
        env = activation.child_environ(result)
        raise typer.Exit(code=run_command(cmd, env))
    except GcpctxError as exc:
        _handle_error(exc)


@app.command("init-project")
def init_project(
    project: Annotated[str | None, typer.Option(help="GCP project ID.")] = None,
    service_account: Annotated[
        str | None,
        typer.Option("--service-account", help="Service account email."),
    ] = None,
    profile: Annotated[str, typer.Option(help="Default profile name.")] = "dev",
    gcloud_path: Annotated[
        Path | None,
        typer.Option("--gcloud-path", help="Absolute path to gcloud binary."),
    ] = None,
    cwd: Annotated[Path | None, typer.Option(help="Target directory.")] = None,
) -> None:
    """Write a minimal .gcpctx.toml in the current directory."""
    target = (cwd or Path.cwd()).resolve()
    dest = target / ".gcpctx.toml"
    if dest.exists():
        typer.echo(f"{dest} already exists", err=True)
        raise typer.Exit(code=1)
    proj = project or typer.prompt("GCP project ID")
    sa = service_account or typer.prompt("Service account email")
    try:
        validate_init_project_inputs(project=proj, service_account=sa, profile=profile)
    except ConfigValidationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    resolved_gcloud: str | None = None
    if gcloud_path is not None:
        resolved_gcloud = str(resolve_existing_gcloud_binary(gcloud_path))
    content = render_init_project_toml(
        project=proj,
        service_account=sa,
        profile=profile,
        gcloud_path=resolved_gcloud,
    )
    ensure_file(dest, content)
    typer.echo(f"Wrote {dest}")


@config_app.command("show")
def config_show(
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Show gcloud_path from the project .gcpctx.toml."""
    root = find_project_root((cwd or Path.cwd()).resolve())
    if root is None:
        typer.echo("No .gcpctx.toml found", err=True)
        raise typer.Exit(code=2)
    config = load_project_config(root)
    if config.gcloud_path:
        typer.echo(f"gcloud_path = {config.gcloud_path}")
    else:
        typer.echo("gcloud_path = (unset, using PATH)")


@config_app.command("set-gcloud-path")
def config_set_gcloud_path(
    path: Annotated[
        Path,
        typer.Argument(help="Absolute path to gcloud binary (e.g. $(which gcloud))."),
    ],
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Pin the trusted gcloud binary path in .gcpctx.toml."""
    ctx = _require_project_context(cwd)
    try:
        set_project_gcloud_path(ctx.root, str(path.resolve()))
    except ConfigValidationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"Set gcloud_path to {path.resolve()} in {config_path(ctx.root)}")


@config_app.command("unset-gcloud-path")
def config_unset_gcloud_path(
    cwd: Annotated[Path | None, typer.Option(help="Working directory.")] = None,
) -> None:
    """Clear pinned gcloud path from .gcpctx.toml and use PATH resolution."""
    ctx = _require_project_context(cwd)
    unset_project_gcloud_path(ctx.root)
    typer.echo("Cleared gcloud_path (using PATH)")


@init_app.command("zsh")
def init_zsh() -> None:
    """Print zsh hook snippet to stdout."""
    _emit_init("zsh")


@init_app.command("bash")
def init_bash() -> None:
    """Print bash hook snippet to stdout."""
    _emit_init("bash")


def _emit_init_instructions(rc_file: str) -> None:
    log_stderr(
        f"Add the snippet above to {rc_file} (or redirect stdout: >> {rc_file}). "
        "Check for an existing '# >>> gcpctx hook >>>' block first to avoid duplicates.\n"
        "Ensure gcpctx is on PATH (pipx / uv tool install, or alias gcpctx='uvx gcpctx').\n"
        "Reload your shell: exec $SHELL"
    )


if __name__ == "__main__":
    app()
