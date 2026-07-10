# Copyright 2025 yu-iskw
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Doctor service: gather Snapshot via ports -> pure checks -> Report."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from gcpctx import paths
from gcpctx.core.checks.evaluators import evaluate_all
from gcpctx.core.checks.report import findings_to_result
from gcpctx.core.checks.snapshot import ApprovalFacts, DoctorSnapshot
from gcpctx.discovery import find_project_root
from gcpctx.errors import ConfigNotFoundError, ConfigValidationError, GcpctxError
from gcpctx.policy import SecurityPolicy, load_policy
from gcpctx.project_context import resolve_project_context
from gcpctx.security import check_path_permissions, reject_symlink
from gcpctx.services import audit
from gcpctx.services.approvals import (
    approval_evidence_id,
    find_matching_approval,
    resolve_approval_doctor_state,
)
from gcpctx.settings import deprecated_global_gcloud_path
from gcpctx.version import __version__

if TYPE_CHECKING:
    from gcpctx.gcloud_trust import GcloudTrustResult
    from gcpctx.models import ApprovalRecord, DoctorResult
    from gcpctx.ports import EnvPort, GcloudPort
    from gcpctx.project_context import ResolvedProjectContext

_configured_env: EnvPort | None = None
_configured_gcloud: GcloudPort | None = None


def configure_env_port(env: EnvPort) -> None:
    """Set the process-wide EnvPort (called from composition root)."""
    global _configured_env  # noqa: PLW0603
    _configured_env = env


def configure_gcloud_port(gcloud: GcloudPort) -> None:
    """Set the process-wide GcloudPort (called from composition root)."""
    global _configured_gcloud  # noqa: PLW0603
    _configured_gcloud = gcloud


def _get_env_port(explicit: EnvPort | None) -> EnvPort:
    e = explicit or _configured_env
    if e is None:
        msg = "EnvPort not configured; call configure_env_port() or configure_runtime_defaults()"
        raise RuntimeError(msg)
    return e


def _get_gcloud_port(explicit: GcloudPort | None) -> GcloudPort:
    g = explicit or _configured_gcloud
    if g is None:
        msg = "GcloudPort not configured; call configure_gcloud_port() or configure_runtime_defaults()"
        raise RuntimeError(msg)
    return g


def _strict_policy_for_checks(policy: SecurityPolicy, effective_strict: bool) -> SecurityPolicy:
    """Apply strict-mode approval rules when doctor runs with --strict."""
    if not effective_strict or policy.strict:
        return policy
    return replace(
        policy,
        mode="strict",
        require_gcloud_path_approval=True,
        require_initialized_adc_for_hook=True,
    )


def _approval_facts(record: ApprovalRecord | None) -> ApprovalFacts | None:
    if record is None:
        return None
    return ApprovalFacts(
        mode=record.mode,
        expires_at=record.expires_at,
        evidence_id=approval_evidence_id(record),
    )


def _resolve_path_str(path_str: str) -> tuple[str | None, bool]:
    """Return (resolved_str_or_none, invalid). Empty input -> (None, False)."""
    if not path_str:
        return None, False
    try:
        return str(Path(path_str).resolve()), False
    except OSError:
        return path_str, True


def _gather_state_permissions() -> tuple[tuple[str, ...], str | None]:
    targets = [
        paths.approvals_file(),
        paths.user_config_path(),
        paths.user_cache_path(),
        audit.audit_file(),
    ]
    for target in targets:
        if not target.exists():
            continue
        try:
            reject_symlink(target)
            check_path_permissions(target, expect_dir=target.is_dir())
        except GcpctxError as exc:
            return (str(exc),), str(target)
    return (), None


def _gather_trust(
    cwd: Path,
    policy: SecurityPolicy,
    effective_strict: bool,
    gcloud_port: GcloudPort,
    configured_path: str | None = None,
) -> tuple[GcloudTrustResult | None, str | None]:
    try:
        return (
            gcloud_port.resolve_binary(
                cwd,
                policy=policy,
                configured_path=configured_path,
                strict=effective_strict,
            ),
            None,
        )
    except GcpctxError as exc:
        return None, str(exc)


def _partial_snapshot(  # noqa: PLR0913
    *,
    interactive: bool,
    effective_strict: bool,
    cache_root: str,
    cwd_str: str,
    policy: SecurityPolicy,
    config_error: str,
    schema_error: bool = False,
    config_error_exit_code: int | None = None,
    deprecated: str | None,
    trust: GcloudTrustResult | None,
    trust_error: str | None,
) -> DoctorSnapshot:
    return DoctorSnapshot(
        interactive=interactive,
        effective_strict=effective_strict,
        cache_root=cache_root,
        cwd_str=cwd_str,
        policy=policy,
        config_found=False,
        config_error=config_error,
        schema_error=schema_error,
        config_error_exit_code=config_error_exit_code,
        deprecated_global_gcloud_path=deprecated,
        gcloud_trust_path=trust.path if trust else None,
        gcloud_trust_warnings=trust.warnings if trust else (),
        gcloud_trust_error=trust_error,
    )


def gather_snapshot(  # noqa: PLR0911,PLR0913
    cwd: Path,
    *,
    profile: str | None = None,
    strict: bool = False,
    interactive: bool | None = None,
    env: EnvPort | None = None,
    gcloud: GcloudPort | None = None,
    allow_iam_probe: bool = True,
) -> DoctorSnapshot:
    """Probe filesystem/env and return a frozen DoctorSnapshot.

    Inject ``EnvPort`` or ``GcloudPort`` for testing; defaults to configured adapters.
    Set ``allow_iam_probe=False`` to suppress the ``gcloud auth print-access-token`` probe
    (required for read-only callers such as the MCP server).
    """
    env_port = _get_env_port(env)
    gcloud_port = _get_gcloud_port(gcloud)
    is_interactive = sys.stdin.isatty() if interactive is None else interactive
    cwd_str = str(cwd.resolve())
    cache_root = str(paths.user_cache_path().resolve())

    try:
        policy = load_policy()
    except GcpctxError as exc:
        return DoctorSnapshot(
            interactive=is_interactive,
            effective_strict=strict,
            cache_root=cache_root,
            cwd_str=cwd_str,
            policy_error=str(exc),
            policy_error_exit_code=exc.exit_code,
        )

    effective_strict = strict or policy.strict
    deprecated = deprecated_global_gcloud_path()

    # Resolve project context first so we can pass configured_path to trust
    # resolution, avoiding a redundant config read in the happy path.
    try:
        ctx = resolve_project_context(cwd, profile, policy=policy)
    except ConfigNotFoundError:
        return _config_error_snapshot(
            cwd,
            policy=policy,
            effective_strict=effective_strict,
            interactive=is_interactive,
            cache_root=cache_root,
            cwd_str=cwd_str,
            deprecated=deprecated,
            gcloud_port=gcloud_port,
            config_error=".gcpctx.toml not found",
        )
    except ConfigValidationError as exc:
        return _config_error_snapshot(
            cwd,
            policy=policy,
            effective_strict=effective_strict,
            interactive=is_interactive,
            cache_root=cache_root,
            cwd_str=cwd_str,
            deprecated=deprecated,
            gcloud_port=gcloud_port,
            config_error=str(exc),
            schema_error=True,
            config_error_exit_code=exc.exit_code,
        )
    except GcpctxError as exc:
        return _config_error_snapshot(
            cwd,
            policy=policy,
            effective_strict=effective_strict,
            interactive=is_interactive,
            cache_root=cache_root,
            cwd_str=cwd_str,
            deprecated=deprecated,
            gcloud_port=gcloud_port,
            config_error=str(exc),
            config_error_exit_code=exc.exit_code,
        )

    trust, trust_error = _gather_trust(cwd, policy, effective_strict, gcloud_port, ctx.gcloud_path)
    return _gather_resolved_snapshot(
        ctx,
        policy=policy,
        trust=trust,
        trust_error=trust_error,
        interactive=is_interactive,
        effective_strict=effective_strict,
        cache_root=cache_root,
        cwd_str=cwd_str,
        deprecated=deprecated,
        env_port=env_port,
        gcloud_port=gcloud_port,
        allow_iam_probe=allow_iam_probe,
    )


def _config_error_snapshot(  # noqa: PLR0913
    cwd: Path,
    *,
    policy: SecurityPolicy,
    effective_strict: bool,
    interactive: bool,
    cache_root: str,
    cwd_str: str,
    deprecated: str | None,
    gcloud_port: GcloudPort,
    config_error: str,
    schema_error: bool = False,
    config_error_exit_code: int | None = None,
) -> DoctorSnapshot:
    trust, trust_error = _gather_trust(cwd, policy, effective_strict, gcloud_port)
    return _partial_snapshot(
        interactive=interactive,
        effective_strict=effective_strict,
        cache_root=cache_root,
        cwd_str=cwd_str,
        policy=policy,
        config_error=config_error,
        schema_error=schema_error,
        config_error_exit_code=config_error_exit_code,
        deprecated=deprecated,
        trust=trust,
        trust_error=trust_error,
    )


def _gather_resolved_snapshot(  # noqa: PLR0912,PLR0913
    ctx: ResolvedProjectContext,
    *,
    policy: SecurityPolicy,
    trust: GcloudTrustResult | None,
    trust_error: str | None,
    interactive: bool,
    effective_strict: bool,
    cache_root: str,
    cwd_str: str,
    deprecated: str | None,
    env_port: EnvPort,
    gcloud_port: GcloudPort,
    allow_iam_probe: bool = True,
) -> DoctorSnapshot:
    check_policy = _strict_policy_for_checks(policy, effective_strict)
    approval_state = resolve_approval_doctor_state(ctx, policy=check_policy, gcloud_trust=trust)
    expected_raw = ctx.expected_cloudsdk_config()
    expected_str, expected_invalid = _resolve_path_str(str(expected_raw))
    if expected_str is None:
        expected_str = str(expected_raw)
        expected_invalid = True

    ambient_raw = env_port.get("CLOUDSDK_CONFIG") or ""
    ambient_str, ambient_invalid = _resolve_path_str(ambient_raw)

    gac_value = env_port.get("GOOGLE_APPLICATION_CREDENTIALS")
    env_project = env_port.get("CLOUDSDK_CORE_PROJECT")

    gcloud_project_property: str | None = None
    impersonation_property: str | None = None
    adc_exists: bool | None = None
    iam_ok: bool | None = None
    iam_skipped = False
    iam_error: str | None = None
    state_issues: tuple[str, ...] = ()
    state_path: str | None = None
    state_checked = False

    if trust is not None:
        gcloud_project_property = gcloud_port.get_property(
            expected_raw, "project", gcloud_executable=trust.path
        )
        impersonation_property = gcloud_port.get_property(
            expected_raw,
            "auth/impersonate_service_account",
            gcloud_executable=trust.path,
        )
        adc_exists = gcloud_port.adc_exists(expected_raw)
        if effective_strict:
            if not adc_exists:
                iam_skipped = True
            elif allow_iam_probe:
                probe_ok = gcloud_port.probe_impersonation(
                    expected_raw, ctx.service_account, gcloud_executable=trust.path
                )
                iam_ok = probe_ok
                if not probe_ok:
                    iam_error = "IAM impersonation probe failed"
            # allow_iam_probe=False: leave iam_ok=None / iam_skipped=False so the
            # impersonation_iam check is omitted (read-only callers must not mint tokens).

    if effective_strict:
        state_issues, state_path = _gather_state_permissions()
        state_checked = True

    return DoctorSnapshot(
        interactive=interactive,
        effective_strict=effective_strict,
        cache_root=cache_root,
        cwd_str=cwd_str,
        policy=policy,
        config_found=True,
        profile_name=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        context_id=ctx.context_id(),
        root_str=str(ctx.root),
        config_path=str(ctx.root / ".gcpctx.toml"),
        expected_cloudsdk_config=expected_str,
        expected_cloudsdk_invalid=expected_invalid,
        ambient_cloudsdk_config=ambient_str,
        ambient_cloudsdk_invalid=ambient_invalid,
        env_cloudsdk_core_project=env_project,
        gac_set=bool(gac_value),
        gac_value=gac_value,
        approval_matching=_approval_facts(approval_state.matching),
        approval_identity=_approval_facts(approval_state.identity),
        approval_expired=_approval_facts(approval_state.expired_remembered),
        gcloud_trust_path=trust.path if trust else None,
        gcloud_trust_warnings=trust.warnings if trust else (),
        gcloud_trust_error=trust_error,
        gcloud_project_property=gcloud_project_property,
        impersonation_property=impersonation_property,
        adc_exists=adc_exists,
        impersonation_iam_ok=iam_ok,
        impersonation_iam_skipped_adc=iam_skipped,
        impersonation_iam_error=iam_error,
        state_permission_issues=state_issues,
        state_permission_path=state_path,
        state_permissions_checked=state_checked,
        deprecated_global_gcloud_path=deprecated,
    )


def run_doctor(
    cwd: Path,
    *,
    profile: str | None = None,
    interactive: bool | None = None,
    strict: bool = False,
    allow_iam_probe: bool = True,
) -> DoctorResult:
    """Run diagnostic checks and return aggregated result.

    Set ``allow_iam_probe=False`` to suppress the IAM token probe (e.g. from MCP).
    """
    snapshot = gather_snapshot(
        cwd,
        profile=profile,
        strict=strict,
        interactive=interactive,
        allow_iam_probe=allow_iam_probe,
    )
    findings = evaluate_all(snapshot)
    result = findings_to_result(
        findings,
        version=__version__,
        interactive=snapshot.interactive,
        strict=snapshot.effective_strict,
        profile=snapshot.profile_name,
        context_id=snapshot.context_id,
    )
    if snapshot.effective_strict and result.exit_code != 0:
        audit.log_event("doctor_strict_failed", exit_code=result.exit_code)
    return result


def _approval_status(root: Path, info: dict[str, str], gcloud_port: GcloudPort) -> str:
    try:
        policy = load_policy()
        ctx = resolve_project_context(root, info.get("profile"), policy=policy)
        trust = gcloud_port.resolve_binary(root, policy=policy, configured_path=ctx.gcloud_path)
        approval = find_matching_approval(ctx, policy=policy, gcloud_trust=trust)
    except GcpctxError:
        return "unknown"
    return approval.mode if approval else "none"


def status_info(cwd: Path) -> dict[str, str]:
    """Return status fields for display."""
    env = _get_env_port(None)
    gcloud_port = _get_gcloud_port(None)
    if env.get("GCPCTX_ACTIVE") != "1":
        return {"active": "false"}

    info: dict[str, str] = {
        "active": "true",
        "root": env.get("GCPCTX_ROOT") or "",
        "profile": env.get("GCPCTX_PROFILE") or "",
        "project": env.get("GCPCTX_PROJECT") or "",
        "service_account": env.get("GCPCTX_SERVICE_ACCOUNT") or "",
        "cloudsdk_config": env.get("CLOUDSDK_CONFIG") or "",
    }

    root = find_project_root(cwd)
    if root:
        info["approval"] = _approval_status(root, info, gcloud_port)

    cloudsdk = info.get("cloudsdk_config", "")
    if cloudsdk:
        info["adc"] = "initialized" if gcloud_port.adc_exists(Path(cloudsdk)) else "missing"
    return info
