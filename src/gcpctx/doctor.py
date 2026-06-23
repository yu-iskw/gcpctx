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
"""Diagnostics: status and doctor."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from gcpctx import audit, gcloud as gcloud_mod, paths
from gcpctx.approvals import find_matching_approval
from gcpctx.discovery import find_project_root
from gcpctx.errors import ConfigNotFoundError, GcpctxError
from gcpctx.gcloud_trust import GcloudTrustResult, resolve_trusted_gcloud
from gcpctx.models import DoctorCheck, DoctorResult, ProfileConfig
from gcpctx.policy import SecurityPolicy, load_policy
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context
from gcpctx.security import check_path_permissions, reject_symlink
from gcpctx.settings import deprecated_global_gcloud_path

CheckStatus = Literal["ok", "warning", "error"]


@dataclass
class _CheckCollector:
    """Accumulates doctor checks and computes exit status."""

    interactive: bool
    strict: bool
    checks: list[DoctorCheck] = field(default_factory=list)
    exit_code: int = 0

    def add(
        self,
        name: str,
        status: CheckStatus,
        message: str,
        remediation: str | None = None,
    ) -> None:
        if status == "warning" and self.strict:
            status = "error"
        self.checks.append(
            DoctorCheck(name=name, status=status, message=message, remediation=remediation)
        )
        if status == "error" or (status == "warning" and not self.interactive and not self.strict):
            self.exit_code = max(self.exit_code, _severity_exit(name))

    def result(self) -> DoctorResult:
        return DoctorResult(checks=self.checks, exit_code=self.exit_code)

    def env_issue_severity(self) -> CheckStatus:
        return "warning" if self.interactive and not self.strict else "error"


def run_doctor(  # noqa: PLR0911
    cwd: Path,
    *,
    profile: str | None = None,
    interactive: bool | None = None,
    strict: bool = False,
) -> DoctorResult:
    """Run diagnostic checks and return aggregated result."""
    is_interactive = sys.stdin.isatty() if interactive is None else interactive
    try:
        policy = load_policy()
    except GcpctxError as exc:
        collector = _CheckCollector(interactive=is_interactive, strict=strict)
        collector.add("policy", "error", str(exc))
        return _finalize(collector, strict)
    effective_strict = strict or policy.strict
    collector = _CheckCollector(interactive=is_interactive, strict=effective_strict)

    _check_deprecated_global_gcloud_pin(collector)
    trust = _resolve_trust(collector, cwd, policy, effective_strict)
    try:
        ctx = resolve_project_context(cwd, profile, policy=policy)
    except ConfigNotFoundError:
        collector.add("config", "error", ".gcpctx.toml not found", "Run gcpctx init-project")
        return _finalize(collector, effective_strict)
    except GcpctxError as exc:
        collector.add("config", "error", str(exc))
        return _finalize(collector, effective_strict)

    collector.add("config", "ok", f"Configuration valid at {ctx.root}")
    collector.add("profile", "ok", f"Profile {ctx.profile_name!r} resolved")
    _check_policy(collector, policy)
    check_policy = _strict_policy_for_checks(policy, effective_strict)
    _check_approval(collector, ctx, check_policy, trust)
    expected_cloudsdk = ctx.expected_cloudsdk_config()
    _check_expected_context(collector, expected_cloudsdk)
    if trust is not None:
        _check_gcloud_state(
            collector,
            expected_cloudsdk,
            ctx.profile,
            gcloud_executable=trust.path,
        )
        if effective_strict:
            _check_impersonation_iam(collector, expected_cloudsdk, ctx, trust.path)
    ambient_cloudsdk = os.environ.get("CLOUDSDK_CONFIG", "")
    _check_ambient_cloudsdk(collector, ambient_cloudsdk, expected_cloudsdk)
    _check_env_project(collector, ctx)
    _check_state_permissions(collector, effective_strict)
    _check_gac(collector)
    return _finalize(collector, effective_strict)


def status_info(cwd: Path) -> dict[str, str]:
    """Return status fields for display."""
    if os.environ.get("GCPCTX_ACTIVE") != "1":
        return {"active": "false"}

    info: dict[str, str] = {
        "active": "true",
        "root": os.environ.get("GCPCTX_ROOT", ""),
        "profile": os.environ.get("GCPCTX_PROFILE", ""),
        "project": os.environ.get("GCPCTX_PROJECT", ""),
        "service_account": os.environ.get("GCPCTX_SERVICE_ACCOUNT", ""),
        "cloudsdk_config": os.environ.get("CLOUDSDK_CONFIG", ""),
    }

    root = find_project_root(cwd)
    if root:
        info["approval"] = _approval_status(root, info)

    cloudsdk = info.get("cloudsdk_config", "")
    if cloudsdk:
        info["adc"] = "initialized" if gcloud_mod.adc_exists(Path(cloudsdk)) else "missing"
    return info


def _finalize(collector: _CheckCollector, strict: bool) -> DoctorResult:
    result = collector.result()
    if strict and result.exit_code != 0:
        audit.log_event("doctor_strict_failed", exit_code=result.exit_code)
    return result


def _resolve_trust(
    collector: _CheckCollector,
    cwd: Path,
    policy: SecurityPolicy,
    strict: bool,
) -> GcloudTrustResult | None:
    try:
        trust = resolve_trusted_gcloud(cwd, policy=policy, strict=strict)
    except GcpctxError as exc:
        collector.add("gcloud_trust", "error", str(exc), "Install or configure a trusted gcloud")
        return None
    collector.add("gcloud_trust", "ok", f"gcloud trusted at {trust.path}")
    for warning in trust.warnings:
        collector.add("gcloud_trust", "warning", warning)
    return trust


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


def _check_deprecated_global_gcloud_pin(collector: _CheckCollector) -> None:
    if deprecated_global_gcloud_path() is None:
        return
    collector.add(
        "settings",
        "warning",
        "settings.toml contains deprecated gcloud_path; move it to .gcpctx.toml and remove the global key",
        "Run gcpctx config set-gcloud-path in the project directory, then edit settings.toml",
    )


def _check_policy(collector: _CheckCollector, policy: SecurityPolicy) -> None:
    if policy.source:
        collector.add("policy", "ok", f"Policy loaded from {policy.source} (mode={policy.mode})")
    else:
        collector.add("policy", "ok", "Using built-in default policy")


def _check_approval(
    collector: _CheckCollector,
    ctx: ResolvedProjectContext,
    policy: SecurityPolicy,
    trust: GcloudTrustResult | None,
) -> None:
    approval = find_matching_approval(ctx, policy=policy, gcloud_trust=trust)
    if approval is None:
        collector.add(
            "approval",
            collector.env_issue_severity(),
            "No matching approval",
            "Run gcpctx approve or activate interactively",
        )
        return
    expiry = f", expires {approval.expires_at}" if approval.expires_at else ""
    collector.add("approval", "ok", f"Approval found ({approval.mode}{expiry})")


def _check_env_project(collector: _CheckCollector, ctx: ResolvedProjectContext) -> None:
    env_project = os.environ.get("CLOUDSDK_CORE_PROJECT")
    if not env_project:
        collector.add("env_project", "ok", "CLOUDSDK_CORE_PROJECT unset in environment")
        return
    if env_project == ctx.project:
        collector.add("env_project", "ok", f"CLOUDSDK_CORE_PROJECT matches profile: {env_project}")
    else:
        collector.add(
            "env_project",
            "error",
            f"CLOUDSDK_CORE_PROJECT {env_project!r} != profile project {ctx.project!r}",
            'eval "$(gcpctx activate --shell zsh)"',
        )


def _resolve_config_path(path_str: str) -> Path | None:
    if not path_str:
        return None
    try:
        return Path(path_str).resolve()
    except OSError:
        return None


def _check_expected_context(collector: _CheckCollector, expected_cloudsdk: Path) -> None:
    cache = paths.user_cache_path().resolve()
    try:
        resolved = expected_cloudsdk.resolve()
    except OSError:
        collector.add(
            "expected_context",
            "error",
            f"Expected context path is invalid: {expected_cloudsdk}",
        )
        return
    if resolved.is_relative_to(cache):
        collector.add("expected_context", "ok", f"Expected context path: {resolved}")
        return
    collector.add(
        "expected_context",
        "error",
        f"Expected context path not under gcpctx cache: {resolved}",
    )


def _check_ambient_cloudsdk(
    collector: _CheckCollector,
    ambient: str,
    expected_cloudsdk: Path,
) -> None:
    expected_resolved = _resolve_config_path(str(expected_cloudsdk))
    ambient_resolved = _resolve_config_path(ambient)
    cache = paths.user_cache_path().resolve()
    if ambient_resolved is None:
        collector.add(
            "ambient_cloudsdk",
            collector.env_issue_severity(),
            "CLOUDSDK_CONFIG unset in environment",
            'eval "$(gcpctx activate --shell zsh)"',
        )
        return
    try:
        under_cache = ambient_resolved.is_relative_to(cache)
    except OSError:
        under_cache = False
    if not under_cache:
        collector.add(
            "ambient_cloudsdk",
            "error",
            f"CLOUDSDK_CONFIG not under gcpctx cache (ADR-0003): {ambient_resolved}",
            'eval "$(gcpctx activate --shell zsh)"',
        )
        return
    if expected_resolved is not None and ambient_resolved == expected_resolved:
        collector.add(
            "ambient_cloudsdk",
            "ok",
            f"CLOUDSDK_CONFIG matches expected context: {ambient_resolved}",
        )
        return
    expected_display = expected_resolved or expected_cloudsdk
    collector.add(
        "ambient_cloudsdk",
        collector.env_issue_severity(),
        f"CLOUDSDK_CONFIG {ambient_resolved} != expected {expected_display}",
        'eval "$(gcpctx activate --shell zsh)"',
    )


def _check_state_permissions(collector: _CheckCollector, strict: bool) -> None:
    if not strict:
        return
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
            collector.add("state_permissions", "error", str(exc))
            return
    collector.add("state_permissions", "ok", "gcpctx state paths have safe permissions")


def _check_gcloud_state(
    collector: _CheckCollector,
    config_path: Path,
    prof: ProfileConfig,
    *,
    gcloud_executable: str | None = None,
) -> None:
    _check_gcloud_project(collector, config_path, prof, gcloud_executable=gcloud_executable)
    _check_gcloud_impersonation(collector, config_path, prof, gcloud_executable=gcloud_executable)
    _check_gcloud_adc(collector, config_path)


def _check_impersonation_iam(
    collector: _CheckCollector,
    config_path: Path,
    ctx: ResolvedProjectContext,
    gcloud_executable: str,
) -> None:
    if not gcloud_mod.adc_exists(config_path):
        collector.add("impersonation_iam", "warning", "Skipped IAM probe: ADC not initialized")
        return
    try:
        gcloud_mod.run_gcloud(
            [
                "auth",
                "print-access-token",
                "--impersonate-service-account",
                ctx.service_account,
            ],
            cloudsdk_config=config_path,
            gcloud_executable=gcloud_executable,
        )
    except GcpctxError as exc:
        collector.add(
            "impersonation_iam",
            "error",
            f"IAM impersonation probe failed: {exc}",
            "Grant roles/iam.serviceAccountTokenCreator on the service account",
        )
        return
    collector.add("impersonation_iam", "ok", "IAM impersonation probe succeeded")


def _check_gcloud_project(
    collector: _CheckCollector,
    config_path: Path,
    prof: ProfileConfig,
    *,
    gcloud_executable: str | None = None,
) -> None:
    proj = gcloud_mod.read_gcloud_property(
        config_path,
        "project",
        gcloud_executable=gcloud_executable,
    )
    if proj == prof.project:
        collector.add("gcloud_project", "ok", f"Project matches: {proj}")
    else:
        collector.add("gcloud_project", "error", f"Project mismatch: {proj!r} != {prof.project!r}")


def _check_gcloud_impersonation(
    collector: _CheckCollector,
    config_path: Path,
    prof: ProfileConfig,
    *,
    gcloud_executable: str | None = None,
) -> None:
    imp = gcloud_mod.read_gcloud_property(
        config_path,
        "auth/impersonate_service_account",
        gcloud_executable=gcloud_executable,
    )
    if imp == prof.service_account:
        collector.add("impersonation", "ok", f"Impersonation matches: {imp}")
    else:
        collector.add(
            "impersonation",
            "error",
            f"Impersonation mismatch: {imp!r} != {prof.service_account!r}",
        )


def _check_gcloud_adc(collector: _CheckCollector, config_path: Path) -> None:
    if gcloud_mod.adc_exists(config_path):
        collector.add("adc", "ok", "ADC initialized")
    else:
        collector.add(
            "adc",
            collector.env_issue_severity(),
            "ADC not initialized",
            "Run gcpctx refresh",
        )


def _check_gac(collector: _CheckCollector) -> None:
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not gac:
        collector.add("gac", "ok", "GOOGLE_APPLICATION_CREDENTIALS unset")
        return
    collector.add(
        "gac",
        collector.env_issue_severity(),
        f"GOOGLE_APPLICATION_CREDENTIALS is set: {gac}",
        "Unset or use --allow-google-application-credentials",
    )


def _approval_status(root: Path, info: dict[str, str]) -> str:
    try:
        policy = load_policy()
        ctx = resolve_project_context(root, info.get("profile"), policy=policy)
        trust = resolve_trusted_gcloud(root, policy=policy)
        approval = find_matching_approval(ctx, policy=policy, gcloud_trust=trust)
    except GcpctxError:
        return "unknown"
    else:
        return approval.mode if approval else "none"


def _severity_exit(name: str) -> int:
    mapping = {
        "config": 2,
        "profile": 2,
        "approval": 3,
        "gcloud_trust": 5,
        "gcloud_project": 5,
        "impersonation": 5,
        "gac": 6,
        "adc": 5,
        "policy": 7,
        "impersonation_iam": 5,
        "state_permissions": 4,
        "env_project": 2,
        "expected_context": 2,
        "ambient_cloudsdk": 2,
    }
    return mapping.get(name, 1)
