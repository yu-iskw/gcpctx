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

from gcpctx import __version__, audit, gcloud as gcloud_mod, paths
from gcpctx.approvals import (
    ApprovalDoctorState,
    approval_evidence_id,
    find_matching_approval,
    resolve_approval_doctor_state,
)
from gcpctx.discovery import find_project_root
from gcpctx.doctor_checks import DOCTOR_CHECK_IDS, DOCTOR_CHECK_REGISTRY, check_exit_code
from gcpctx.errors import ConfigNotFoundError, ConfigValidationError, GcpctxError
from gcpctx.gcloud_trust import GcloudTrustResult, resolve_trusted_gcloud
from gcpctx.models import DoctorCheck, DoctorRemediation, DoctorResult, ProfileConfig
from gcpctx.policy import SecurityPolicy, load_policy
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context
from gcpctx.security import check_path_permissions, reject_symlink
from gcpctx.settings import deprecated_global_gcloud_path

CheckStatus = Literal["ok", "warning", "error"]
_STATUS_RANK = {"ok": 0, "warning": 1, "error": 2}
_WARN_ONLY_CHECK_IDS = frozenset({"settings"})


@dataclass
class _AccumulatedCheck:
    """Merged state for a single doctor check id."""

    status: CheckStatus = "ok"
    messages: list[str] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)
    remediation_command: str | None = None


@dataclass
class _CheckCollector:
    """Accumulates doctor checks and computes exit status."""

    interactive: bool
    strict: bool
    profile: str | None = None
    context_id: str | None = None
    _checks: dict[str, _AccumulatedCheck] = field(default_factory=dict)
    exit_code: int = 0

    def add(  # noqa: PLR0912, PLR0913
        self,
        check_id: str,
        status: CheckStatus,
        message: str,
        *,
        evidence: dict[str, str] | None = None,
        remediation_command: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        if status == "warning" and self.strict:
            status = "error"
        entry = self._checks.setdefault(check_id, _AccumulatedCheck())
        if _STATUS_RANK[status] > _STATUS_RANK[entry.status]:
            entry.status = status
        entry.messages.append(message)
        if evidence:
            entry.evidence.update(evidence)
        if remediation_command is not None:
            entry.remediation_command = remediation_command
        elif entry.remediation_command is None:
            spec = DOCTOR_CHECK_REGISTRY.get(check_id)
            if spec is not None:
                entry.remediation_command = spec.default_command
        contributes_exit = status == "error" or (
            status == "warning" and not self.interactive and not self.strict
        )
        if contributes_exit and not (status == "warning" and check_id in _WARN_ONLY_CHECK_IDS):
            code = exit_code if exit_code is not None else int(check_exit_code(check_id))
            self.exit_code = max(self.exit_code, code)

    def result(self) -> DoctorResult:
        checks = [
            _build_doctor_check(check_id, self._checks[check_id])
            for check_id in DOCTOR_CHECK_IDS
            if check_id in self._checks
        ]
        has_warn = any(check.status == "warn" for check in checks)
        if self.exit_code != 0:
            aggregate_status: Literal["ok", "warn", "fail"] = "fail"
        elif has_warn:
            aggregate_status = "warn"
        else:
            aggregate_status = "ok"
        return DoctorResult(
            version=__version__,
            status=aggregate_status,
            profile=self.profile,
            context_id=self.context_id,
            checks=checks,
            exit_code=self.exit_code,
        )

    def env_issue_severity(self) -> CheckStatus:
        return "warning" if self.interactive and not self.strict else "error"


def _build_doctor_check(check_id: str, accumulated: _AccumulatedCheck) -> DoctorCheck:
    spec = DOCTOR_CHECK_REGISTRY.get(check_id)
    docs = spec.docs if spec is not None else None
    default_command = spec.default_command if spec is not None else None
    message = "; ".join(accumulated.messages)
    if accumulated.status == "ok":
        severity: Literal["error", "warning", "info"] = "info"
        check_status: Literal["pass", "warn", "fail"] = "pass"
        remediation = None
    elif accumulated.status == "warning":
        severity = "warning"
        check_status = "warn"
        command = accumulated.remediation_command or default_command
        remediation = DoctorRemediation(command=command, docs=docs) if command or docs else None
    else:
        severity = "error"
        check_status = "fail"
        command = accumulated.remediation_command or default_command
        remediation = DoctorRemediation(command=command, docs=docs)
    return DoctorCheck(
        id=check_id,
        severity=severity,
        status=check_status,
        message=message,
        evidence=dict(accumulated.evidence),
        remediation=remediation,
    )


def run_doctor(  # noqa: PLR0911, PLR0912
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
        collector.add("policy", "error", str(exc), exit_code=exc.exit_code)
        return _finalize(collector, strict)
    effective_strict = strict or policy.strict
    collector = _CheckCollector(interactive=is_interactive, strict=effective_strict)

    _check_deprecated_global_gcloud_pin(collector)
    trust = _resolve_trust(collector, cwd, policy, effective_strict)
    try:
        ctx = resolve_project_context(cwd, profile, policy=policy)
    except ConfigNotFoundError:
        collector.add(
            "config",
            "error",
            ".gcpctx.toml not found",
            evidence={"reason": "not_found", "cwd": str(cwd.resolve())},
        )
        return _finalize(collector, effective_strict)
    except ConfigValidationError as exc:
        collector.add(
            "config",
            "error",
            str(exc),
            evidence={"reason": "schema_error"},
            exit_code=exc.exit_code,
        )
        return _finalize(collector, effective_strict)
    except GcpctxError as exc:
        collector.add(
            "config",
            "error",
            str(exc),
            evidence={"reason": "config_error"},
            exit_code=exc.exit_code,
        )
        return _finalize(collector, effective_strict)

    collector.profile = ctx.profile_name
    collector.context_id = ctx.context_id()
    collector.add(
        "config",
        "ok",
        f"Configuration valid at {ctx.root}",
        evidence={"path": str(ctx.root / ".gcpctx.toml")},
    )
    collector.add("profile", "ok", f"Profile {ctx.profile_name!r} resolved")
    _check_policy(collector, policy)
    check_policy = _strict_policy_for_checks(policy, effective_strict)
    approval_state = resolve_approval_doctor_state(ctx, policy=check_policy, gcloud_trust=trust)
    _check_approvals(collector, approval_state)
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
        collector.add(
            "gcloud_trust",
            "error",
            str(exc),
            evidence={"reason": "trust_validation_failed"},
        )
        return None
    collector.add(
        "gcloud_trust",
        "ok",
        f"gcloud trusted at {trust.path}",
        evidence={"path": trust.path},
    )
    if trust.warnings:
        collector.add(
            "gcloud_trust",
            "warning",
            "; ".join(trust.warnings),
            evidence={"path": trust.path, "reason": "trust_warning"},
        )
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
    deprecated = deprecated_global_gcloud_path()
    if deprecated is None:
        return
    collector.add(
        "settings",
        "warning",
        "settings.toml contains deprecated gcloud_path; move it to .gcpctx.toml and remove the global key",
        evidence={"deprecated_key": "gcloud_path"},
        remediation_command=(
            "Run gcpctx config set-gcloud-path in the project directory, then edit settings.toml"
        ),
    )


def _check_policy(collector: _CheckCollector, policy: SecurityPolicy) -> None:
    if policy.source:
        collector.add(
            "policy",
            "ok",
            f"Policy loaded from {policy.source} (mode={policy.mode})",
            evidence={"source": policy.source, "mode": policy.mode},
        )
    else:
        collector.add(
            "policy", "ok", "Using built-in default policy", evidence={"mode": policy.mode}
        )


def _check_approvals(collector: _CheckCollector, state: ApprovalDoctorState) -> None:  # noqa: PLR0912
    approval = state.matching
    if approval is None:
        if state.expired_remembered is not None:
            collector.add(
                "approval",
                collector.env_issue_severity(),
                "No matching approval (remembered approval expired)",
            )
        else:
            collector.add(
                "approval",
                collector.env_issue_severity(),
                "No matching approval",
            )
    else:
        expiry = f", expires {approval.expires_at}" if approval.expires_at else ""
        collector.add(
            "approval",
            "ok",
            f"Approval found ({approval.mode}{expiry})",
            evidence={"mode": approval.mode},
        )

    if approval is not None:
        collector.add("approval_expiry", "ok", "Valid approval is active")
        return
    if state.expired_remembered is None:
        if state.identity is None:
            collector.add("approval_expiry", "ok", "No remembered approval on file")
        else:
            collector.add("approval_expiry", "ok", "Remembered approval has not expired")
        return
    expired = state.expired_remembered
    collector.add(
        "approval_expiry",
        collector.env_issue_severity(),
        f"Remembered approval expired at {expired.expires_at}",
        evidence={
            "expires_at": expired.expires_at or "",
            "approval_id": approval_evidence_id(expired),
        },
    )


def _check_env_project(collector: _CheckCollector, ctx: ResolvedProjectContext) -> None:
    env_project = os.environ.get("CLOUDSDK_CORE_PROJECT")
    if not env_project:
        collector.add("env_project", "ok", "CLOUDSDK_CORE_PROJECT unset in environment")
        return
    if env_project == ctx.project:
        collector.add(
            "env_project",
            "ok",
            f"CLOUDSDK_CORE_PROJECT matches profile: {env_project}",
        )
        return
    collector.add(
        "env_project",
        "error",
        f"CLOUDSDK_CORE_PROJECT {env_project!r} != profile project {ctx.project!r}",
        evidence={"expected": ctx.project, "actual": env_project},
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
            evidence={"path": str(expected_cloudsdk), "reason": "invalid_path"},
        )
        return
    if resolved.is_relative_to(cache):
        collector.add(
            "expected_context",
            "ok",
            f"Expected context path: {resolved}",
            evidence={"path": str(resolved)},
        )
        return
    collector.add(
        "expected_context",
        "error",
        f"Expected context path not under gcpctx cache: {resolved}",
        evidence={"path": str(resolved), "reason": "outside_cache"},
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
            evidence={"reason": "unset"},
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
            evidence={"path": str(ambient_resolved), "reason": "outside_cache"},
        )
        return
    if expected_resolved is not None and ambient_resolved == expected_resolved:
        collector.add(
            "ambient_cloudsdk",
            "ok",
            f"CLOUDSDK_CONFIG matches expected context: {ambient_resolved}",
            evidence={"path": str(ambient_resolved)},
        )
        return
    expected_display = expected_resolved or expected_cloudsdk
    collector.add(
        "ambient_cloudsdk",
        collector.env_issue_severity(),
        f"CLOUDSDK_CONFIG {ambient_resolved} != expected {expected_display}",
        evidence={
            "path": str(ambient_resolved),
            "expected": str(expected_display),
            "reason": "stale_context",
        },
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
            collector.add(
                "state_permissions",
                "error",
                str(exc),
                evidence={"path": str(target)},
            )
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
        collector.add(
            "impersonation_iam",
            "warning",
            "Skipped IAM probe: ADC not initialized",
            evidence={"reason": "adc_missing"},
        )
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
            evidence={"service_account": ctx.service_account},
        )
        return
    collector.add(
        "impersonation_iam",
        "ok",
        "IAM impersonation probe succeeded",
        evidence={"service_account": ctx.service_account},
    )


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
        collector.add(
            "gcloud_project",
            "ok",
            f"Project matches: {proj}",
            evidence={"project": proj or ""},
        )
    else:
        collector.add(
            "gcloud_project",
            "error",
            f"Project mismatch: {proj!r} != {prof.project!r}",
            evidence={"expected": prof.project, "actual": proj or ""},
        )


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
        collector.add(
            "impersonation",
            "ok",
            f"Impersonation matches: {imp}",
            evidence={"service_account": imp or ""},
        )
    else:
        collector.add(
            "impersonation",
            "error",
            f"Impersonation mismatch: {imp!r} != {prof.service_account!r}",
            evidence={"expected": prof.service_account, "actual": imp or ""},
        )


def _check_gcloud_adc(collector: _CheckCollector, config_path: Path) -> None:
    if gcloud_mod.adc_exists(config_path):
        collector.add("adc", "ok", "ADC initialized")
    else:
        collector.add(
            "adc",
            collector.env_issue_severity(),
            "ADC not initialized",
            evidence={"path": str(config_path)},
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
        evidence={"reason": "credential_surface_set"},
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
