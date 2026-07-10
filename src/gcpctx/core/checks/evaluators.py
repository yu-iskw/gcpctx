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
"""Pure doctor check evaluators: DoctorSnapshot -> Finding(s)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from gcpctx.core.checks.registry import CHECK_EVALUATION_ORDER, STRICT_ONLY_CHECK_IDS
from gcpctx.core.checks.snapshot import Finding
from gcpctx.core.contract import ExitCode

if TYPE_CHECKING:
    from gcpctx.core.checks.snapshot import CheckStatus, DoctorSnapshot

CheckFn = Callable[["DoctorSnapshot"], "Finding | Sequence[Finding] | None"]


def env_issue_severity(snapshot: DoctorSnapshot) -> CheckStatus:
    """Interactive non-strict runs soften env issues to warnings."""
    return "warning" if snapshot.interactive and not snapshot.effective_strict else "error"


def _config_error_evidence(snapshot: DoctorSnapshot) -> dict[str, str]:
    if snapshot.schema_error:
        return {"reason": "schema_error"}
    if snapshot.config_error == ".gcpctx.toml not found":
        return {"reason": "not_found", "cwd": snapshot.cwd_str}
    return {"reason": "config_error"}


def check_config(snapshot: DoctorSnapshot) -> Finding | None:
    if snapshot.config_found:
        return Finding(
            "config",
            "ok",
            f"Configuration valid at {snapshot.root_str}",
            evidence={"path": snapshot.config_path or ""},
        )
    if snapshot.config_error is None:
        return None
    exit_code = snapshot.config_error_exit_code
    if snapshot.schema_error and exit_code is None:
        exit_code = int(ExitCode.CONFIG_SCHEMA_ERROR)
    return Finding(
        "config",
        "error",
        snapshot.config_error,
        evidence=_config_error_evidence(snapshot),
        exit_code=exit_code,
    )


def check_profile(snapshot: DoctorSnapshot) -> Finding | None:
    if not snapshot.config_found or snapshot.profile_name is None:
        return None
    return Finding("profile", "ok", f"Profile {snapshot.profile_name!r} resolved")


def check_policy(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if snapshot.policy_error is not None:
        return Finding(
            "policy",
            "error",
            snapshot.policy_error,
            exit_code=snapshot.policy_error_exit_code,
        )
    if snapshot.policy is None or not snapshot.config_found:
        return None
    policy = snapshot.policy
    if policy.source:
        return Finding(
            "policy",
            "ok",
            f"Policy loaded from {policy.source} (mode={policy.mode})",
            evidence={"source": policy.source, "mode": policy.mode},
        )
    return Finding(
        "policy",
        "ok",
        "Using built-in default policy",
        evidence={"mode": policy.mode},
    )


def check_settings(snapshot: DoctorSnapshot) -> Finding | None:
    if snapshot.deprecated_global_gcloud_path is None:
        return None
    return Finding(
        "settings",
        "warning",
        "settings.toml contains deprecated gcloud_path; move it to .gcpctx.toml "
        "and remove the global key",
        evidence={"deprecated_key": "gcloud_path"},
        remediation_command=(
            "Run gcpctx config in the project directory, then edit settings.toml"
        ),
    )


def check_gcloud_trust(snapshot: DoctorSnapshot) -> list[Finding] | None:
    if snapshot.gcloud_trust_error is not None:
        return [
            Finding(
                "gcloud_trust",
                "error",
                snapshot.gcloud_trust_error,
                evidence={"reason": "trust_validation_failed"},
            )
        ]
    if snapshot.gcloud_trust_path is None:
        return None
    findings = [
        Finding(
            "gcloud_trust",
            "ok",
            f"gcloud trusted at {snapshot.gcloud_trust_path}",
            evidence={"path": snapshot.gcloud_trust_path},
        )
    ]
    if snapshot.gcloud_trust_warnings:
        findings.append(
            Finding(
                "gcloud_trust",
                "warning",
                "; ".join(snapshot.gcloud_trust_warnings),
                evidence={"path": snapshot.gcloud_trust_path, "reason": "trust_warning"},
            )
        )
    return findings


def check_approval(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found:
        return None
    matching = snapshot.approval_matching
    severity = env_issue_severity(snapshot)
    if matching is None:
        if snapshot.approval_expired is not None:
            return Finding(
                "approval",
                severity,
                "No matching approval (remembered approval expired)",
            )
        return Finding("approval", severity, "No matching approval")
    expiry = f", expires {matching.expires_at}" if matching.expires_at else ""
    return Finding(
        "approval",
        "ok",
        f"Approval found ({matching.mode}{expiry})",
        evidence={"mode": matching.mode},
    )


def check_approval_expiry(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found:
        return None
    if snapshot.approval_matching is not None:
        return Finding("approval_expiry", "ok", "Valid approval is active")
    expired = snapshot.approval_expired
    if expired is None:
        if snapshot.approval_identity is None:
            return Finding("approval_expiry", "ok", "No remembered approval on file")
        return Finding("approval_expiry", "ok", "Remembered approval has not expired")
    return Finding(
        "approval_expiry",
        env_issue_severity(snapshot),
        f"Remembered approval expired at {expired.expires_at}",
        evidence={
            "expires_at": expired.expires_at or "",
            "approval_id": expired.evidence_id,
        },
    )


def _under_cache(path: str, cache_root: str) -> bool:
    try:
        return Path(path).is_relative_to(Path(cache_root))
    except (OSError, ValueError):
        return False


def check_expected_context(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found or snapshot.expected_cloudsdk_config is None:
        return None
    expected = snapshot.expected_cloudsdk_config
    if snapshot.expected_cloudsdk_invalid:
        return Finding(
            "expected_context",
            "error",
            f"Expected context path is invalid: {expected}",
            evidence={"path": expected, "reason": "invalid_path"},
        )
    if _under_cache(expected, snapshot.cache_root):
        return Finding(
            "expected_context",
            "ok",
            f"Expected context path: {expected}",
            evidence={"path": expected},
        )
    return Finding(
        "expected_context",
        "error",
        f"Expected context path not under gcpctx cache: {expected}",
        evidence={"path": expected, "reason": "outside_cache"},
    )


def check_ambient_cloudsdk(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found or snapshot.expected_cloudsdk_config is None:
        return None
    ambient = snapshot.ambient_cloudsdk_config
    expected = snapshot.expected_cloudsdk_config
    if not ambient or snapshot.ambient_cloudsdk_invalid:
        return Finding(
            "ambient_cloudsdk",
            env_issue_severity(snapshot),
            "CLOUDSDK_CONFIG unset in environment",
            evidence={"reason": "unset"},
        )
    if not _under_cache(ambient, snapshot.cache_root):
        return Finding(
            "ambient_cloudsdk",
            "error",
            f"CLOUDSDK_CONFIG not under gcpctx cache (ADR-0003): {ambient}",
            evidence={"path": ambient, "reason": "outside_cache"},
        )
    if ambient == expected:
        return Finding(
            "ambient_cloudsdk",
            "ok",
            f"CLOUDSDK_CONFIG matches expected context: {ambient}",
            evidence={"path": ambient},
        )
    return Finding(
        "ambient_cloudsdk",
        env_issue_severity(snapshot),
        f"CLOUDSDK_CONFIG {ambient} != expected {expected}",
        evidence={
            "path": ambient,
            "expected": expected,
            "reason": "stale_context",
        },
    )


def check_env_project(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found or snapshot.project is None:
        return None
    env_project = snapshot.env_cloudsdk_core_project
    if not env_project:
        return Finding("env_project", "ok", "CLOUDSDK_CORE_PROJECT unset in environment")
    if env_project == snapshot.project:
        return Finding(
            "env_project",
            "ok",
            f"CLOUDSDK_CORE_PROJECT matches profile: {env_project}",
        )
    return Finding(
        "env_project",
        "error",
        f"CLOUDSDK_CORE_PROJECT {env_project!r} != profile project {snapshot.project!r}",
        evidence={"expected": snapshot.project, "actual": env_project},
    )


def check_gcloud_project(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found or snapshot.gcloud_trust_path is None:
        return None
    if snapshot.project is None or snapshot.adc_exists is None:
        return None
    proj = snapshot.gcloud_project_property
    if proj == snapshot.project:
        return Finding(
            "gcloud_project",
            "ok",
            f"Project matches: {proj}",
            evidence={"project": proj or ""},
        )
    return Finding(
        "gcloud_project",
        "error",
        f"Project mismatch: {proj!r} != {snapshot.project!r}",
        evidence={"expected": snapshot.project, "actual": proj or ""},
    )


def check_impersonation(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found or snapshot.gcloud_trust_path is None:
        return None
    if snapshot.service_account is None or snapshot.adc_exists is None:
        return None
    imp = snapshot.impersonation_property
    if imp == snapshot.service_account:
        return Finding(
            "impersonation",
            "ok",
            f"Impersonation matches: {imp}",
            evidence={"service_account": imp or ""},
        )
    return Finding(
        "impersonation",
        "error",
        f"Impersonation mismatch: {imp!r} != {snapshot.service_account!r}",
        evidence={"expected": snapshot.service_account, "actual": imp or ""},
    )


def check_adc(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if not snapshot.config_found or snapshot.gcloud_trust_path is None:
        return None
    if snapshot.adc_exists is None:
        return None
    if snapshot.adc_exists:
        return Finding("adc", "ok", "ADC initialized")
    return Finding(
        "adc",
        env_issue_severity(snapshot),
        "ADC not initialized",
        evidence={"path": snapshot.expected_cloudsdk_config or ""},
    )


def check_gac(snapshot: DoctorSnapshot) -> Finding | None:
    if not snapshot.config_found:
        return None
    if not snapshot.gac_set:
        return Finding("gac", "ok", "GOOGLE_APPLICATION_CREDENTIALS unset")
    return Finding(
        "gac",
        env_issue_severity(snapshot),
        f"GOOGLE_APPLICATION_CREDENTIALS is set: {snapshot.gac_value}",
        evidence={"reason": "credential_surface_set"},
    )


def check_state_permissions(snapshot: DoctorSnapshot) -> Finding | None:
    if not snapshot.state_permissions_checked:
        return None
    if snapshot.state_permission_issues:
        return Finding(
            "state_permissions",
            "error",
            snapshot.state_permission_issues[0],
            evidence={"path": snapshot.state_permission_path or ""},
        )
    return Finding("state_permissions", "ok", "gcpctx state paths have safe permissions")


def check_impersonation_iam(snapshot: DoctorSnapshot) -> Finding | None:  # noqa: PLR0911
    if snapshot.impersonation_iam_ok is None and not snapshot.impersonation_iam_skipped_adc:
        return None
    sa = snapshot.service_account or ""
    if snapshot.impersonation_iam_skipped_adc:
        return Finding(
            "impersonation_iam",
            "warning",
            "Skipped IAM probe: ADC not initialized",
            evidence={"reason": "adc_missing"},
        )
    if snapshot.impersonation_iam_ok:
        return Finding(
            "impersonation_iam",
            "ok",
            "IAM impersonation probe succeeded",
            evidence={"service_account": sa},
        )
    message = snapshot.impersonation_iam_error or "IAM impersonation probe failed"
    return Finding(
        "impersonation_iam",
        "error",
        message,
        evidence={"service_account": sa},
    )


_CHECK_FNS: dict[str, CheckFn] = {
    "config": check_config,
    "profile": check_profile,
    "policy": check_policy,
    "settings": check_settings,
    "gcloud_trust": check_gcloud_trust,
    "approval": check_approval,
    "approval_expiry": check_approval_expiry,
    "expected_context": check_expected_context,
    "ambient_cloudsdk": check_ambient_cloudsdk,
    "env_project": check_env_project,
    "gcloud_project": check_gcloud_project,
    "impersonation": check_impersonation,
    "adc": check_adc,
    "gac": check_gac,
    "state_permissions": check_state_permissions,
    "impersonation_iam": check_impersonation_iam,
}


def _append_result(findings: list[Finding], result: Finding | Sequence[Finding] | None) -> None:
    if result is None:
        return
    if isinstance(result, Finding):
        findings.append(result)
    else:
        findings.extend(result)


def evaluate_all(snapshot: DoctorSnapshot) -> list[Finding]:
    """Run checks in registry order; skip strict-only when not effective_strict."""
    if snapshot.policy_error is not None and not snapshot.config_found:
        finding = check_policy(snapshot)
        return [finding] if finding is not None else []

    findings: list[Finding] = []
    for check_id in CHECK_EVALUATION_ORDER:
        if check_id in STRICT_ONLY_CHECK_IDS and not snapshot.effective_strict:
            continue
        fn = _CHECK_FNS.get(check_id)
        if fn is None:
            continue
        _append_result(findings, fn(snapshot))
    return findings
