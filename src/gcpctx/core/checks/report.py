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
"""Pure aggregation of Findings into DoctorResult."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from gcpctx.core.checks.registry import CHECK_EVALUATION_ORDER, WARN_ONLY_CHECK_IDS, check_exit_code
from gcpctx.core.contract import DOCTOR_CHECK_REGISTRY
from gcpctx.core.model import DoctorCheck, DoctorRemediation, DoctorResult

if TYPE_CHECKING:
    from gcpctx.core.checks.snapshot import CheckStatus, Finding

_STATUS_RANK = {"ok": 0, "warning": 1, "error": 2}


@dataclass
class _AccumulatedCheck:
    """Merged state for a single doctor check id."""

    status: CheckStatus = "ok"
    messages: list[str] = field(default_factory=list)
    evidence: dict[str, str] = field(default_factory=dict)
    remediation_command: str | None = None


def build_doctor_check(check_id: str, accumulated: _AccumulatedCheck) -> DoctorCheck:
    """Convert accumulated check state into the public DoctorCheck model."""
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


def _normalize_status(
    check_id: str,
    status: CheckStatus,
    *,
    strict: bool,
) -> CheckStatus:
    if status == "warning" and strict and check_id not in WARN_ONLY_CHECK_IDS:
        return "error"
    return status


def _contributes_exit(
    check_id: str,
    status: CheckStatus,
    *,
    interactive: bool,
    strict: bool,
) -> bool:
    if check_id in WARN_ONLY_CHECK_IDS:
        return False
    if status == "error":
        return True
    return status == "warning" and not interactive and not strict


def findings_to_result(  # noqa: PLR0912, PLR0913
    findings: list[Finding],
    *,
    version: str,
    interactive: bool,
    strict: bool,
    profile: str | None = None,
    context_id: str | None = None,
) -> DoctorResult:
    """Aggregate findings into a DoctorResult (exit codes + JSON contract)."""
    accumulated: dict[str, _AccumulatedCheck] = {}
    exit_code = 0

    for finding in findings:
        status = _normalize_status(finding.check_id, finding.status, strict=strict)
        entry = accumulated.setdefault(finding.check_id, _AccumulatedCheck())
        if _STATUS_RANK[status] > _STATUS_RANK[entry.status]:
            entry.status = status
        entry.messages.append(finding.message)
        if finding.evidence:
            entry.evidence.update(finding.evidence)
        if finding.remediation_command is not None:
            entry.remediation_command = finding.remediation_command
        elif entry.remediation_command is None:
            spec = DOCTOR_CHECK_REGISTRY.get(finding.check_id)
            if spec is not None:
                entry.remediation_command = spec.default_command
        if _contributes_exit(finding.check_id, status, interactive=interactive, strict=strict):
            code = (
                finding.exit_code
                if finding.exit_code is not None
                else int(check_exit_code(finding.check_id))
            )
            exit_code = max(exit_code, code)

    checks = [
        build_doctor_check(check_id, accumulated[check_id])
        for check_id in CHECK_EVALUATION_ORDER
        if check_id in accumulated
    ]
    has_warn = any(check.status == "warn" for check in checks)
    if exit_code != 0:
        aggregate_status: Literal["ok", "warn", "fail"] = "fail"
    elif has_warn:
        aggregate_status = "warn"
    else:
        aggregate_status = "ok"
    return DoctorResult(
        version=version,
        status=aggregate_status,
        profile=profile,
        context_id=context_id,
        checks=checks,
        exit_code=exit_code,
    )
