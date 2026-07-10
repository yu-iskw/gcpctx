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
"""Frozen doctor snapshot and finding types (pure data)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from gcpctx.core.policy import SecurityPolicy

CheckStatus = Literal["ok", "warning", "error"]


@dataclass(frozen=True, slots=True)
class ApprovalFacts:
    """Approval record fields needed by doctor checks."""

    mode: str
    expires_at: str | None = None
    evidence_id: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """One doctor check observation before aggregation."""

    check_id: str
    status: CheckStatus
    message: str
    evidence: dict[str, str] = field(default_factory=dict)
    remediation_command: str | None = None
    exit_code: int | None = None


@dataclass(frozen=True, slots=True)
class DoctorSnapshot:
    """All facts doctor checks need; gathered via ports/I/O, judged purely."""

    interactive: bool
    strict: bool
    effective_strict: bool
    cache_root: str
    policy: SecurityPolicy | None = None
    policy_error: str | None = None
    policy_error_exit_code: int | None = None
    cwd_str: str = ""
    config_found: bool = False
    config_error: str | None = None
    schema_error: bool = False
    config_error_exit_code: int | None = None
    profile_name: str | None = None
    project: str | None = None
    service_account: str | None = None
    context_id: str | None = None
    root_str: str | None = None
    config_path: str | None = None
    expected_cloudsdk_config: str | None = None
    expected_cloudsdk_invalid: bool = False
    ambient_cloudsdk_config: str | None = None
    ambient_cloudsdk_invalid: bool = False
    env_cloudsdk_core_project: str | None = None
    gac_set: bool = False
    gac_value: str | None = None
    approval_matching: ApprovalFacts | None = None
    approval_identity: ApprovalFacts | None = None
    approval_expired: ApprovalFacts | None = None
    gcloud_trust_path: str | None = None
    gcloud_trust_sha256: str | None = None
    gcloud_trust_warnings: tuple[str, ...] = ()
    gcloud_trust_error: str | None = None
    gcloud_project_property: str | None = None
    impersonation_property: str | None = None
    adc_exists: bool | None = None
    impersonation_iam_ok: bool | None = None
    impersonation_iam_skipped_adc: bool = False
    impersonation_iam_error: str | None = None
    state_permission_issues: tuple[str, ...] = ()
    state_permission_path: str | None = None
    state_permissions_checked: bool = False
    deprecated_global_gcloud_path: str | None = None
