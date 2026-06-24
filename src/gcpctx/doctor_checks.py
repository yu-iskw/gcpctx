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
"""Stable doctor check registry for gcpctx v0.3+."""

from __future__ import annotations

from dataclasses import dataclass

from gcpctx.exit_codes import ExitCode

ACTIVATE_SHELL_REMEDIATION = 'eval "$(gcpctx activate --shell zsh)"'


@dataclass(frozen=True, slots=True)
class DoctorCheckSpec:
    """Metadata for a stable doctor check id."""

    exit_code: ExitCode
    docs: str
    default_command: str | None = None


DOCTOR_CHECK_REGISTRY: dict[str, DoctorCheckSpec] = {
    "config": DoctorCheckSpec(
        ExitCode.CONFIG_NOT_FOUND,
        "docs/checks/config.md",
        "gcpctx create",
    ),
    "profile": DoctorCheckSpec(
        ExitCode.CONFIG_NOT_FOUND,
        "docs/checks/profile.md",
    ),
    "policy": DoctorCheckSpec(
        ExitCode.POLICY_VIOLATION,
        "docs/checks/policy.md",
    ),
    "settings": DoctorCheckSpec(
        ExitCode.GENERIC_ERROR,
        "docs/checks/settings.md",
        "Remove deprecated keys from ~/.config/gcpctx/settings.toml",
    ),
    "gcloud_trust": DoctorCheckSpec(
        ExitCode.GCLOUD_TRUST_FAILURE,
        "docs/checks/gcloud_trust.md",
        'gcpctx config "$(which gcloud)"',
    ),
    "approval": DoctorCheckSpec(
        ExitCode.APPROVAL_REQUIRED,
        "docs/checks/approval.md",
        "gcpctx approve",
    ),
    "approval_expiry": DoctorCheckSpec(
        ExitCode.APPROVAL_REQUIRED,
        "docs/checks/approval_expiry.md",
        "gcpctx approve",
    ),
    "expected_context": DoctorCheckSpec(
        ExitCode.CONFIG_NOT_FOUND,
        "docs/checks/expected_context.md",
        ACTIVATE_SHELL_REMEDIATION,
    ),
    "ambient_cloudsdk": DoctorCheckSpec(
        ExitCode.CONFIG_NOT_FOUND,
        "docs/checks/ambient_cloudsdk.md",
        ACTIVATE_SHELL_REMEDIATION,
    ),
    "env_project": DoctorCheckSpec(
        ExitCode.CONFIG_NOT_FOUND,
        "docs/checks/env_project.md",
        ACTIVATE_SHELL_REMEDIATION,
    ),
    "gcloud_project": DoctorCheckSpec(
        ExitCode.GCLOUD_TRUST_FAILURE,
        "docs/checks/gcloud_project.md",
        "gcpctx reload",
    ),
    "impersonation": DoctorCheckSpec(
        ExitCode.GCLOUD_TRUST_FAILURE,
        "docs/checks/impersonation.md",
        "gcpctx reload",
    ),
    "adc": DoctorCheckSpec(
        ExitCode.ADC_NOT_INITIALIZED,
        "docs/checks/adc.md",
        "gcpctx reload",
    ),
    "gac": DoctorCheckSpec(
        ExitCode.POLICY_VIOLATION,
        "docs/checks/gac.md",
        "unset GOOGLE_APPLICATION_CREDENTIALS",
    ),
    "state_permissions": DoctorCheckSpec(
        ExitCode.UNSAFE_FILESYSTEM,
        "docs/checks/state_permissions.md",
        "chmod 700 ~/.cache/gcpctx && chmod 600 ~/.config/gcpctx/approvals.json",
    ),
    "impersonation_iam": DoctorCheckSpec(
        ExitCode.IAM_IMPERSONATION_FAILURE,
        "docs/checks/impersonation_iam.md",
        "Grant roles/iam.serviceAccountTokenCreator on the service account",
    ),
}


DOCTOR_CHECK_IDS: frozenset[str] = frozenset(DOCTOR_CHECK_REGISTRY)


def check_exit_code(check_id: str) -> ExitCode:
    """Return the exit code associated with a doctor check id."""
    spec = DOCTOR_CHECK_REGISTRY.get(check_id)
    if spec is None:
        return ExitCode.GENERIC_ERROR
    return spec.exit_code
