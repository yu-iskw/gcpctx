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
"""RFC §9.1: plan refuses and doctor check fails for the same invariants."""

from __future__ import annotations

from gcpctx.core.checks.evaluators import (
    check_approval,
    check_env_project,
    check_gac,
)
from gcpctx.core.checks.snapshot import DoctorSnapshot
from gcpctx.core.contract import ExitCode
from gcpctx.core.plan import (
    APPROVAL_REQUIRED_MESSAGE,
    GAC_CONFLICT_MESSAGE,
    ActivationFacts,
    build_activation_plan,
    build_exports,
)
from gcpctx.core.policy import SecurityPolicy


def _snapshot(**overrides: object) -> DoctorSnapshot:
    base: dict[str, object] = {
        "interactive": False,
        "strict": False,
        "effective_strict": False,
        "cache_root": "/cache/gcpctx",
        "cwd_str": "/repo",
        "policy": SecurityPolicy(),
        "config_found": True,
        "profile_name": "dev",
        "project": "my-dev-project",
        "service_account": "sa@my-dev-project.iam.gserviceaccount.com",
        "context_id": "abc123",
        "root_str": "/repo",
        "config_path": "/repo/.gcpctx.toml",
        "expected_cloudsdk_config": "/cache/gcpctx/contexts/abc123/gcloud",
        "gcloud_trust_path": "/usr/bin/gcloud",
        "adc_exists": True,
    }
    base.update(overrides)
    return DoctorSnapshot(**base)  # type: ignore[arg-type]


def _facts(**overrides: object) -> ActivationFacts:
    base: dict[str, object] = {
        "root_str": "/repo",
        "profile_name": "dev",
        "project": "my-dev-project",
        "service_account": "sa@my-dev-project.iam.gserviceaccount.com",
        "config_sha256": "a" * 64,
        "context_id": "abc123",
        "cloudsdk_config": "/cache/contexts/abc123/gcloud",
        "profile_env": {},
        "approval_present": True,
        "interactive": False,
        "skip_gcloud_init": True,
    }
    base.update(overrides)
    return ActivationFacts(**base)  # type: ignore[arg-type]


def test_gac_set_plan_denies_and_check_fails() -> None:
    plan = build_activation_plan(_facts(gac_set=True, interactive=False, allow_gac=False))
    assert plan.denial is not None
    assert plan.denial.exit_code == int(ExitCode.POLICY_VIOLATION)
    assert plan.denial.message == GAC_CONFLICT_MESSAGE

    finding = check_gac(_snapshot(gac_set=True, gac_value="/tmp/creds.json"))
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "gac"
    assert "GOOGLE_APPLICATION_CREDENTIALS is set" in finding.message


def test_no_approval_plan_denies_and_check_fails() -> None:
    plan = build_activation_plan(_facts(approval_present=False))
    assert plan.denial is not None
    assert plan.denial.exit_code == int(ExitCode.APPROVAL_REQUIRED)
    assert plan.denial.message == APPROVAL_REQUIRED_MESSAGE

    finding = check_approval(_snapshot(approval_matching=None))
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "approval"
    assert finding.message == "No matching approval"


def test_env_project_mismatch_exports_win_and_check_fails() -> None:
    exports = build_exports(
        root_str="/repo",
        profile_name="dev",
        project="my-dev-project",
        service_account="sa@my-dev-project.iam.gserviceaccount.com",
        context_id="abc123",
        cloudsdk_config="/cache/gcloud",
        profile_env={"CLOUDSDK_CORE_PROJECT": "evil-project"},
    )
    assert exports["CLOUDSDK_CORE_PROJECT"] == "my-dev-project"

    finding = check_env_project(
        _snapshot(env_cloudsdk_core_project="evil-project", project="my-dev-project")
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "env_project"
    assert finding.evidence["expected"] == "my-dev-project"
    assert finding.evidence["actual"] == "evil-project"
