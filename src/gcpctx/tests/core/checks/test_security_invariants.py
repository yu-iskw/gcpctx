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
    check_adc,
    check_ambient_cloudsdk,
    check_approval,
    check_approval_expiry,
    check_env_project,
    check_expected_context,
    check_gac,
    check_gcloud_project,
    check_gcloud_trust,
    check_impersonation,
    check_impersonation_iam,
    check_policy,
    check_state_permissions,
)
from gcpctx.core.checks.snapshot import ApprovalFacts, DoctorSnapshot
from gcpctx.core.contract import ExitCode
from gcpctx.core.plan import (
    APPROVAL_REQUIRED_MESSAGE,
    GAC_CONFLICT_MESSAGE,
    ActivationFacts,
    InitImpersonatedAdc,
    SetGcloudProperty,
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


def test_isolated_cloudsdk_plan_exports_and_check_fails_outside_cache() -> None:
    plan = build_activation_plan(_facts())
    assert plan.denial is None
    assert plan.env_delta.exports["CLOUDSDK_CONFIG"].endswith("/gcloud")

    finding = check_expected_context(
        _snapshot(expected_cloudsdk_config="/tmp/evil-gcloud", expected_cloudsdk_invalid=False)
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "expected_context"

    ambient = check_ambient_cloudsdk(
        _snapshot(
            ambient_cloudsdk_config="/home/user/.config/gcloud",
            expected_cloudsdk_config="/cache/gcpctx/contexts/abc123/gcloud",
        )
    )
    assert ambient is not None
    assert ambient.status == "error"
    assert ambient.check_id == "ambient_cloudsdk"


def test_impersonation_plan_sets_sa_and_check_fails_on_mismatch() -> None:
    plan = build_activation_plan(_facts(skip_gcloud_init=False))
    assert plan.denial is None
    sa_steps = [
        step
        for step in plan.steps
        if isinstance(step, SetGcloudProperty) and step.key == "auth/impersonate_service_account"
    ]
    assert sa_steps
    assert sa_steps[0].value == "sa@my-dev-project.iam.gserviceaccount.com"
    assert any(isinstance(step, InitImpersonatedAdc) for step in plan.steps)

    finding = check_impersonation(
        _snapshot(
            impersonation_property="other@my-dev-project.iam.gserviceaccount.com",
            service_account="sa@my-dev-project.iam.gserviceaccount.com",
            adc_exists=True,
            gcloud_trust_path="/usr/bin/gcloud",
        )
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "impersonation"


def test_gcloud_project_mismatch_check_fails() -> None:
    finding = check_gcloud_project(
        _snapshot(
            gcloud_project_property="other-project",
            project="my-dev-project",
            adc_exists=True,
            gcloud_trust_path="/usr/bin/gcloud",
        )
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "gcloud_project"


def test_gcloud_trust_failure_check() -> None:
    findings = check_gcloud_trust(
        _snapshot(gcloud_trust_path=None, gcloud_trust_error="untrusted binary")
    )
    assert findings is not None
    assert any(f.status == "error" and f.check_id == "gcloud_trust" for f in findings)


def test_state_permissions_strict_check_fails() -> None:
    finding = check_state_permissions(
        _snapshot(
            state_permissions_checked=True,
            state_permission_issues=("unsafe permissions on approvals.json",),
            state_permission_path="/config/approvals.json",
        )
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "state_permissions"


def test_policy_allowlist_denial_via_strict_facts() -> None:
    """Plan still requires approval; policy violations surface at config parse time.

    Doctor policy check reports loaded mode; allowlist denials are ConfigValidationError
    before planning. Assert plan refuses without approval under strict policy flags.
    """
    plan = build_activation_plan(
        _facts(
            approval_present=False,
            require_initialized_adc_for_hook=True,
        )
    )
    assert plan.denial is not None
    assert plan.denial.exit_code == int(ExitCode.APPROVAL_REQUIRED)


def test_approval_expiry_expired_remembered_check_fails() -> None:
    """Expired remembered approval → approval_expiry check fails.

    Plan side: approval_present=False (expired record does not count as matching)
    → plan denies with APPROVAL_REQUIRED.
    """
    expired = ApprovalFacts(
        mode="remembered",
        expires_at="2024-01-01T00:00:00+00:00",
        evidence_id="abc123",
    )
    finding = check_approval_expiry(
        _snapshot(
            approval_matching=None,
            approval_identity=expired,
            approval_expired=expired,
        )
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "approval_expiry"
    assert "expired" in finding.message

    plan = build_activation_plan(_facts(approval_present=False))
    assert plan.denial is not None
    assert plan.denial.exit_code == int(ExitCode.APPROVAL_REQUIRED)


def test_adc_not_exists_check_fails_plan_includes_init_step() -> None:
    """adc_exists=False → check_adc fails; plan with skip_gcloud_init=False includes InitImpersonatedAdc.

    The check detects the unhealthy state; the plan knows how to fix it.
    """
    finding = check_adc(
        _snapshot(
            adc_exists=False,
            gcloud_trust_path="/usr/bin/gcloud",
        )
    )
    assert finding is not None
    assert finding.status in ("error", "warning")
    assert finding.check_id == "adc"

    plan = build_activation_plan(_facts(skip_gcloud_init=False, adc_exists=False))
    assert plan.denial is None
    assert any(isinstance(step, InitImpersonatedAdc) for step in plan.steps)


def test_policy_error_check_fails() -> None:
    """policy_error in snapshot → check_policy returns an error finding.

    Policy load errors surface in the snapshot before config resolution;
    no plan is built in this path.
    """
    finding = check_policy(
        _snapshot(
            config_found=False,
            policy=None,
            policy_error="policy.toml: unknown key 'bad_field'",
            policy_error_exit_code=int(ExitCode.POLICY_VIOLATION),
        )
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "policy"
    assert "policy.toml" in finding.message


def test_impersonation_iam_probe_fails_check_fails() -> None:
    """impersonation_iam check fails when probe returns ok=False."""
    finding = check_impersonation_iam(
        _snapshot(
            impersonation_iam_ok=False,
            impersonation_iam_skipped_adc=False,
            impersonation_iam_error="IAM impersonation probe failed: permission denied",
        )
    )
    assert finding is not None
    assert finding.status == "error"
    assert finding.check_id == "impersonation_iam"
    assert "failed" in finding.message.lower() or "denied" in finding.message.lower()
