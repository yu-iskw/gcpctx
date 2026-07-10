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
"""Pure activation plan tests."""

from __future__ import annotations

import pytest

from gcpctx.core.contract import ExitCode
from gcpctx.core.plan import (
    ADC_NOT_READY_WARNING,
    APPROVAL_REQUIRED_MESSAGE,
    GAC_CONFLICT_MESSAGE,
    GAC_WARNING,
    ActivationFacts,
    ConsumeOnceApproval,
    InitImpersonatedAdc,
    build_activation_plan,
    build_exports,
    evaluate_gac_policy,
)


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


@pytest.mark.parametrize(
    ("profile_env", "region", "zone"),
    [
        ({}, None, None),
        ({"CUSTOM_FLAG": "1"}, "us-central1", None),
        ({"CLOUDSDK_CORE_PROJECT": "evil"}, "us-east1", "us-east1-b"),
    ],
)
def test_exports_always_set_cloudsdk_core_project(
    profile_env: dict[str, str],
    region: str | None,
    zone: str | None,
) -> None:
    exports = build_exports(
        root_str="/repo",
        profile_name="dev",
        project="my-dev-project",
        service_account="sa@my-dev-project.iam.gserviceaccount.com",
        context_id="abc123",
        cloudsdk_config="/cache/gcloud",
        profile_env=profile_env,
        region=region,
        zone=zone,
    )
    assert exports["CLOUDSDK_CORE_PROJECT"] == "my-dev-project"
    assert exports["GCPCTX_PROJECT"] == "my-dev-project"
    assert "CLOUDSDK_CORE_PROJECT" not in profile_env or exports["CLOUDSDK_CORE_PROJECT"] != "evil"


@pytest.mark.parametrize(
    ("kwargs", "expect_denial", "expect_warning", "expect_unsets"),
    [
        (
            {
                "gac_set": False,
                "interactive": False,
                "allow_gac": False,
                "hook_mode": False,
                "run_mode": False,
            },
            False,
            False,
            (),
        ),
        (
            {
                "gac_set": True,
                "interactive": False,
                "allow_gac": False,
                "hook_mode": False,
                "run_mode": False,
            },
            True,
            False,
            (),
        ),
        (
            {
                "gac_set": True,
                "interactive": True,
                "allow_gac": False,
                "hook_mode": False,
                "run_mode": False,
            },
            False,
            True,
            ("GOOGLE_APPLICATION_CREDENTIALS",),
        ),
        (
            {
                "gac_set": True,
                "interactive": True,
                "allow_gac": True,
                "hook_mode": False,
                "run_mode": False,
            },
            False,
            True,
            (),
        ),
        (
            {
                "gac_set": True,
                "interactive": True,
                "allow_gac": True,
                "hook_mode": True,
                "run_mode": False,
            },
            False,
            True,
            ("GOOGLE_APPLICATION_CREDENTIALS",),
        ),
        (
            {
                "gac_set": True,
                "interactive": False,
                "allow_gac": True,
                "hook_mode": False,
                "run_mode": True,
            },
            False,
            True,
            ("GOOGLE_APPLICATION_CREDENTIALS",),
        ),
    ],
)
def test_gac_policy_rules(
    kwargs: dict[str, bool],
    expect_denial: bool,
    expect_warning: bool,
    expect_unsets: tuple[str, ...],
) -> None:
    denial, warnings, unsets = evaluate_gac_policy(**kwargs)
    if expect_denial:
        assert denial is not None
        assert denial.exit_code == int(ExitCode.POLICY_VIOLATION)
        assert denial.message == GAC_CONFLICT_MESSAGE
    else:
        assert denial is None
    assert (GAC_WARNING in warnings) is expect_warning
    assert unsets == expect_unsets


def test_denial_without_approval() -> None:
    plan = build_activation_plan(_facts(approval_present=False))
    assert plan.denial is not None
    assert plan.denial.exit_code == int(ExitCode.APPROVAL_REQUIRED)
    assert plan.denial.message == APPROVAL_REQUIRED_MESSAGE
    assert plan.active is False
    assert plan.steps == ()


def test_hook_adc_readiness_preserves_once_approval() -> None:
    plan = build_activation_plan(
        _facts(
            hook_mode=True,
            require_initialized_adc_for_hook=True,
            adc_exists=False,
            skip_gcloud_init=True,
        )
    )
    assert plan.denial is None
    assert plan.active is False
    assert plan.readiness == "approved_not_initialized"
    assert ADC_NOT_READY_WARNING in plan.warnings
    assert not any(isinstance(step, ConsumeOnceApproval) for step in plan.steps)
    assert plan.env_delta.exports == {}


def test_ready_plan_includes_consume_and_exports() -> None:
    plan = build_activation_plan(_facts())
    assert plan.denial is None
    assert plan.active is True
    assert plan.readiness == "ready"
    assert any(isinstance(step, ConsumeOnceApproval) for step in plan.steps)
    assert plan.env_delta.exports["CLOUDSDK_CORE_PROJECT"] == "my-dev-project"
    assert plan.env_delta.exports["CLOUDSDK_CONFIG"] == "/cache/contexts/abc123/gcloud"


def test_init_steps_when_not_skipping_gcloud() -> None:
    plan = build_activation_plan(_facts(skip_gcloud_init=False, force_refresh=True))
    assert any(isinstance(step, InitImpersonatedAdc) and step.force for step in plan.steps)
    assert any(isinstance(step, ConsumeOnceApproval) for step in plan.steps)


def test_gac_denial_in_plan() -> None:
    plan = build_activation_plan(_facts(gac_set=True, interactive=False, allow_gac=False))
    assert plan.denial is not None
    assert plan.denial.exit_code == int(ExitCode.POLICY_VIOLATION)
