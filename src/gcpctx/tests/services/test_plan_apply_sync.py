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
"""Contract test: plan steps produced by build_activation_plan match what Engine.apply executes.

These tests document the step-level contract between the plan builder and the apply phase.
``ensure_initialized`` on the GcloudPort must implement EnsureContextDir + SetGcloudProperty
(project and impersonation SA) + InitImpersonatedAdc + WriteContextState — the ``build_init_steps``
strangler contract (see ADR-0003, ADR-0005).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.approvals import add_approval
from gcpctx.core.plan import (
    ConsumeOnceApproval,
    EnsureContextDir,
    InitImpersonatedAdc,
    SetGcloudProperty,
    WriteContextState,
    build_activation_plan,
    build_init_steps,
)
from gcpctx.models import ActivationRequest
from gcpctx.project_context import resolve_project_context
from gcpctx.services.engine import Engine
from gcpctx.tests.fakes import FakeAuditSink, FakeEnv, FakeGcloudPort

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.core.plan import ActivationFacts, Plan, Step


def _make_facts(project_tree: Path) -> ActivationFacts:
    """Return ActivationFacts for a typical remembered approval."""
    from gcpctx.core.plan import ActivationFacts

    ctx = resolve_project_context(project_tree)
    cloudsdk_config = str(ctx.expected_cloudsdk_config())
    return ActivationFacts(
        root_str=str(ctx.root),
        profile_name=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        config_sha256=ctx.config_sha256,
        context_id=ctx.context_id(),
        cloudsdk_config=cloudsdk_config,
        profile_env={},
        approval_present=True,
        skip_gcloud_init=False,
    )


def _step_types(plan: Plan) -> list[type[Step]]:
    return [type(s) for s in plan.steps]


class TestBuildInitStepsContract:
    """build_init_steps must include all the gcloud properties Engine.apply needs."""

    def test_includes_project_property(self, project_tree: Path) -> None:
        ctx = resolve_project_context(project_tree)
        steps = build_init_steps(
            context_id=ctx.context_id(),
            project=ctx.project,
            service_account=ctx.service_account,
            region=None,
            zone=None,
            force_refresh=False,
        )
        project_steps = [
            s for s in steps if isinstance(s, SetGcloudProperty) and s.key == "project"
        ]
        assert len(project_steps) == 1
        assert project_steps[0].value == ctx.project

    def test_includes_impersonation_property(self, project_tree: Path) -> None:
        ctx = resolve_project_context(project_tree)
        steps = build_init_steps(
            context_id=ctx.context_id(),
            project=ctx.project,
            service_account=ctx.service_account,
            region=None,
            zone=None,
            force_refresh=False,
        )
        sa_steps = [
            s
            for s in steps
            if isinstance(s, SetGcloudProperty) and s.key == "auth/impersonate_service_account"
        ]
        assert len(sa_steps) == 1
        assert sa_steps[0].value == ctx.service_account

    def test_includes_init_impersonated_adc(self, project_tree: Path) -> None:
        ctx = resolve_project_context(project_tree)
        steps = build_init_steps(
            context_id=ctx.context_id(),
            project=ctx.project,
            service_account=ctx.service_account,
            region=None,
            zone=None,
            force_refresh=False,
        )
        assert any(isinstance(s, InitImpersonatedAdc) for s in steps)

    def test_step_order_ensure_dir_before_init_before_write(self, project_tree: Path) -> None:
        ctx = resolve_project_context(project_tree)
        steps = build_init_steps(
            context_id=ctx.context_id(),
            project=ctx.project,
            service_account=ctx.service_account,
            region=None,
            zone=None,
            force_refresh=False,
        )
        types = [type(s) for s in steps]
        assert types.index(EnsureContextDir) < types.index(InitImpersonatedAdc)
        assert types.index(InitImpersonatedAdc) < types.index(WriteContextState)


class TestPlanContractWithApproval:
    """build_activation_plan with skip_gcloud_init=False must include init steps."""

    def test_plan_includes_set_gcloud_property_project(self, project_tree: Path) -> None:
        facts = _make_facts(project_tree)
        plan = build_activation_plan(facts)
        assert plan.denial is None
        project_steps = [
            s for s in plan.steps if isinstance(s, SetGcloudProperty) and s.key == "project"
        ]
        assert len(project_steps) == 1
        assert project_steps[0].value == facts.project

    def test_plan_includes_set_gcloud_property_impersonation_sa(self, project_tree: Path) -> None:
        facts = _make_facts(project_tree)
        plan = build_activation_plan(facts)
        sa_steps = [
            s
            for s in plan.steps
            if isinstance(s, SetGcloudProperty) and s.key == "auth/impersonate_service_account"
        ]
        assert len(sa_steps) == 1
        assert sa_steps[0].value == facts.service_account

    def test_plan_includes_init_impersonated_adc(self, project_tree: Path) -> None:
        facts = _make_facts(project_tree)
        plan = build_activation_plan(facts)
        assert any(isinstance(s, InitImpersonatedAdc) for s in plan.steps)

    def test_plan_includes_consume_once_approval(self, project_tree: Path) -> None:
        facts = _make_facts(project_tree)
        plan = build_activation_plan(facts)
        assert any(isinstance(s, ConsumeOnceApproval) for s in plan.steps)


class TestEnginePlanApplyIntegration:
    """Engine plan + apply with a real init state surfaces step-contract violations."""

    def _engine(self) -> tuple[Engine, FakeGcloudPort]:
        port = FakeGcloudPort()
        sink = FakeAuditSink()
        engine = Engine(gcloud=port, env=FakeEnv(), audit=sink)
        return engine, port

    def test_apply_calls_ensure_initialized_when_plan_has_init(self, project_tree: Path) -> None:
        ctx = resolve_project_context(project_tree)
        add_approval(ctx, mode="remembered")
        engine, port = self._engine()

        from gcpctx.models import ContextState
        from gcpctx.timeutil import utc_now_iso

        ctx_id = ctx.context_id()
        now = utc_now_iso()
        port.init_states[ctx_id] = ContextState(
            root=str(ctx.root),
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256=ctx.config_sha256,
            last_checked_at=now,
            last_initialized_at=now,
        )

        request = ActivationRequest(cwd=project_tree, shell_name="zsh", interactive=False)
        res = engine.resolve(request.cwd, request.profile)
        plan = engine.plan(res, request)
        assert plan.denial is None
        assert any(isinstance(s, InitImpersonatedAdc) for s in plan.steps)
        result = engine.apply(plan, res)
        assert result.active is True

    def test_skip_gcloud_init_suppresses_init_step(self, project_tree: Path) -> None:
        ctx = resolve_project_context(project_tree)
        add_approval(ctx, mode="remembered")
        engine, _ = self._engine()

        request = ActivationRequest(
            cwd=project_tree,
            shell_name="zsh",
            interactive=False,
            skip_gcloud_init=True,
        )
        res = engine.resolve(request.cwd, request.profile)
        plan = engine.plan(res, request)
        assert plan.denial is None
        assert not any(isinstance(s, InitImpersonatedAdc) for s in plan.steps)

    @pytest.mark.usefixtures("fake_gcloud")
    def test_apply_does_not_depend_on_approval_existing_after_consume(
        self,
        project_tree: Path,
    ) -> None:
        """Once-approval is consumed atomically; subsequent find returns None."""
        ctx = resolve_project_context(project_tree)
        add_approval(ctx, mode="once")
        engine, port = self._engine()

        from gcpctx.models import ContextState
        from gcpctx.timeutil import utc_now_iso

        ctx_id = ctx.context_id()
        now = utc_now_iso()
        port.init_states[ctx_id] = ContextState(
            root=str(ctx.root),
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256=ctx.config_sha256,
            last_checked_at=now,
            last_initialized_at=now,
        )

        request = ActivationRequest(cwd=project_tree, shell_name="zsh", interactive=False)
        res = engine.resolve(request.cwd, request.profile)
        plan = engine.plan(res, request)
        assert plan.denial is None
        engine.apply(plan, res)

        from gcpctx.approvals import find_matching_approval

        assert find_matching_approval(ctx) is None
