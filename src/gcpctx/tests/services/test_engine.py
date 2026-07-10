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
"""Engine resolve/plan/apply tests with in-memory fakes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.adapters.system import NullPrompter
from gcpctx.approvals import add_approval, find_matching_approval
from gcpctx.errors import ApprovalRequiredError, ConfigNotFoundError
from gcpctx.models import ActivationRequest
from gcpctx.project_context import resolve_project_context
from gcpctx.services.engine import Engine
from gcpctx.tests.fakes import FakeAuditSink, FakeClock, FakeEnv, FakeGcloudPort

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.ports import Prompter


def _engine(
    *,
    gcloud: FakeGcloudPort | None = None,
    env: FakeEnv | None = None,
    audit: FakeAuditSink | None = None,
    prompter: Prompter | None = None,
) -> tuple[Engine, FakeGcloudPort, FakeAuditSink, FakeEnv]:
    port = gcloud or FakeGcloudPort()
    sink = audit or FakeAuditSink()
    fake_env = env or FakeEnv()
    engine = Engine(
        gcloud=port,
        env=fake_env,
        audit=sink,
        clock=FakeClock(),
        prompter=prompter,
    )
    return engine, port, sink, fake_env


def test_resolve_plan_apply_happy_path(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    engine, _, audit, _ = _engine()
    request = ActivationRequest(
        cwd=project_tree,
        shell_name="zsh",
        interactive=False,
        skip_gcloud_init=True,
    )
    res = engine.resolve(request.cwd, request.profile)
    assert res.approval is not None
    plan = engine.plan(res, request)
    assert plan.denial is None
    assert plan.active is True
    result = engine.apply(plan, res)
    assert result.active is True
    assert result.exports["CLOUDSDK_CORE_PROJECT"] == ctx.project
    assert result.exports["GCPCTX_ACTIVE"] == "1"
    assert any(event["event"] == "activation" for event in audit.events)
    assert find_matching_approval(ctx) is not None


def test_activate_happy_path(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    engine, *_ = _engine()
    result = engine.activate(
        ActivationRequest(
            cwd=project_tree,
            shell_name="zsh",
            interactive=False,
            skip_gcloud_init=True,
        )
    )
    assert result.active is True
    assert result.project == "my-dev-project"


def test_null_prompter_fails_closed(project_tree: Path) -> None:
    engine, *_ = _engine(prompter=NullPrompter())
    with pytest.raises(ApprovalRequiredError):
        engine.activate(
            ActivationRequest(
                cwd=project_tree,
                shell_name="zsh",
                interactive=False,
                skip_gcloud_init=True,
            )
        )


def test_explain_plan_does_not_apply(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="once")
    engine, _, audit, _ = _engine()
    plan = engine.explain_plan(
        ActivationRequest(
            cwd=project_tree,
            shell_name="zsh",
            interactive=False,
            skip_gcloud_init=True,
        )
    )
    assert plan.active is True
    assert audit.events == []
    assert find_matching_approval(ctx) is not None


def test_missing_config_via_engine(tmp_path: Path) -> None:
    engine, _, _, env = _engine(env=FakeEnv({"GCPCTX_ACTIVE": "1"}))
    result = engine.missing_config_result()
    assert result.active is False
    assert result.noop is False
    assert env.get("GCPCTX_ACTIVE") == "1"

    engine2, *_ = _engine(env=FakeEnv())
    noop = engine2.missing_config_result()
    assert noop.noop is True

    with pytest.raises(ConfigNotFoundError):
        engine2.activate(
            ActivationRequest(
                cwd=tmp_path,
                shell_name="zsh",
                interactive=False,
                run_mode=True,
                skip_gcloud_init=True,
            )
        )
