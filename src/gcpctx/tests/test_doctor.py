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
"""Doctor diagnostic tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.approvals import add_approval
from gcpctx.context_id import ContextIdInput, derive_context_id
from gcpctx.doctor import run_doctor
from gcpctx.paths import cloudsdk_config_dir
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


def _expected_cloudsdk(ctx: ResolvedProjectContext) -> Path:
    ctx_id = derive_context_id(
        ContextIdInput(
            root=ctx.root,
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256=ctx.config_sha256,
        )
    )
    return cloudsdk_config_dir(ctx_id)


@pytest.fixture(autouse=True)
def isolated_state() -> None:
    """Use global conftest state isolation."""


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_happy_path(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    isolated = _expected_cloudsdk(ctx)
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))
    monkeypatch.setenv("GCPCTX_ACTIVE", "1")

    result = run_doctor(project_tree, interactive=False)

    names = {check.name for check in result.checks}
    assert "config" in names
    assert "profile" in names
    assert "approval" in names or "approval_expiry" in names
    assert "expected_context" in names
    assert "ambient_cloudsdk" in names
    config_check = next(c for c in result.checks if c.name == "config")
    ambient_check = next(c for c in result.checks if c.name == "ambient_cloudsdk")
    assert config_check.status == "ok"
    assert ambient_check.status == "ok"


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_isolation_error_when_not_under_cache(
    project_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    outside_config = tmp_path / "outside-gcloud"
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(outside_config))
    monkeypatch.setenv("GCPCTX_ACTIVE", "1")

    result = run_doctor(project_tree, interactive=False)

    isolation_check = next(c for c in result.checks if c.name == "isolation")
    assert isolation_check.status == "error"


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_strict_fails_when_ambient_points_to_stale_context(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    expected = _expected_cloudsdk(ctx)
    expected.mkdir(parents=True)
    (expected / "application_default_credentials.json").write_text("{}", encoding="utf-8")

    stale_id = derive_context_id(
        ContextIdInput(
            root=ctx.root,
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256="0" * 64,
        )
    )
    stale = cloudsdk_config_dir(stale_id)
    stale.mkdir(parents=True)
    (stale / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(stale))

    result = run_doctor(project_tree, interactive=False, strict=True)

    ambient_check = next(c for c in result.checks if c.name == "ambient_cloudsdk")
    assert ambient_check.status == "error"
    assert result.exit_code != 0
