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

from gcpctx import paths
from gcpctx.approvals import add_approval
from gcpctx.context_id import ContextIdInput, derive_context_id
from gcpctx.doctor import run_doctor
from gcpctx.paths import cloudsdk_config_dir
from gcpctx.project_context import resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


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
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))
    monkeypatch.setenv("GCPCTX_ACTIVE", "1")

    result = run_doctor(project_tree, interactive=False)

    names = {check.name for check in result.checks}
    assert "config" in names
    assert "profile" in names
    assert "approval" in names
    assert "expected_context" in names
    assert "ambient_cloudsdk" in names
    config_check = next(c for c in result.checks if c.name == "config")
    ambient_check = next(c for c in result.checks if c.name == "ambient_cloudsdk")
    assert config_check.status == "ok"
    assert ambient_check.status == "ok"


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_ambient_cloudsdk_error_when_not_under_cache(
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

    ambient_check = next(c for c in result.checks if c.name == "ambient_cloudsdk")
    assert ambient_check.status == "error"
    assert "not under gcpctx cache" in ambient_check.message


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_strict_fails_when_ambient_points_to_stale_context(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    expected = ctx.expected_cloudsdk_config()
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


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_strict_rejects_approval_without_gcloud_binding(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered", gcloud_trust=None)
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))

    result = run_doctor(project_tree, interactive=False, strict=True)

    approval_check = next(c for c in result.checks if c.name == "approval")
    assert approval_check.status == "error"


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_reports_invalid_policy(project_tree: Path) -> None:
    policy_path = paths.user_config_path() / "policy.toml"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text("version = 1\n[policy\n", encoding="utf-8")
    policy_path.chmod(0o600)

    result = run_doctor(project_tree, interactive=False)

    policy_check = next(c for c in result.checks if c.name == "policy")
    assert policy_check.status == "error"
    assert result.exit_code == 7
