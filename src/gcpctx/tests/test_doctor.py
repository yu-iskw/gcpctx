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
from gcpctx.doctor import run_doctor
from gcpctx.paths import cloudsdk_config_dir
from gcpctx.project_context import resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "cache" / "gcpctx"
    config = tmp_path / "config" / "gcpctx"
    cache.mkdir(parents=True)
    config.mkdir(parents=True)
    cache.chmod(0o700)
    config.chmod(0o700)
    monkeypatch.setattr("gcpctx.paths.user_cache_path", lambda: cache)
    monkeypatch.setattr("gcpctx.doctor.user_cache_path", lambda: cache)
    monkeypatch.setattr("gcpctx.paths.user_config_path", lambda: config)
    monkeypatch.setattr("gcpctx.paths.context_base_dir", lambda: cache / "contexts")
    monkeypatch.setattr("gcpctx.paths.approvals_file", lambda: config / "approvals.json")


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_happy_path(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    ctx_id = "doctorctx1234567890123456"
    isolated = cloudsdk_config_dir(ctx_id)
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))
    monkeypatch.setenv("GCPCTX_ACTIVE", "1")

    result = run_doctor(project_tree, interactive=False)

    names = {check.name for check in result.checks}
    assert "config" in names
    assert "profile" in names
    assert "approval" in names
    assert "isolation" in names
    config_check = next(c for c in result.checks if c.name == "config")
    isolation_check = next(c for c in result.checks if c.name == "isolation")
    assert config_check.status == "ok"
    assert isolation_check.status == "ok"


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
