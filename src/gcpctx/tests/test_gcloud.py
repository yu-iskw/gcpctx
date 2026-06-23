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
"""gcloud integration tests with fake gcloud."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from gcpctx.gcloud import InitContext, ensure_initialized, run_gcloud
from gcpctx.models import ProfileConfig
from gcpctx.paths import cloudsdk_config_dir

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def isolated_cache() -> None:
    """Use global conftest state isolation."""


def test_run_gcloud_passes_cloudsdk_config(
    fake_gcloud: Path,
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    run_gcloud(["config", "set", "project", "my-dev-project"], cloudsdk_config=config_dir)
    lines = fake_gcloud.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[0])
    assert entry["CLOUDSDK_CONFIG"] == str(config_dir)
    assert entry["argv"] == ["config", "set", "project", "my-dev-project"]


def test_run_gcloud_merges_environ_and_strips_gac(
    fake_gcloud: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secret/key.json")
    monkeypatch.setenv("GCPCTX_TEST_MARKER", "present")
    run_gcloud(["config", "set", "project", "my-dev-project"], cloudsdk_config=config_dir)
    entry = json.loads(fake_gcloud.read_text(encoding="utf-8").strip().splitlines()[0])
    assert entry["CLOUDSDK_CONFIG"] == str(config_dir)
    assert entry["has_gac"] is False
    assert entry["marker"] == "present"


def test_ensure_initialized_calls(
    fake_gcloud: Path,
    project_tree: Path,
) -> None:
    profile = ProfileConfig(
        project="my-dev-project",
        service_account="agent-dev@my-dev-project.iam.gserviceaccount.com",
        quota_project="billing-project",
        region="asia-northeast1",
    )
    ctx_id = "testctx123456789012345678"
    ensure_initialized(
        InitContext(
            context_id=ctx_id,
            root=project_tree,
            profile_name="dev",
            profile=profile,
            config_sha256="abc",
            gcloud_executable=str(fake_gcloud.parent / "gcloud"),
            force=True,
        )
    )
    lines = fake_gcloud.read_text(encoding="utf-8").strip().splitlines()
    argv_list = [json.loads(line)["argv"] for line in lines]
    assert ["config", "set", "project", "my-dev-project"] in argv_list
    assert [
        "config",
        "set",
        "auth/impersonate_service_account",
        "agent-dev@my-dev-project.iam.gserviceaccount.com",
    ] in argv_list
    assert [
        "auth",
        "application-default",
        "login",
        "--impersonate-service-account",
        "agent-dev@my-dev-project.iam.gserviceaccount.com",
    ] in argv_list
    assert [
        "auth",
        "application-default",
        "set-quota-project",
        "billing-project",
    ] in argv_list
    assert cloudsdk_config_dir(ctx_id).is_dir()
