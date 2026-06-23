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

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from gcpctx import __version__, paths
from gcpctx.approvals import add_approval, load_store, save_store
from gcpctx.context_id import ContextIdInput, derive_context_id
from gcpctx.doctor import run_doctor
from gcpctx.exit_codes import ExitCode
from gcpctx.models import ApprovalRecord
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

    ids = {check.id for check in result.checks}
    assert "config" in ids
    assert "profile" in ids
    assert "approval" in ids
    assert "approval_expiry" in ids
    assert "expected_context" in ids
    assert "ambient_cloudsdk" in ids
    config_check = next(c for c in result.checks if c.id == "config")
    ambient_check = next(c for c in result.checks if c.id == "ambient_cloudsdk")
    assert config_check.status == "pass"
    assert ambient_check.status == "pass"
    assert result.version == __version__
    assert result.status == "ok"
    assert result.profile == ctx.profile_name
    assert result.context_id == ctx.context_id()


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

    ambient_check = next(c for c in result.checks if c.id == "ambient_cloudsdk")
    assert ambient_check.status == "fail"
    assert "not under gcpctx cache" in ambient_check.message
    assert ambient_check.remediation is not None
    assert ambient_check.remediation.docs is not None


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

    ambient_check = next(c for c in result.checks if c.id == "ambient_cloudsdk")
    assert ambient_check.status == "fail"
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

    approval_check = next(c for c in result.checks if c.id == "approval")
    assert approval_check.status == "fail"


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_reports_invalid_policy(project_tree: Path) -> None:
    policy_path = paths.user_config_path() / "policy.toml"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text("version = 1\n[policy\n", encoding="utf-8")
    policy_path.chmod(0o600)

    result = run_doctor(project_tree, interactive=False)

    policy_check = next(c for c in result.checks if c.id == "policy")
    assert policy_check.status == "fail"
    assert result.exit_code == int(ExitCode.POLICY_VIOLATION)


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_reports_expired_approval(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    store = load_store()
    expired_at = (datetime.now(tz=UTC) - timedelta(days=1)).isoformat()
    store.approvals = [
        ApprovalRecord(
            root=str(ctx.root.resolve()),
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256=ctx.config_sha256,
            approved_at=datetime.now(tz=UTC).isoformat(),
            mode="remembered",
            expires_at=expired_at,
        )
    ]
    save_store(store)
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))

    result = run_doctor(project_tree, interactive=False)

    expiry_check = next(c for c in result.checks if c.id == "approval_expiry")
    assert expiry_check.status == "fail"
    assert expiry_check.evidence.get("expires_at") == expired_at
    assert result.exit_code == int(ExitCode.APPROVAL_REQUIRED)


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_json_contract_shape(project_tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))

    result = run_doctor(project_tree, interactive=False)
    payload = json.loads(result.model_dump_json())

    assert set(payload) >= {"version", "status", "profile", "context_id", "exit_code", "checks"}
    assert payload["version"] == __version__
    for check in payload["checks"]:
        assert set(check) >= {"id", "severity", "status", "message", "evidence", "remediation"}
        if check["status"] == "fail":
            assert check["remediation"] is not None
            assert check["remediation"].get("docs")


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_settings_warning_non_interactive_does_not_fail(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = paths.user_config_path() / "settings.toml"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text('version = 1\ngcloud_path = "/usr/bin/gcloud"\n', encoding="utf-8")
    settings_path.chmod(0o600)

    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))

    result = run_doctor(project_tree, interactive=False)

    settings_check = next(c for c in result.checks if c.id == "settings")
    assert settings_check.status == "warn"
    assert result.exit_code == 0
    assert result.status == "warn"


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_approval_expiry_ok_when_valid_once_approval_exists(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    once = add_approval(ctx, mode="once")
    store = load_store()
    expired_at = (datetime.now(tz=UTC) - timedelta(days=1)).isoformat()
    store.approvals.append(
        ApprovalRecord(
            root=once.root,
            profile=once.profile,
            project=once.project,
            service_account=once.service_account,
            config_sha256=once.config_sha256,
            approved_at=(datetime.now(tz=UTC).isoformat()),
            mode="remembered",
            expires_at=expired_at,
        )
    )
    save_store(store)
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))

    result = run_doctor(project_tree, interactive=False)

    expiry_check = next(c for c in result.checks if c.id == "approval_expiry")
    assert expiry_check.status == "pass"
    assert "Valid approval is active" in expiry_check.message
