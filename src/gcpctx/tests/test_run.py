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
"""gcpctx run command tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gcpctx import paths
from gcpctx.activation import activate, child_environ
from gcpctx.approvals import add_approval, load_store, save_store
from gcpctx.cli import app
from gcpctx.errors import ConfigNotFoundError
from gcpctx.exit_codes import ExitCode
from gcpctx.models import ActivationRequest, ActivationResult
from gcpctx.project_context import resolve_project_context
from gcpctx.tests.conftest import matching_gcloud_trust

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_state() -> None:
    """Use global conftest state isolation."""


def test_child_environ_applies_exports_and_unsets() -> None:
    base = {"PATH": "/usr/bin", "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/key.json"}
    result = ActivationResult(
        active=True,
        exports={"GCPCTX_ACTIVE": "1", "CLOUDSDK_CONFIG": "/cache/ctx/gcloud"},
        unsets=["GOOGLE_APPLICATION_CREDENTIALS"],
    )
    env = child_environ(result, base=base)
    assert env["GCPCTX_ACTIVE"] == "1"
    assert env["CLOUDSDK_CONFIG"] == "/cache/ctx/gcloud"
    assert env["PATH"] == "/usr/bin"
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in env


def test_run_mode_raises_when_no_config(tmp_path: Path) -> None:
    request = ActivationRequest(
        cwd=tmp_path,
        shell_name="zsh",
        run_mode=True,
        skip_gcloud_init=True,
        interactive=False,
    )
    with pytest.raises(ConfigNotFoundError):
        activate(request)


def test_run_no_args() -> None:
    result = runner.invoke(app, ["run"])
    assert result.exit_code == 2
    assert "usage:" in result.stderr.lower()


def test_run_no_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--cwd", str(tmp_path), "--", "env"])
    assert result.exit_code == 2


def test_run_no_approval_non_interactive(project_tree: Path) -> None:
    result = runner.invoke(app, ["run", "--cwd", str(project_tree), "--", "env"])
    assert result.exit_code == 3
    assert "approval required" in result.stderr.lower()


def test_run_happy_path_with_run_scope(
    project_tree: Path,
    fake_gcloud: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(
        ctx,
        mode="remembered",
        scope="run",
        gcloud_trust=matching_gcloud_trust(),
    )
    captured: dict[str, object] = {}

    def fake_run_command(cmd: list[str], env: dict[str, str]) -> int:
        captured["path"] = cmd[0]
        captured["args"] = cmd
        captured["env"] = env
        return 0

    monkeypatch.setattr("gcpctx.cli.run_command", fake_run_command)
    result = runner.invoke(
        app,
        ["run", "--cwd", str(project_tree), "--", "env"],
    )
    assert result.exit_code == 0, result.stderr
    assert fake_gcloud.read_text(encoding="utf-8").strip()
    env = captured["env"]
    assert isinstance(env, dict)
    assert env.get("GCPCTX_ACTIVE") == "1"
    assert env.get("CLOUDSDK_CONFIG")
    assert captured["path"] == "env"
    assert captured["args"] == ["env"]


def test_run_mode_unsets_gac(
    project_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered", scope="run")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "key.json"))
    result = activate(
        ActivationRequest(
            cwd=project_tree,
            shell_name="zsh",
            run_mode=True,
            interactive=True,
            skip_gcloud_init=True,
        )
    )
    assert result.active is True
    assert "GOOGLE_APPLICATION_CREDENTIALS" in result.unsets


def _grant_run(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(
        ctx,
        mode="remembered",
        scope="run",
        gcloud_trust=matching_gcloud_trust(),
    )


def test_run_fails_when_doctor_strict_would_fail(
    project_tree: Path,
    fake_gcloud: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_gcloud
    _grant_run(project_tree)
    policy_path = paths.user_config_path() / "policy.toml"
    policy_path.write_text("version = 1\n[policy\n", encoding="utf-8")
    policy_path.chmod(0o600)
    captured: dict[str, object] = {}

    def fake_run_command(cmd: list[str], env: dict[str, str]) -> int:
        del cmd, env
        captured["called"] = True
        return 0

    monkeypatch.setattr("gcpctx.cli.run_command", fake_run_command)
    doctor = runner.invoke(app, ["doctor", "--strict", "--cwd", str(project_tree)])
    result = runner.invoke(app, ["run", "--cwd", str(project_tree), "--", "true"])
    assert doctor.exit_code == int(ExitCode.POLICY_VIOLATION)
    assert result.exit_code == int(ExitCode.POLICY_VIOLATION)
    assert "called" not in captured


def test_run_rejects_shell_remember_after_run_ttl(
    project_tree: Path,
    fake_gcloud: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_gcloud
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered", scope="shell", gcloud_trust=matching_gcloud_trust())
    add_approval(ctx, mode="remembered", scope="run", gcloud_trust=matching_gcloud_trust())
    store = load_store()
    expired = (datetime.now(tz=UTC) - timedelta(hours=9)).isoformat()
    store.approvals = [
        record.model_copy(update={"expires_at": expired}) if record.scope == "run" else record
        for record in store.approvals
    ]
    save_store(store)
    captured: dict[str, object] = {}

    def fake_run_command(cmd: list[str], env: dict[str, str]) -> int:
        del cmd, env
        captured["called"] = True
        return 0

    monkeypatch.setattr("gcpctx.cli.run_command", fake_run_command)
    result = runner.invoke(app, ["run", "--cwd", str(project_tree), "--", "true"])
    assert result.exit_code == int(ExitCode.APPROVAL_REQUIRED)
    assert "called" not in captured


def test_gcpctx_trust_mismatch_blocks_run_and_hook(
    project_tree: Path,
    fake_gcloud: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_gcloud
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered", scope="shell", gcloud_trust=matching_gcloud_trust())
    add_approval(ctx, mode="remembered", scope="run", gcloud_trust=matching_gcloud_trust())

    def _mutate(field: str) -> None:
        store = load_store()
        store.approvals = [
            record.model_copy(update={field: "d" * 64}) for record in store.approvals
        ]
        save_store(store)

    captured: dict[str, object] = {}

    def fake_run_command(cmd: list[str], env: dict[str, str]) -> int:
        del cmd, env
        captured["called"] = True
        return 0

    monkeypatch.setattr("gcpctx.cli.run_command", fake_run_command)
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))
    for field in (
        "gcpctx_launcher_sha256",
        "gcpctx_python_sha256",
        "gcpctx_package_sha256",
    ):
        add_approval(ctx, mode="remembered", scope="shell", gcloud_trust=matching_gcloud_trust())
        add_approval(ctx, mode="remembered", scope="run", gcloud_trust=matching_gcloud_trust())
        _mutate(field)
        doctor = runner.invoke(app, ["doctor", "--cwd", str(project_tree)])
        run_result = runner.invoke(app, ["run", "--cwd", str(project_tree), "--", "true"])
        hook = runner.invoke(app, ["hook", "--shell", "zsh", "--cwd", str(project_tree)])
        assert doctor.exit_code == int(ExitCode.GCLOUD_TRUST_FAILURE), field
        assert run_result.exit_code == int(ExitCode.GCLOUD_TRUST_FAILURE), field
        assert hook.exit_code == int(ExitCode.GCLOUD_TRUST_FAILURE), field
        assert "unset GCPCTX_ACTIVE" in hook.stdout or "GCPCTX_ACTIVE" in hook.stdout
        assert "called" not in captured
