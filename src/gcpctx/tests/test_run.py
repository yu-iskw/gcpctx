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

from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gcpctx.activation import activate, child_environ
from gcpctx.approvals import add_approval
from gcpctx.cli import app
from gcpctx.errors import ConfigNotFoundError
from gcpctx.models import ActivationRequest, ActivationResult
from gcpctx.project_context import resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "cache" / "gcpctx"
    config = tmp_path / "config" / "gcpctx"
    cache.mkdir(parents=True)
    config.mkdir(parents=True)
    cache.chmod(0o700)
    config.chmod(0o700)
    monkeypatch.setattr("gcpctx.paths.user_cache_path", lambda: cache)
    monkeypatch.setattr("gcpctx.paths.user_config_path", lambda: config)
    monkeypatch.setattr("gcpctx.paths.context_base_dir", lambda: cache / "contexts")
    monkeypatch.setattr("gcpctx.paths.approvals_file", lambda: config / "approvals.json")


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


def test_run_cli_invokes_command(
    project_tree: Path,
    fake_gcloud: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
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
    assert result.exit_code == 0
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
    add_approval(ctx, mode="remembered")
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
