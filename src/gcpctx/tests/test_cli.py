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
"""CLI smoke tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gcpctx.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()
CONFIG_NOT_FOUND_EXIT = 2


def test_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "gcpctx" in result.stdout


def test_profiles_not_found(tmp_path: Path) -> None:
    result = runner.invoke(app, ["profiles", "--cwd", str(tmp_path)])
    assert result.exit_code == CONFIG_NOT_FOUND_EXIT


def test_hook_eval_noop_outside_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GCPCTX_ACTIVE", raising=False)
    result = runner.invoke(app, ["hook", "eval", "zsh", "--cwd", str(tmp_path)])
    assert result.exit_code == 0
    assert result.stdout == ""


def test_hook_eval_deactivates_outside_project_when_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GCPCTX_ACTIVE", "1")
    result = runner.invoke(app, ["hook", "eval", "zsh", "--cwd", str(tmp_path)])
    assert result.exit_code == 0
    assert "unset GCPCTX_ACTIVE" in result.stdout


def test_hook_eval_activation_failure_emits_deactivate(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(project_tree)
    result = runner.invoke(app, ["hook", "eval", "zsh"])
    assert result.exit_code == 3
    assert "unset GCPCTX_ACTIVE" in result.stdout
    assert "approval required" in result.stderr.lower()


def test_config_unset_gcloud_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from gcpctx import paths
    from gcpctx.settings import UserSettings, load_settings, save_settings

    settings_path = paths.user_config_path() / "settings.toml"
    monkeypatch.setattr("gcpctx.settings.settings_file", lambda: settings_path)

    save_settings(UserSettings(gcloud_path="/usr/bin/gcloud"))
    result = runner.invoke(app, ["config", "unset-gcloud-path"])
    assert result.exit_code == 0
    assert "Cleared gcloud_path" in result.stdout
    assert load_settings().gcloud_path is None
