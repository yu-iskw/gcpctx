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

from gcpctx import paths
from gcpctx.cli import app
from gcpctx.project_context import resolve_project_context

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


def test_config_unset_gcloud_path(project_tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(project_tree)
    gcloud_bin = project_tree / "gcloud"
    gcloud_bin.write_bytes(b"fake")
    gcloud_bin.chmod(0o755)
    set_result = runner.invoke(app, ["config", "set-gcloud-path", str(gcloud_bin)])
    assert set_result.exit_code == 0

    result = runner.invoke(app, ["config", "unset-gcloud-path"])
    assert result.exit_code == 0
    assert "Cleared gcloud_path" in result.stdout
    config_text = (project_tree / ".gcpctx.toml").read_text(encoding="utf-8")
    assert "gcloud_path" not in config_text


def test_clean_project_context(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    ctx_dir = paths.context_dir(ctx.context_id())
    ctx_dir.mkdir(parents=True)

    result = runner.invoke(app, ["clean", "--cwd", str(project_tree)])

    assert result.exit_code == 0
    assert "removed" in result.stdout
    assert not ctx_dir.exists()


def test_clean_nothing_to_remove(project_tree: Path) -> None:
    result = runner.invoke(app, ["clean", "--cwd", str(project_tree)])
    assert result.exit_code == 0
    assert "nothing to clean" in result.stdout


def test_clean_dry_run_leaves_context(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    ctx_dir = paths.context_dir(ctx.context_id())
    ctx_dir.mkdir(parents=True)

    result = runner.invoke(app, ["clean", "--cwd", str(project_tree), "--dry-run"])

    assert result.exit_code == 0
    assert "would remove" in result.stdout
    assert ctx_dir.is_dir()


def test_clean_reinit_rejected_with_all_contexts() -> None:
    result = runner.invoke(app, ["clean", "--all-contexts", "--reinit"])
    assert result.exit_code == 2
    assert "--reinit requires project-scoped clean" in result.stderr


@pytest.mark.parametrize(
    ("shell", "rc_file"),
    [("zsh", "~/.zshrc"), ("bash", "~/.bashrc")],
)
def test_init_prints_snippet_and_instructions(shell: str, rc_file: str) -> None:
    result = runner.invoke(app, ["init", shell])
    assert result.exit_code == 0
    assert "# >>> gcpctx hook >>>" in result.stdout
    assert "gcpctx-use" in result.stdout
    assert "Installed" not in result.stdout
    assert rc_file in result.stderr
    assert "exec $SHELL" in result.stderr
