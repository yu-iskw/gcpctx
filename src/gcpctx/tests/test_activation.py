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
"""Activation tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.activation import activate, deactivate, missing_config_result
from gcpctx.approvals import add_approval
from gcpctx.errors import ApprovalRequiredError, CredentialConflictError
from gcpctx.models import ActivationRequest
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
    monkeypatch.setattr("gcpctx.paths.user_config_path", lambda: config)
    monkeypatch.setattr("gcpctx.paths.context_base_dir", lambda: cache / "contexts")
    monkeypatch.setattr("gcpctx.paths.approvals_file", lambda: config / "approvals.json")


def test_deactivate_inactive() -> None:
    result = deactivate()
    assert result.active is False


def test_missing_config_noop_when_inactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GCPCTX_ACTIVE", raising=False)
    result = missing_config_result()
    assert result.active is False
    assert result.noop is True


def test_missing_config_deactivates_when_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GCPCTX_ACTIVE", "1")
    result = missing_config_result()
    assert result.active is False
    assert result.noop is False


def test_activate_without_approval_non_interactive(project_tree: Path) -> None:
    request = ActivationRequest(
        cwd=project_tree,
        shell_name="zsh",
        interactive=False,
        skip_gcloud_init=True,
    )
    with pytest.raises(ApprovalRequiredError):
        activate(request)


def test_activate_with_approval(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    request = ActivationRequest(
        cwd=project_tree,
        shell_name="zsh",
        interactive=False,
        skip_gcloud_init=True,
    )
    result = activate(request)
    assert result.active is True
    assert result.project == "my-dev-project"
    assert result.exports["GCPCTX_ACTIVE"] == "1"


def test_gac_conflict_non_interactive(
    project_tree: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "key.json"))
    request = ActivationRequest(
        cwd=project_tree,
        shell_name="zsh",
        interactive=False,
        skip_gcloud_init=True,
    )
    with pytest.raises(CredentialConflictError):
        activate(request)
