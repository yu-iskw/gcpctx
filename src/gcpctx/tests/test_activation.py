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

from gcpctx import paths
from gcpctx.activation import activate, deactivate, missing_config_result
from gcpctx.approvals import add_approval, find_matching_approval
from gcpctx.errors import ApprovalRequiredError, CredentialConflictError
from gcpctx.models import ActivationRequest
from gcpctx.project_context import resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


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


def test_once_approval_preserved_when_adc_not_initialized(
    project_tree: Path,
) -> None:
    policy_path = paths.user_config_path() / "policy.toml"
    policy_path.write_text(
        "version = 1\n\n[policy]\nrequire_initialized_adc_for_hook = true\n",
        encoding="utf-8",
    )
    policy_path.chmod(0o600)
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="once")
    result = activate(
        ActivationRequest(
            cwd=project_tree,
            shell_name="zsh",
            interactive=False,
            hook_mode=True,
            skip_gcloud_init=True,
        )
    )
    assert result.active is False
    assert result.readiness == "approved_not_initialized"
    assert find_matching_approval(ctx) is not None
