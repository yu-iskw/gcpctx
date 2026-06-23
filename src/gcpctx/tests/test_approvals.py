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
"""Approval store tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx import paths
from gcpctx.approvals import add_approval, find_matching_approval, revoke_approval
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


def _ctx(project_tree: Path, config_sha256: str | None = None) -> ResolvedProjectContext:
    ctx = resolve_project_context(project_tree)
    if config_sha256 is None:
        return ctx
    return ResolvedProjectContext(
        root=ctx.root,
        profile_name=ctx.profile_name,
        profile=ctx.profile,
        config_sha256=config_sha256,
    )


@pytest.fixture(autouse=True)
def isolated_approvals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config_dir = tmp_path / "config" / "gcpctx"
    config_dir.mkdir(parents=True)
    config_dir.chmod(0o700)
    approvals_json = config_dir / "approvals.json"

    def _approvals_file() -> Path:
        return approvals_json

    monkeypatch.setattr("gcpctx.paths.approvals_file", _approvals_file)
    return approvals_json


def test_persist_and_match(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    record = find_matching_approval(ctx)
    assert record is not None
    assert record.mode == "remembered"
    assert paths.approvals_file().is_file()


def test_config_hash_invalidation(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    assert find_matching_approval(_ctx(project_tree, "sha2")) is None


def test_revoke(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    assert revoke_approval(ctx)
