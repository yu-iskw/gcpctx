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
"""Cleanup command tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx import cleanup, paths
from gcpctx.errors import UnsafePermissionError
from gcpctx.project_context import resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


def test_remove_context_deletes_isolated_tree(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    ctx_dir = paths.context_dir(ctx.context_id())
    gcloud_dir = ctx_dir / "gcloud"
    gcloud_dir.mkdir(parents=True)
    (gcloud_dir / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    (ctx_dir / "state.json").write_text("{}", encoding="utf-8")

    removed = cleanup.remove_context(ctx.context_id())

    assert removed == [ctx_dir]
    assert not ctx_dir.exists()


def test_remove_all_contexts_skips_unrelated_cache_files() -> None:
    contexts = paths.context_base_dir()
    contexts.mkdir(parents=True, exist_ok=True)
    (contexts / "aaa").mkdir()
    (contexts / "bbb").mkdir()
    other = paths.user_cache_path() / "other.txt"
    other.write_text("keep", encoding="utf-8")

    removed = cleanup.remove_all_contexts()

    assert len(removed) == 2
    assert not (contexts / "aaa").exists()
    assert not (contexts / "bbb").exists()
    assert other.read_text(encoding="utf-8") == "keep"


def test_remove_approvals() -> None:
    approvals = paths.approvals_file()
    approvals.parent.mkdir(parents=True, exist_ok=True)
    approvals.write_text('{"approvals":[]}', encoding="utf-8")

    removed = cleanup.remove_approvals()

    assert removed == [approvals]
    assert not approvals.exists()


def test_remove_context_dry_run_leaves_files(project_tree: Path) -> None:
    ctx = resolve_project_context(project_tree)
    ctx_dir = paths.context_dir(ctx.context_id())
    ctx_dir.mkdir(parents=True)

    removed = cleanup.remove_context(ctx.context_id(), dry_run=True)

    assert removed == [ctx_dir]
    assert ctx_dir.is_dir()


def test_remove_context_idempotent_when_missing() -> None:
    assert not cleanup.remove_context("0" * 24)


def test_remove_context_rejects_invalid_id() -> None:
    with pytest.raises(UnsafePermissionError, match="invalid context_id"):
        cleanup.remove_context("..")
