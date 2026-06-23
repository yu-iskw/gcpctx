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
"""Security permission tests."""

from __future__ import annotations

import stat
from typing import TYPE_CHECKING

import pytest

from gcpctx import paths
from gcpctx.errors import UnsafePermissionError
from gcpctx.security import (
    DIR_MODE,
    FILE_MODE,
    ensure_dir,
    ensure_file,
    ensure_managed_file,
    ensure_secure_tree,
    reject_symlink,
)

if TYPE_CHECKING:
    from pathlib import Path

LOOSE_MODE = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO


def test_ensure_dir_restrictive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    managed = tmp_path / "config" / "gcpctx"
    monkeypatch.setattr(paths, "user_config_path", lambda: managed)
    target = managed / "secret"
    ensure_dir(target)
    mode = target.stat().st_mode & 0o777
    assert mode == DIR_MODE


def test_ensure_file_restrictive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    managed = tmp_path / "config" / "gcpctx"
    monkeypatch.setattr(paths, "user_config_path", lambda: managed)
    target = managed / "nested" / "file.json"
    ensure_managed_file(target, "{}")
    mode = target.stat().st_mode & 0o777
    assert mode == FILE_MODE


def test_ensure_dir_repairs_loose_managed_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed = tmp_path / "config" / "gcpctx"
    monkeypatch.setattr(paths, "user_config_path", lambda: managed)
    target = managed / "loose"
    target.mkdir(parents=True)
    target.chmod(LOOSE_MODE)
    ensure_dir(target)
    assert (target.stat().st_mode & 0o777) == DIR_MODE


def test_ensure_file_allows_loose_parent_dir(tmp_path: Path) -> None:
    parent = tmp_path / "repo"
    parent.mkdir()
    parent.chmod(LOOSE_MODE)
    target = parent / ".gcpctx.toml"
    ensure_file(target, "version = 1\n")
    assert (target.stat().st_mode & 0o777) == FILE_MODE


def test_reject_symlink(tmp_path: Path) -> None:
    target = tmp_path / "link"
    target.symlink_to(tmp_path / "real")
    with pytest.raises(UnsafePermissionError):
        reject_symlink(target)


def test_ensure_secure_tree_repairs_loose_managed_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed = tmp_path / "cache" / "gcpctx"
    monkeypatch.setattr(paths, "user_cache_path", lambda: managed)
    contexts = managed / "contexts"
    contexts.mkdir(parents=True)
    contexts.chmod(LOOSE_MODE)
    ensure_secure_tree(contexts / "ctx-id" / "gcloud")
    assert (contexts.stat().st_mode & 0o777) == DIR_MODE
