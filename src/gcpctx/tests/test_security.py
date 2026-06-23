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

from gcpctx.errors import UnsafePermissionError
from gcpctx.security import DIR_MODE, FILE_MODE, ensure_dir, ensure_file

if TYPE_CHECKING:
    from pathlib import Path

LOOSE_MODE = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO


def test_ensure_dir_restrictive(tmp_path: Path) -> None:
    target = tmp_path / "secret"
    ensure_dir(target)
    mode = target.stat().st_mode & 0o777
    assert mode == DIR_MODE


def test_ensure_file_restrictive(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "file.json"
    ensure_file(target, "{}")
    mode = target.stat().st_mode & 0o777
    assert mode == FILE_MODE


def test_unsafe_dir_raises(tmp_path: Path) -> None:
    target = tmp_path / "loose"
    target.mkdir()
    target.chmod(LOOSE_MODE)
    with pytest.raises(UnsafePermissionError):
        ensure_dir(target)
