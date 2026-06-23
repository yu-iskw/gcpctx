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
"""Secure directory and file permission helpers."""

from __future__ import annotations

import stat
import sys
from typing import TYPE_CHECKING

from gcpctx.errors import UnsafePermissionError

if TYPE_CHECKING:
    from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def ensure_dir(path: Path) -> None:
    """Create directory with restrictive permissions."""
    if path.exists():
        check_path_permissions(path, expect_dir=True)
        return
    path.mkdir(parents=True, exist_ok=True)
    if not _chmod_supported():
        return
    path.chmod(DIR_MODE)
    mode = path.stat().st_mode & 0o777
    if mode != DIR_MODE:
        msg = f"unsafe directory permissions on {path}: {oct(mode)}"
        raise UnsafePermissionError(msg)


def ensure_file(path: Path, content: str) -> None:
    """Write file with restrictive permissions.

    Parent directories are created if missing but not permission-checked; only
    gcpctx-managed state trees should use `ensure_dir` on ancestors first.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if not _chmod_supported():
        return
    path.chmod(FILE_MODE)
    mode = path.stat().st_mode & 0o777
    if mode != FILE_MODE:
        msg = f"unsafe file permissions on {path}: {oct(mode)}"
        raise UnsafePermissionError(msg)


def check_path_permissions(path: Path, *, expect_dir: bool) -> None:
    """Validate existing path permissions."""
    if not path.exists():
        return
    if not _chmod_supported():
        return
    mode = path.stat().st_mode
    if expect_dir and not stat.S_ISDIR(mode):
        msg = f"expected directory at {path}"
        raise UnsafePermissionError(msg)
    perm = mode & 0o777
    expected = DIR_MODE if expect_dir else FILE_MODE
    if perm != expected:
        msg = f"unsafe permissions on {path}: {oct(perm)}, expected {oct(expected)}"
        raise UnsafePermissionError(msg)


def check_config_permissions(root: Path) -> None:
    """Validate .gcpctx.toml permissions when group/other bits are set."""
    config = root / ".gcpctx.toml"
    if not config.exists() or not _chmod_supported():
        return
    mode = config.stat().st_mode
    perm = mode & 0o077
    if perm != 0:
        msg = f"unsafe permissions on {config}: group/other bits set ({oct(mode & 0o777)})"
        raise UnsafePermissionError(msg)


def _chmod_supported() -> bool:
    return sys.platform != "win32"
