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

import contextlib
import fcntl
import os
import stat
import sys
from typing import TYPE_CHECKING

from gcpctx import paths
from gcpctx.errors import UnsafePermissionError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def _managed_roots() -> tuple[Path, Path]:
    return paths.user_config_path().resolve(), paths.user_cache_path().resolve()


def _is_managed_state_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    config_root, cache_root = _managed_roots()
    return (
        resolved in {config_root, cache_root}
        or _path_is_relative_to(resolved, config_root)
        or _path_is_relative_to(resolved, cache_root)
    )


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        return path.is_relative_to(root)
    except AttributeError:
        return str(path).startswith(f"{root}{os.sep}")


def reject_symlink(path: Path) -> None:
    """Raise if *path* exists and is a symlink."""
    try:
        st = path.lstat()
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        msg = f"symlink not allowed at {path}"
        raise UnsafePermissionError(msg)


def ensure_dir(path: Path) -> None:
    """Create directory with restrictive permissions."""
    reject_symlink(path)
    if path.exists():
        if _is_managed_state_path(path):
            _chmod_managed_ancestors(path)
            check_path_permissions(path, expect_dir=True)
        return
    path.mkdir(parents=True, exist_ok=True)
    if not _chmod_supported():
        return
    _chmod_managed_ancestors(path)
    if _is_managed_state_path(path):
        mode = path.stat().st_mode & 0o777
        if mode != DIR_MODE:
            msg = f"unsafe directory permissions on {path}: {oct(mode)}"
            raise UnsafePermissionError(msg)


def _chmod_managed_ancestors(path: Path) -> None:  # noqa: PLR0912
    config_root, cache_root = _managed_roots()
    current = path.resolve()
    visited: list[Path] = []
    while True:
        visited.append(current)
        if current in {config_root, cache_root}:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    for directory in reversed(visited):
        if not _is_managed_state_path(directory) or not directory.is_dir():
            continue
        directory.chmod(DIR_MODE)
        mode = directory.stat().st_mode & 0o777
        if mode != DIR_MODE:
            msg = f"unsafe directory permissions on {directory}: {oct(mode)}"
            raise UnsafePermissionError(msg)


def _managed_ancestor_parts(root: Path) -> list[Path]:
    config_root, cache_root = _managed_roots()
    current = root.resolve()
    parts: list[Path] = []
    while True:
        if not (
            current in {config_root, cache_root}
            or _path_is_relative_to(current, config_root)
            or _path_is_relative_to(current, cache_root)
        ):
            break
        parts.append(current)
        if current in {config_root, cache_root}:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return parts


def ensure_secure_tree(root: Path) -> None:
    """Ensure managed ancestors of *root* are owner-only without scanning /."""
    if not _chmod_supported():
        return
    parts = _managed_ancestor_parts(root)
    if not parts:
        return
    _chmod_managed_ancestors(parts[0])
    for directory in reversed(parts):
        reject_symlink(directory)
        if directory.exists():
            check_path_permissions(directory, expect_dir=True)


def secure_atomic_write_text(path: Path, content: str, *, managed_state: bool = False) -> None:  # noqa: PLR0912
    """Atomically write *content* with restrictive permissions and symlink safety."""
    if managed_state:
        ensure_dir(path.parent)
        ensure_secure_tree(path.parent)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if _chmod_supported():
            mode = path.stat().st_mode & 0o777
            if mode != FILE_MODE:
                msg = f"unsafe file permissions on {path}: {oct(mode)}"
                raise UnsafePermissionError(msg)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)


def ensure_file(path: Path, content: str, *, managed_state: bool = False) -> None:
    """Write file with restrictive permissions via atomic replace."""
    secure_atomic_write_text(path, content, managed_state=managed_state)


def ensure_managed_file(path: Path, content: str) -> None:
    """Write a gcpctx-managed state file with full tree hardening."""
    secure_atomic_write_text(path, content, managed_state=True)


def secure_read_text(path: Path) -> str:
    """Read file text after symlink and permission checks."""
    reject_symlink(path)
    check_path_permissions(path, expect_dir=False)
    return path.read_text(encoding="utf-8")


@contextlib.contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Advisory exclusive lock on a companion .lock file next to *path*."""
    ensure_dir(path.parent)
    lock_path = path.with_name(f".{path.name}.lock")
    reject_symlink(lock_path)
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError as exc:
        msg = f"failed to acquire lock for {path}: {exc}"
        raise UnsafePermissionError(msg) from exc


def check_path_permissions(path: Path, *, expect_dir: bool) -> None:
    """Validate existing path permissions."""
    if not path.exists():
        return
    if not _chmod_supported():
        return
    reject_symlink(path)
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
    reject_symlink(config)
    mode = config.stat().st_mode
    perm = mode & 0o077
    if perm != 0:
        msg = f"unsafe permissions on {config}: group/other bits set ({oct(mode & 0o777)})"
        raise UnsafePermissionError(msg)


def is_posix_platform() -> bool:
    """Return True when platform supports gcpctx security guarantees."""
    return sys.platform != "win32"


def _chmod_supported() -> bool:
    return is_posix_platform()
