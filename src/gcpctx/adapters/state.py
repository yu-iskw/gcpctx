# Copyright 2025 yu-iskw
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Filesystem-backed StateStore — the single writer for managed state."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from gcpctx import paths
from gcpctx.security import (
    ensure_managed_file,
    file_lock,
    reject_symlink,
    secure_read_text,
    secure_remove_tree,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

_CONTEXT_STATE_PARTS = 3


def _context_state_path(key: str) -> Path | None:
    if not (key.startswith("contexts/") and key.endswith("/state")):
        return None
    parts = key.split("/")
    if len(parts) != _CONTEXT_STATE_PARTS or not parts[1]:
        return None
    return paths.context_state_file(parts[1])


def _logical_state_path(key: str) -> Path | None:
    if key == "approvals":
        return paths.approvals_file()
    if key == "audit":
        return paths.user_config_path() / "audit.jsonl"
    return _context_state_path(key)


def resolve_state_key(key: str) -> Path:
    """Map a logical state key (or absolute path) to a filesystem path."""
    logical = _logical_state_path(key)
    if logical is not None:
        return logical
    path = Path(key)
    if path.is_absolute():
        return path
    msg = f"unknown state key: {key}"
    raise KeyError(msg)


class FilesystemStateStore:
    """Atomic, locked, symlink-safe state under managed gcpctx roots."""

    def resolve(self, key: str) -> Path:
        """Resolve *key* to a path (logical key or absolute path)."""
        return resolve_state_key(key)

    def read(self, key: str) -> bytes | None:
        """Return file bytes for *key*, or None if missing."""
        path = self.resolve(key)
        if not path.is_file():
            return None
        return secure_read_text(path).encode("utf-8")

    def write(self, key: str, data: bytes) -> None:
        """Atomically write *data* for *key* with managed-file hardening."""
        path = self.resolve(key)
        ensure_managed_file(path, data.decode("utf-8"))

    def delete(self, key: str) -> None:
        """Remove the file or tree for *key* if it exists."""
        path = self.resolve(key)
        if not path.exists():
            return
        reject_symlink(path)
        if path.is_dir():
            secure_remove_tree(path)
            return
        path.unlink()

    @contextmanager
    def lock(self, key: str) -> Iterator[None]:
        """Exclusive advisory lock for *key*."""
        path = self.resolve(key)
        with file_lock(path):
            yield
