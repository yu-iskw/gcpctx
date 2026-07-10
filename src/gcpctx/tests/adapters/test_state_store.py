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
"""FilesystemStateStore adapter tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.adapters.state import FilesystemStateStore, resolve_state_key
from gcpctx.errors import UnsafePermissionError
from gcpctx.security import FILE_MODE

if TYPE_CHECKING:
    from pathlib import Path


def test_write_read_roundtrip() -> None:
    store = FilesystemStateStore()
    store.write("approvals", b'{"approvals":[]}')
    assert store.read("approvals") == b'{"approvals":[]}'
    path = store.resolve("approvals")
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == FILE_MODE


def test_delete_removes_file() -> None:
    store = FilesystemStateStore()
    store.write("approvals", b"{}")
    store.delete("approvals")
    assert store.read("approvals") is None


def test_lock_context_manager() -> None:
    store = FilesystemStateStore()
    with store.lock("approvals"):
        store.write("approvals", b'{"locked":true}')
    assert store.read("approvals") == b'{"locked":true}'


def test_context_state_key_and_absolute_path() -> None:
    store = FilesystemStateStore()
    store.write("contexts/abc123/state", b'{"ok":true}')
    assert store.read("contexts/abc123/state") == b'{"ok":true}'
    abs_path = resolve_state_key("contexts/abc123/state")
    assert abs_path.is_absolute()
    assert store.read(str(abs_path)) == b'{"ok":true}'
    with pytest.raises(KeyError, match="unknown state key"):
        store.resolve("not-a-key")


def test_reject_symlink_on_read(tmp_path: Path) -> None:
    store = FilesystemStateStore()
    target = store.resolve("approvals")
    target.parent.mkdir(parents=True, exist_ok=True)
    real = tmp_path / "elsewhere.json"
    real.write_text("{}", encoding="utf-8")
    target.symlink_to(real)
    with pytest.raises(UnsafePermissionError, match="symlink"):
        store.read("approvals")
