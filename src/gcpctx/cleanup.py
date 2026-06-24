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
"""Remove gcpctx-managed cache and config state."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from gcpctx import paths
from gcpctx.errors import UnsafePermissionError
from gcpctx.security import secure_remove_tree

if TYPE_CHECKING:
    from pathlib import Path

_CONTEXT_ID_RE = re.compile(r"^[0-9a-f]{24}$")


def _remove_path(path: Path, *, dry_run: bool) -> list[Path]:
    if not path.exists():
        return []
    if dry_run:
        return [path]
    secure_remove_tree(path)
    return [path]


def remove_context(context_id: str, *, dry_run: bool = False) -> list[Path]:
    """Delete isolated context directory for *context_id*."""
    if not _CONTEXT_ID_RE.fullmatch(context_id):
        msg = f"invalid context_id: {context_id!r}"
        raise UnsafePermissionError(msg)
    return _remove_path(paths.context_dir(context_id), dry_run=dry_run)


def remove_all_contexts(*, dry_run: bool = False) -> list[Path]:
    """Delete every context directory under the managed cache."""
    base = paths.context_base_dir()
    if not base.is_dir():
        return []
    removed: list[Path] = []
    for child in sorted(base.iterdir()):
        if child.is_dir():
            removed.extend(_remove_path(child, dry_run=dry_run))
    return removed


def remove_approvals(*, dry_run: bool = False) -> list[Path]:
    """Delete the approvals store file."""
    return _remove_path(paths.approvals_file(), dry_run=dry_run)
