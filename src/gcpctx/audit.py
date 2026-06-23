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
"""Append-only security audit log."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from gcpctx import paths
from gcpctx.security import ensure_dir, file_lock, reject_symlink
from gcpctx.timeutil import utc_now_iso

if TYPE_CHECKING:
    from pathlib import Path

FILE_MODE = 0o600


def audit_file() -> Path:
    return paths.user_config_path() / "audit.jsonl"


def log_event(event_type: str, **fields: Any) -> None:
    """Append a security audit event without credential material."""
    path = audit_file()
    ensure_dir(path.parent)
    record = {"ts": utc_now_iso(), "event": event_type, **fields}
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with file_lock(path):
        reject_symlink(path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, FILE_MODE)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            os.close(fd)
            raise
