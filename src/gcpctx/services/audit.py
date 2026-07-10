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
"""Append-oriented security audit log."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from gcpctx import paths
from gcpctx.adapters.system import FileAuditSink

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.ports import AuditSink

_default_sink: AuditSink | None = None


def audit_file() -> Path:
    return paths.user_config_path() / "audit.jsonl"


def _get_sink() -> AuditSink:
    global _default_sink  # noqa: PLW0603
    if _default_sink is None:
        _default_sink = FileAuditSink()
    return _default_sink


def set_audit_sink(sink: AuditSink | None) -> None:
    """Override the process-wide audit sink (tests / DI)."""
    global _default_sink  # noqa: PLW0603
    _default_sink = sink


def log_event(event_type: str, **fields: Any) -> None:
    """Append a security audit event without credential material."""
    _get_sink().emit(event_type, **fields)
