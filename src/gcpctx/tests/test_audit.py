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
"""Audit log tests."""

from __future__ import annotations

import importlib

import pytest

import gcpctx.audit as audit_mod
from gcpctx import paths


def test_log_event_chmods_existing_world_readable_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importlib.reload(audit_mod)
    config = paths.user_config_path()
    audit_path = config / "audit.jsonl"
    monkeypatch.setattr(audit_mod, "audit_file", lambda: audit_path)

    audit_path.write_text('{"existing":true}\n', encoding="utf-8")
    audit_path.chmod(0o644)

    audit_mod.log_event("test_event", detail="value")

    assert audit_path.stat().st_mode & 0o777 == 0o600
    content = audit_path.read_text(encoding="utf-8")
    assert "test_event" in content
