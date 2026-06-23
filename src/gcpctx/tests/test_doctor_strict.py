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
"""Doctor strict-mode tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.approvals import add_approval
from gcpctx.doctor import run_doctor
from gcpctx.project_context import resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.usefixtures("fake_gcloud")
def test_doctor_strict_without_policy_file(
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = resolve_project_context(project_tree)
    add_approval(ctx, mode="remembered")
    isolated = ctx.expected_cloudsdk_config()
    isolated.mkdir(parents=True)
    (isolated / "application_default_credentials.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLOUDSDK_CONFIG", str(isolated))

    result = run_doctor(project_tree, interactive=False, strict=True)

    policy_check = next(c for c in result.checks if c.name == "policy")
    assert policy_check.status == "ok"
    assert "gcloud_trust" in {check.name for check in result.checks}
