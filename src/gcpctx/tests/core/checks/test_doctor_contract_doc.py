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
"""Ensure docs/doctor-contract.md check catalog lists every registry id."""

from __future__ import annotations

from pathlib import Path

from gcpctx.core.contract import DOCTOR_CHECK_REGISTRY

_REPO_ROOT = Path(__file__).resolve().parents[5]
_CONTRACT_DOC = _REPO_ROOT / "docs" / "doctor-contract.md"


def test_doctor_contract_doc_lists_all_check_ids() -> None:
    text = _CONTRACT_DOC.read_text(encoding="utf-8")
    missing = [
        check_id
        for check_id in DOCTOR_CHECK_REGISTRY
        if f"`{check_id}`" not in text
    ]
    assert not missing, f"docs/doctor-contract.md missing check ids: {missing}"
