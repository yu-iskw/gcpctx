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
"""Ensure docs/doctor-contract.md check catalog lists every registry id and matches generation."""

from __future__ import annotations

from pathlib import Path

from gcpctx.core.checks.registry import generate_catalog_table_lines
from gcpctx.core.contract import DOCTOR_CHECK_REGISTRY

_REPO_ROOT = Path(__file__).resolve().parents[5]
_CONTRACT_DOC = _REPO_ROOT / "docs" / "doctor-contract.md"

_CATALOG_SECTION_MARKER = "## Check catalog\n\n"


def _extract_catalog_table(text: str) -> str:
    """Return the pipe-delimited table lines from the Check catalog section."""
    start = text.find(_CATALOG_SECTION_MARKER)
    if start == -1:
        msg = "## Check catalog section not found in docs/doctor-contract.md"
        raise AssertionError(msg)
    table_start = start + len(_CATALOG_SECTION_MARKER)
    table_lines = []
    for line in text[table_start:].splitlines():
        if line.startswith("|"):
            table_lines.append(line)
        elif table_lines:
            break
    return "\n".join(table_lines)


def test_doctor_contract_doc_lists_all_check_ids() -> None:
    text = _CONTRACT_DOC.read_text(encoding="utf-8")
    missing = [check_id for check_id in DOCTOR_CHECK_REGISTRY if f"`{check_id}`" not in text]
    assert not missing, f"docs/doctor-contract.md missing check ids: {missing}"


def test_doctor_contract_doc_catalog_table_matches_registry() -> None:
    """Snapshot test: the catalog table in the doc must match the generator output."""
    text = _CONTRACT_DOC.read_text(encoding="utf-8")
    actual = _extract_catalog_table(text)
    expected = "\n".join(generate_catalog_table_lines())
    assert actual == expected, (
        "docs/doctor-contract.md catalog table does not match registry.\n"
        "Run `uv run python dev/generate_doctor_contract_catalog.py` to regenerate.\n"
        f"--- expected (from registry) ---\n{expected}\n"
        f"--- actual (from doc) ---\n{actual}"
    )
