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
"""Doctor check registry re-exports and strict-only ids."""

from __future__ import annotations

from gcpctx.core.contract import (
    ACTIVATE_SHELL_REMEDIATION,
    DOCTOR_CHECK_IDS,
    DOCTOR_CHECK_REGISTRY,
    DoctorCheckSpec,
    check_exit_code,
)

STRICT_ONLY_CHECK_IDS: frozenset[str] = frozenset({"state_permissions", "impersonation_iam"})
WARN_ONLY_CHECK_IDS: frozenset[str] = frozenset({"settings"})

# Stable evaluation order (dict insertion order of the contract registry).
CHECK_EVALUATION_ORDER: tuple[str, ...] = tuple(DOCTOR_CHECK_REGISTRY)

# Exit-text overrides for checks whose exit text differs from a plain integer.
_EXIT_TEXT_OVERRIDES: dict[str, str] = {
    "config": "2 or 9",
    "settings": "1 (warn-only; does not fail non-interactive doctor)",
}

_CATALOG_HEADERS: tuple[str, str, str] = ("Check id", "Exit when failing", "Strict only")


def generate_catalog_table_lines() -> list[str]:
    """Build the Check catalog Markdown table rows from DOCTOR_CHECK_REGISTRY.

    Matches the table format in docs/doctor-contract.md (left-aligned columns,
    column widths derived from the widest cell in each column).
    """
    rows: list[tuple[str, str, str]] = []
    for check_id, spec in DOCTOR_CHECK_REGISTRY.items():
        exit_text = _EXIT_TEXT_OVERRIDES.get(check_id, str(spec.exit_code.value))
        strict_text = "yes" if check_id in STRICT_ONLY_CHECK_IDS else "no"
        rows.append((f"`{check_id}`", exit_text, strict_text))

    col_widths = [len(h) for h in _CATALOG_HEADERS]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def _fmt(cells: tuple[str, ...]) -> str:
        parts = [f" {cell:<{col_widths[i]}} " for i, cell in enumerate(cells)]
        return "|" + "|".join(parts) + "|"

    sep = "|" + "|".join(" " + ("-" * w) + " " for w in col_widths) + "|"
    lines: list[str] = [_fmt(_CATALOG_HEADERS), sep]
    lines.extend(_fmt(row) for row in rows)
    return lines


__all__ = [
    "ACTIVATE_SHELL_REMEDIATION",
    "CHECK_EVALUATION_ORDER",
    "DOCTOR_CHECK_IDS",
    "DOCTOR_CHECK_REGISTRY",
    "STRICT_ONLY_CHECK_IDS",
    "WARN_ONLY_CHECK_IDS",
    "DoctorCheckSpec",
    "check_exit_code",
    "generate_catalog_table_lines",
]
