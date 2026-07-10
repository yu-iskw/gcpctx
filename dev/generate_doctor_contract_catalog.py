#!/usr/bin/env python3
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
"""Generate the Check catalog table for docs/doctor-contract.md.

Run with:
    uv run python dev/generate_doctor_contract_catalog.py

Prints the Markdown table rows to stdout. Redirect to update the doc section:
    uv run python dev/generate_doctor_contract_catalog.py > /tmp/catalog.md
"""

from __future__ import annotations

from gcpctx.core.checks.registry import generate_catalog_table_lines


def main() -> None:
    lines = generate_catalog_table_lines()
    print("\n".join(lines))


if __name__ == "__main__":
    main()
