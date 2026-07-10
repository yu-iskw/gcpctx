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
"""Pure doctor checks: Snapshot -> Finding (no I/O)."""

from __future__ import annotations

from gcpctx.core.checks.evaluators import evaluate_all
from gcpctx.core.checks.report import findings_to_result
from gcpctx.core.checks.snapshot import ApprovalFacts, DoctorSnapshot, Finding

__all__ = [
    "ApprovalFacts",
    "DoctorSnapshot",
    "Finding",
    "evaluate_all",
    "findings_to_result",
]
