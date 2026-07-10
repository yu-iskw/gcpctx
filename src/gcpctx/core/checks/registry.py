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

__all__ = [
    "ACTIVATE_SHELL_REMEDIATION",
    "CHECK_EVALUATION_ORDER",
    "DOCTOR_CHECK_IDS",
    "DOCTOR_CHECK_REGISTRY",
    "STRICT_ONLY_CHECK_IDS",
    "WARN_ONLY_CHECK_IDS",
    "DoctorCheckSpec",
    "check_exit_code",
]
