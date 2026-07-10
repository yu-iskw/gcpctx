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
"""Strangler shim: re-exports gcpctx.services.approvals for backward compatibility."""

from gcpctx.services.approvals import (
    APPROVAL_SCHEMA_V2,
    ApprovalDoctorState,
    ApprovalMode,
    add_approval,
    approval_evidence_id,
    consume_once_approval,
    find_matching_approval,
    load_store,
    prompt_for_approval,
    resolve_approval_doctor_state,
    revoke_approval,
    save_store,
)

__all__ = [
    "APPROVAL_SCHEMA_V2",
    "ApprovalDoctorState",
    "ApprovalMode",
    "add_approval",
    "approval_evidence_id",
    "consume_once_approval",
    "find_matching_approval",
    "load_store",
    "prompt_for_approval",
    "resolve_approval_doctor_state",
    "revoke_approval",
    "save_store",
]
