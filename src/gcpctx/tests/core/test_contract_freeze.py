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
"""Contract freeze snapshots for ExitCode and doctor check registry."""

from __future__ import annotations

from gcpctx.core.contract import (
    DOCTOR_CHECK_IDS,
    DOCTOR_CHECK_REGISTRY,
    DOCTOR_JSON_VERSION,
    GCPCTX_ACTIVE,
    GCPCTX_CONTEXT_ID,
    GCPCTX_PROFILE,
    GCPCTX_PROJECT,
    GCPCTX_ROOT,
    GCPCTX_SERVICE_ACCOUNT,
    STATUS_JSON_VERSION,
    ExitCode,
    check_exit_code,
)

# Frozen v0.3+ exit code table — changing requires a deliberate, reviewed diff.
_EXIT_CODE_SNAPSHOT: dict[str, int] = {
    "OK": 0,
    "GENERIC_ERROR": 1,
    "CONFIG_NOT_FOUND": 2,
    "APPROVAL_REQUIRED": 3,
    "POLICY_VIOLATION": 4,
    "UNSAFE_FILESYSTEM": 5,
    "GCLOUD_TRUST_FAILURE": 6,
    "ADC_NOT_INITIALIZED": 7,
    "IAM_IMPERSONATION_FAILURE": 8,
    "CONFIG_SCHEMA_ERROR": 9,
    "UNSUPPORTED_PLATFORM": 10,
}

# Frozen doctor check id -> exit code mapping.
_DOCTOR_EXIT_CODE_SNAPSHOT: dict[str, int] = {
    "config": 2,
    "profile": 2,
    "policy": 4,
    "settings": 1,
    "gcloud_trust": 6,
    "approval": 3,
    "approval_expiry": 3,
    "expected_context": 2,
    "ambient_cloudsdk": 2,
    "env_project": 2,
    "gcloud_project": 6,
    "impersonation": 6,
    "adc": 7,
    "gac": 4,
    "state_permissions": 5,
    "impersonation_iam": 8,
}


def test_exit_code_values_frozen() -> None:
    assert {member.name: int(member) for member in ExitCode} == _EXIT_CODE_SNAPSHOT


def test_doctor_check_ids_frozen() -> None:
    assert DOCTOR_CHECK_IDS == frozenset(_DOCTOR_EXIT_CODE_SNAPSHOT)


def test_doctor_check_exit_codes_frozen() -> None:
    actual = {check_id: int(spec.exit_code) for check_id, spec in DOCTOR_CHECK_REGISTRY.items()}
    assert actual == _DOCTOR_EXIT_CODE_SNAPSHOT
    for check_id, expected in _DOCTOR_EXIT_CODE_SNAPSHOT.items():
        assert int(check_exit_code(check_id)) == expected


def test_json_schema_versions_frozen() -> None:
    assert STATUS_JSON_VERSION == "status.v1"
    assert DOCTOR_JSON_VERSION == "doctor.v1"


def test_gcpctx_env_names_frozen() -> None:
    assert GCPCTX_ACTIVE == "GCPCTX_ACTIVE"
    assert GCPCTX_ROOT == "GCPCTX_ROOT"
    assert GCPCTX_PROFILE == "GCPCTX_PROFILE"
    assert GCPCTX_PROJECT == "GCPCTX_PROJECT"
    assert GCPCTX_SERVICE_ACCOUNT == "GCPCTX_SERVICE_ACCOUNT"
    assert GCPCTX_CONTEXT_ID == "GCPCTX_CONTEXT_ID"
