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
"""Exit code contract tests."""

from __future__ import annotations

import pytest

from gcpctx.doctor_checks import DOCTOR_CHECK_IDS, DOCTOR_CHECK_REGISTRY, check_exit_code
from gcpctx.errors import (
    ApprovalRequiredError,
    ConfigNotFoundError,
    ConfigValidationError,
    CredentialConflictError,
    GcloudTrustError,
    GcpctxError,
    PolicyViolationError,
    SettingsViolationError,
    UnsafePermissionError,
    UnsupportedPlatformError,
)
from gcpctx.exit_codes import ExitCode


@pytest.mark.parametrize(
    ("exc_type", "expected"),
    [
        (ConfigNotFoundError, ExitCode.CONFIG_NOT_FOUND),
        (ConfigValidationError, ExitCode.CONFIG_SCHEMA_ERROR),
        (ApprovalRequiredError, ExitCode.APPROVAL_REQUIRED),
        (UnsafePermissionError, ExitCode.UNSAFE_FILESYSTEM),
        (GcloudTrustError, ExitCode.GCLOUD_TRUST_FAILURE),
        (CredentialConflictError, ExitCode.POLICY_VIOLATION),
        (PolicyViolationError, ExitCode.POLICY_VIOLATION),
        (SettingsViolationError, ExitCode.CONFIG_SCHEMA_ERROR),
        (UnsupportedPlatformError, ExitCode.UNSUPPORTED_PLATFORM),
    ],
)
def test_exception_exit_codes(exc_type: type[GcpctxError], expected: ExitCode) -> None:
    assert exc_type("test").exit_code == int(expected)


def test_doctor_registry_covers_all_check_ids() -> None:
    assert DOCTOR_CHECK_REGISTRY.keys() == DOCTOR_CHECK_IDS


def test_doctor_check_exit_codes_are_mapped() -> None:
    warn_only_ids = frozenset({"settings"})
    for check_id in DOCTOR_CHECK_IDS:
        code = check_exit_code(check_id)
        if check_id in warn_only_ids:
            continue
        assert code != ExitCode.GENERIC_ERROR, check_id
