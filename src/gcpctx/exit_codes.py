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
"""Stable process exit codes for gcpctx v0.3+."""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Canonical exit codes for gcpctx CLI and doctor."""

    OK = 0
    GENERIC_ERROR = 1
    CONFIG_NOT_FOUND = 2
    APPROVAL_REQUIRED = 3
    POLICY_VIOLATION = 4
    UNSAFE_FILESYSTEM = 5
    GCLOUD_TRUST_FAILURE = 6
    ADC_NOT_INITIALIZED = 7
    IAM_IMPERSONATION_FAILURE = 8
    CONFIG_SCHEMA_ERROR = 9
    UNSUPPORTED_PLATFORM = 10
