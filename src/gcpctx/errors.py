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
"""Typed exceptions for gcpctx."""

from __future__ import annotations


class GcpctxError(Exception):
    """Base exception for gcpctx errors."""

    exit_code: int = 1


class ConfigNotFoundError(GcpctxError):
    """Raised when .gcpctx.toml cannot be found."""

    exit_code = 2


class ConfigValidationError(GcpctxError):
    """Raised when .gcpctx.toml fails validation."""

    exit_code = 2


class ApprovalRequiredError(GcpctxError):
    """Raised when activation requires approval that is missing."""

    exit_code = 3


class UnsafePermissionError(GcpctxError):
    """Raised when config or state files have unsafe permissions."""

    exit_code = 4


class GcloudNotFoundError(GcpctxError):
    """Raised when gcloud is not available on PATH."""

    exit_code = 5


class GcloudCommandError(GcpctxError):
    """Raised when a gcloud subprocess fails."""

    exit_code = 5


class CredentialConflictError(GcpctxError):
    """Raised when GOOGLE_APPLICATION_CREDENTIALS conflicts with activation."""

    exit_code = 6


class UnsupportedPlatformError(GcpctxError):
    """Raised when gcpctx is run on an unsupported platform."""

    exit_code = 8


class PolicyViolationError(GcpctxError):
    """Raised when an operation violates the active security policy."""

    exit_code = 7


class GcloudTrustError(GcpctxError):
    """Raised when the gcloud binary fails trust validation."""

    exit_code = 5
