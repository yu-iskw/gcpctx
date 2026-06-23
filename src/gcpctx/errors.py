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

from gcpctx.exit_codes import ExitCode


class GcpctxError(Exception):
    """Base exception for gcpctx errors."""

    exit_code: int = ExitCode.GENERIC_ERROR


class ConfigNotFoundError(GcpctxError):
    """Raised when .gcpctx.toml cannot be found."""

    exit_code = ExitCode.CONFIG_NOT_FOUND


class ConfigValidationError(GcpctxError):
    """Raised when .gcpctx.toml fails validation."""

    exit_code = ExitCode.CONFIG_SCHEMA_ERROR


class ApprovalRequiredError(GcpctxError):
    """Raised when activation requires approval that is missing."""

    exit_code = ExitCode.APPROVAL_REQUIRED


class UnsafePermissionError(GcpctxError):
    """Raised when config or state files have unsafe permissions."""

    exit_code = ExitCode.UNSAFE_FILESYSTEM


class GcloudNotFoundError(GcpctxError):
    """Raised when gcloud is not available on PATH."""

    exit_code = ExitCode.GCLOUD_TRUST_FAILURE


class GcloudCommandError(GcpctxError):
    """Raised when a gcloud subprocess fails."""

    exit_code = ExitCode.GCLOUD_TRUST_FAILURE


class CredentialConflictError(GcpctxError):
    """Raised when GOOGLE_APPLICATION_CREDENTIALS conflicts with activation."""

    exit_code = ExitCode.POLICY_VIOLATION


class UnsupportedPlatformError(GcpctxError):
    """Raised when gcpctx is run on an unsupported platform."""

    exit_code = ExitCode.UNSUPPORTED_PLATFORM


class PolicyViolationError(GcpctxError):
    """Raised when an operation violates the active security policy."""

    exit_code = ExitCode.POLICY_VIOLATION


class SettingsViolationError(GcpctxError):
    """Raised when user settings.toml fails validation."""

    exit_code = ExitCode.CONFIG_SCHEMA_ERROR


class GcloudTrustError(GcpctxError):
    """Raised when the gcloud binary fails trust validation."""

    exit_code = ExitCode.GCLOUD_TRUST_FAILURE
