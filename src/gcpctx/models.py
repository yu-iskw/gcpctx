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
"""Pydantic models for gcpctx configuration and activation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class ProfileConfig(BaseModel):
    """A single gcpctx profile."""

    project: str
    service_account: str
    quota_project: str | None = None
    region: str | None = None
    zone: str | None = None
    env: dict[str, str] = Field(default_factory=dict)


class GcpctxConfig(BaseModel):
    """Root .gcpctx.toml configuration."""

    version: Literal[1]
    default_profile: str
    profiles: dict[str, ProfileConfig]


class ActivationRequest(BaseModel):
    """Request to activate a gcpctx profile."""

    cwd: Path
    profile: str | None = None
    shell_name: Literal["bash", "zsh"]
    interactive: bool = True
    hook_mode: bool = False
    allow_google_application_credentials: bool = False
    skip_gcloud_init: bool = False
    force_refresh: bool = False


class ActivationResult(BaseModel):
    """Result of activation or deactivation."""

    active: bool
    noop: bool = False
    root: Path | None = None
    profile: str | None = None
    project: str | None = None
    service_account: str | None = None
    cloudsdk_config: Path | None = None
    context_id: str | None = None
    exports: dict[str, str] = Field(default_factory=dict)
    unsets: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ApprovalRecord(BaseModel):
    """A stored approval for a directory/profile binding."""

    root: str
    profile: str
    project: str
    service_account: str
    config_sha256: str
    approved_at: str
    mode: Literal["once", "remembered"]
    schema_version: int = 1


class ApprovalsStore(BaseModel):
    """Persisted approvals file."""

    version: int = 1
    approvals: list[ApprovalRecord] = Field(default_factory=list)


class ContextState(BaseModel):
    """Per-context initialization state."""

    version: int = 1
    root: str
    profile: str
    project: str
    service_account: str
    quota_project: str | None = None
    config_sha256: str
    last_checked_at: str
    last_initialized_at: str


class DoctorCheck(BaseModel):
    """A single doctor diagnostic check."""

    name: str
    status: Literal["ok", "warning", "error"]
    message: str
    remediation: str | None = None


class DoctorResult(BaseModel):
    """Aggregated doctor output."""

    checks: list[DoctorCheck] = Field(default_factory=list)
    exit_code: int = 0


# Postponed annotations (PEP 563) require rebuild before runtime Path validation.
ActivationRequest.model_rebuild()
ActivationResult.model_rebuild()
