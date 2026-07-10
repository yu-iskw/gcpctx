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
"""Typed ports (Protocols) for I/O boundaries.

Adapters implement these; services depend on the protocols, not concrete I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping
    from contextlib import AbstractContextManager
    from datetime import datetime
    from pathlib import Path

    from gcpctx.gcloud import InitContext
    from gcpctx.gcloud_trust import GcloudTrustResult
    from gcpctx.models import ActivationResult, ContextState
    from gcpctx.policy import SecurityPolicy

ApprovalDecision = Literal["once", "remembered", "deny"]


@dataclass(frozen=True)
class ApprovalRequest:
    """Display inputs for an interactive approval prompt."""

    root: Path
    profile: str
    project: str
    service_account: str
    config_sha256: str
    cloudsdk_config: Path
    quota_project: str | None = None
    env_keys: tuple[str, ...] = ()
    gcloud_path: str | None = None
    gcloud_sha256: str | None = None
    approval_ttl_days: int | None = None
    git_remote: str | None = None
    git_branch: str | None = None
    sa_project_mismatch: str | None = None


@dataclass(frozen=True)
class ApprovalAnswer:
    """User (or fake) response to an approval prompt."""

    decision: ApprovalDecision


@runtime_checkable
class GcloudPort(Protocol):
    """Google Cloud SDK subprocess and trust boundary."""

    def resolve_binary(
        self,
        cwd: Path,
        *,
        policy: SecurityPolicy | None = None,
        configured_path: str | None = None,
        strict: bool | None = None,
    ) -> GcloudTrustResult:
        pass

    def get_property(
        self,
        cloudsdk_config: Path,
        section_property: str,
        *,
        gcloud_executable: str | None = None,
    ) -> str | None:
        pass

    def set_property(
        self,
        cloudsdk_config: Path,
        section_property: str,
        value: str,
        *,
        gcloud_executable: str | None = None,
    ) -> None:
        pass

    def adc_login_impersonated(
        self,
        cloudsdk_config: Path,
        service_account: str,
        *,
        quota_project: str | None = None,
        gcloud_executable: str | None = None,
    ) -> None:
        pass

    def adc_exists(self, cloudsdk_config: Path) -> bool:
        pass

    def ensure_initialized(self, init_context: InitContext) -> ContextState:
        pass

    def probe_impersonation(
        self,
        cloudsdk_config: Path,
        service_account: str,
        *,
        gcloud_executable: str | None = None,
    ) -> bool:
        pass


@runtime_checkable
class StateStore(Protocol):
    """Single writer for managed gcpctx state files."""

    def read(self, key: str) -> bytes | None:
        pass

    def write(self, key: str, data: bytes) -> None:
        pass

    def delete(self, key: str) -> None:
        pass

    def lock(self, key: str) -> AbstractContextManager[None]:
        pass


@runtime_checkable
class EnvPort(Protocol):
    """Read-only process environment access."""

    def get(self, name: str) -> str | None:
        pass

    def snapshot(self) -> Mapping[str, str]:
        pass


@runtime_checkable
class Clock(Protocol):
    """Time source (UTC)."""

    def now(self) -> datetime:
        pass


@runtime_checkable
class Prompter(Protocol):
    """Interactive approval UI; only path that can grant consent."""

    def confirm(self, request: ApprovalRequest) -> ApprovalAnswer:
        pass


@runtime_checkable
class AuditSink(Protocol):
    """Structured security audit events."""

    def emit(self, event: str, **fields: object) -> None:
        pass


@runtime_checkable
class ShellRenderer(Protocol):
    """Render activation/deactivation as shell code."""

    def render(self, result: ActivationResult, shell: str) -> str:
        pass


__all__ = [
    "ApprovalAnswer",
    "ApprovalDecision",
    "ApprovalRequest",
    "AuditSink",
    "Clock",
    "EnvPort",
    "GcloudPort",
    "Prompter",
    "ShellRenderer",
    "StateStore",
]
