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
"""In-memory fakes for every port (unit tests without I/O)."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from gcpctx.errors import ApprovalRequiredError
from gcpctx.gcloud_trust import GcloudTrustResult
from gcpctx.ports import ApprovalAnswer, ApprovalRequest

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence
    from pathlib import Path

    from gcpctx.gcloud import InitContext
    from gcpctx.models import ActivationResult, ContextState
    from gcpctx.policy import SecurityPolicy
    from gcpctx.ports import ApprovalDecision


class FakeStateStore:
    """Dict-backed StateStore."""

    def __init__(self, initial: Mapping[str, bytes] | None = None) -> None:
        self.data: dict[str, bytes] = dict(initial or {})
        self.locks_held: list[str] = []

    def read(self, key: str) -> bytes | None:
        return self.data.get(key)

    def write(self, key: str, data: bytes) -> None:
        self.data[key] = data

    def delete(self, key: str) -> None:
        self.data.pop(key, None)

    @contextmanager
    def lock(self, key: str) -> Iterator[None]:
        self.locks_held.append(key)
        yield


class FakeEnv:
    """Mutable mapping used as a read-only EnvPort."""

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values: dict[str, str] = dict(values or {})

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def snapshot(self) -> Mapping[str, str]:
        return dict(self._values)

    def set(self, name: str, value: str) -> None:
        """Test helper — not part of EnvPort."""
        self._values[name] = value


class FakeClock:
    """Fixed / steppable UTC clock."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, **delta: float) -> datetime:
        """Advance the clock by timedelta kwargs (days, seconds, …)."""
        self._now = self._now + timedelta(**delta)
        return self._now

    def set(self, when: datetime) -> None:
        self._now = when if when.tzinfo else when.replace(tzinfo=UTC)


class FakePrompter:
    """Scripted approval answers; raises when the script is exhausted."""

    def __init__(
        self, answers: Sequence[ApprovalAnswer | ApprovalDecision] | None = None
    ) -> None:
        self._answers: list[ApprovalAnswer] = []
        for item in answers or []:
            if isinstance(item, ApprovalAnswer):
                self._answers.append(item)
            else:
                self._answers.append(ApprovalAnswer(decision=item))
        self.requests: list[ApprovalRequest] = []

    def confirm(self, request: ApprovalRequest) -> ApprovalAnswer:
        self.requests.append(request)
        if not self._answers:
            msg = "FakePrompter has no scripted answers left"
            raise ApprovalRequiredError(msg)
        return self._answers.pop(0)


class FakeAuditSink:
    """Collects audit events in memory."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event: str, **fields: object) -> None:
        self.events.append({"event": event, **fields})


@dataclass
class FakeGcloudPort:
    """In-memory gcloud properties and scripted probe / trust results."""

    binary: GcloudTrustResult = field(
        default_factory=lambda: GcloudTrustResult(path="/usr/bin/gcloud", sha256="a" * 64)
    )
    properties: dict[str, dict[str, str]] = field(default_factory=dict)
    adc_configs: set[str] = field(default_factory=set)
    probe_results: dict[str, bool] = field(default_factory=dict)
    default_probe: bool = True
    init_states: dict[str, ContextState] = field(default_factory=dict)
    login_calls: list[tuple[str, str]] = field(default_factory=list)

    def resolve_binary(
        self,
        cwd: Path,
        *,
        policy: SecurityPolicy | None = None,
        configured_path: str | None = None,
    ) -> GcloudTrustResult:
        del cwd, policy, configured_path
        return self.binary

    def get_property(
        self,
        cloudsdk_config: Path,
        section_property: str,
        *,
        gcloud_executable: str | None = None,
    ) -> str | None:
        del gcloud_executable
        return self.properties.get(str(cloudsdk_config), {}).get(section_property)

    def set_property(
        self,
        cloudsdk_config: Path,
        section_property: str,
        value: str,
        *,
        gcloud_executable: str | None = None,
    ) -> None:
        del gcloud_executable
        bucket = self.properties.setdefault(str(cloudsdk_config), {})
        bucket[section_property] = value

    def adc_login_impersonated(
        self,
        cloudsdk_config: Path,
        service_account: str,
        *,
        quota_project: str | None = None,
        gcloud_executable: str | None = None,
    ) -> None:
        del quota_project, gcloud_executable
        key = str(cloudsdk_config)
        self.adc_configs.add(key)
        self.login_calls.append((key, service_account))

    def adc_exists(self, cloudsdk_config: Path) -> bool:
        return str(cloudsdk_config) in self.adc_configs

    def ensure_initialized(self, init_context: InitContext) -> ContextState:
        state = self.init_states.get(init_context.context_id)
        if state is not None:
            return state
        msg = f"FakeGcloudPort: no init state for {init_context.context_id}"
        raise KeyError(msg)

    def probe_impersonation(
        self,
        cloudsdk_config: Path,
        service_account: str,
        *,
        gcloud_executable: str | None = None,
    ) -> bool:
        del gcloud_executable
        key = f"{cloudsdk_config}:{service_account}"
        return self.probe_results.get(key, self.default_probe)


class FakeShellRenderer:
    """Records render calls; returns a deterministic stub string."""

    def __init__(self) -> None:
        self.calls: list[tuple[ActivationResult, str]] = []

    def render(self, result: ActivationResult, shell: str) -> str:
        self.calls.append((result, shell))
        return f"# fake-shell:{shell}:active={result.active}"


__all__ = [
    "FakeAuditSink",
    "FakeClock",
    "FakeEnv",
    "FakeGcloudPort",
    "FakePrompter",
    "FakeShellRenderer",
    "FakeStateStore",
]
