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
"""Composition root: wire production adapters into services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gcpctx.adapters.gcloud import SubprocessGcloudPort
from gcpctx.adapters.state import FilesystemStateStore
from gcpctx.adapters.system import (
    FileAuditSink,
    NullPrompter,
    OsEnvPort,
    RichPrompter,
)
from gcpctx.services.approvals import configure_state_store
from gcpctx.services.audit import set_audit_sink
from gcpctx.services.doctor import configure_env_port, configure_gcloud_port
from gcpctx.services.engine import Engine

if TYPE_CHECKING:
    from gcpctx.ports import AuditSink, EnvPort, GcloudPort, Prompter, StateStore


@dataclass(frozen=True, slots=True)
class RuntimePorts:
    """Production adapters shared by Engine and service defaults."""

    gcloud: GcloudPort
    env: EnvPort
    audit: AuditSink
    state: StateStore


def configure_runtime_defaults() -> RuntimePorts:
    """Install production adapters as process-wide service defaults.

    Call this once at application startup (CLI entry point, MCP create_server).
    Tests should call this via the conftest autouse fixture so each test gets
    a fresh set of adapters scoped to the monkeypatched tmp_path.
    """
    ports = RuntimePorts(
        gcloud=SubprocessGcloudPort(),
        env=OsEnvPort(),
        audit=FileAuditSink(),
        state=FilesystemStateStore(),
    )
    configure_state_store(ports.state)
    set_audit_sink(ports.audit)
    configure_env_port(ports.env)
    configure_gcloud_port(ports.gcloud)
    return ports


def default_engine(
    *,
    interactive: bool,
    ports: RuntimePorts | None = None,
) -> Engine:
    """Wire production adapters for CLI / MCP activation."""
    runtime = ports or configure_runtime_defaults()
    prompter: Prompter = RichPrompter() if interactive else NullPrompter()
    return Engine(
        gcloud=runtime.gcloud,
        env=runtime.env,
        audit=runtime.audit,
        prompter=prompter,
    )
