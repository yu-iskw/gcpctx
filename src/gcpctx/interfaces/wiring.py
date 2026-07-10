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
    from gcpctx.ports import Prompter


def configure_runtime_defaults() -> None:
    """Install production adapters as process-wide service defaults.

    Call this once at application startup (CLI entry point, MCP create_server).
    Tests should call this via the conftest autouse fixture so each test gets
    a fresh set of adapters scoped to the monkeypatched tmp_path.
    """
    configure_state_store(FilesystemStateStore())
    set_audit_sink(FileAuditSink())
    configure_env_port(OsEnvPort())
    configure_gcloud_port(SubprocessGcloudPort())


def default_engine(*, interactive: bool) -> Engine:
    """Wire production adapters for CLI / MCP activation."""
    configure_runtime_defaults()
    prompter: Prompter = RichPrompter() if interactive else NullPrompter()
    return Engine(
        gcloud=SubprocessGcloudPort(),
        env=OsEnvPort(),
        audit=FileAuditSink(),
        prompter=prompter,
    )
