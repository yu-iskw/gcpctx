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
from gcpctx.adapters.system import (
    FileAuditSink,
    NullPrompter,
    OsEnvPort,
    RichPrompter,
    SystemClock,
)
from gcpctx.services.engine import Engine

if TYPE_CHECKING:
    from gcpctx.ports import Prompter


def default_engine(*, interactive: bool) -> Engine:
    """Wire production adapters for CLI / MCP activation."""
    prompter: Prompter = RichPrompter() if interactive else NullPrompter()
    return Engine(
        gcloud=SubprocessGcloudPort(),
        env=OsEnvPort(),
        audit=FileAuditSink(),
        clock=SystemClock(),
        prompter=prompter,
    )
