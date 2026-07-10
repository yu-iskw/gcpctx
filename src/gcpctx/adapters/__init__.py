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
"""I/O adapters implementing ports (filesystem, gcloud, system, shell)."""

from __future__ import annotations

from gcpctx.adapters.gcloud import SubprocessGcloudPort
from gcpctx.adapters.shell.renderer import SharedShellRenderer
from gcpctx.adapters.state import FilesystemStateStore
from gcpctx.adapters.system import (
    FileAuditSink,
    NullPrompter,
    OsEnvPort,
    RichPrompter,
    SystemClock,
)

__all__ = [
    "FileAuditSink",
    "FilesystemStateStore",
    "NullPrompter",
    "OsEnvPort",
    "RichPrompter",
    "SharedShellRenderer",
    "SubprocessGcloudPort",
    "SystemClock",
]
