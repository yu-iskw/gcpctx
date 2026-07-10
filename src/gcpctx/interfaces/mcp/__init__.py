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
"""Optional read-only MCP stdio server (requires ``gcpctx[mcp]``).

Install with ``pip install 'gcpctx[mcp]'`` or ``uv sync --extra mcp``.
Approval granting is never exposed as an MCP tool — humans run ``gcpctx approve``.
"""

from __future__ import annotations

from gcpctx.interfaces.mcp.server import (
    create_server,
    resolve_workspace_root,
    run_stdio,
    summarize_plan,
    validate_cwd,
)

__all__ = [
    "create_server",
    "resolve_workspace_root",
    "run_stdio",
    "summarize_plan",
    "validate_cwd",
]
