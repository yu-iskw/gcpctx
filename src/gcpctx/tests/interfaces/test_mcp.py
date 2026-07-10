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
"""MCP interface tests (skipped when the optional mcp extra is absent)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from gcpctx.approvals import find_matching_approval, load_store
from gcpctx.project_context import resolve_project_context

pytest.importorskip("mcp")

# Optional extra: skip module collection when mcp is absent.
from gcpctx.interfaces.mcp import (  # pylint: disable=wrong-import-position
    create_server,
    validate_cwd,
)

if TYPE_CHECKING:
    from pathlib import Path

    from mcp.server.fastmcp import FastMCP

_EXPECTED_TOOLS = frozenset({"gcpctx_status", "gcpctx_doctor", "gcpctx_explain_plan"})


async def _call_tool(server: FastMCP, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await server.call_tool(name, arguments)
    if isinstance(result, tuple):
        _blocks, structured = result
        assert isinstance(structured, dict)
        return structured
    assert isinstance(result, dict)
    return result


def test_create_server_registers_exactly_three_tools() -> None:
    server = create_server()
    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert names == _EXPECTED_TOOLS
    for tool in tools:
        assert "gcpctx approve" in (tool.description or "")


def test_validate_cwd_rejects_outside_workspace_root(
    tmp_path: Path,
    project_tree: Path,
) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(ValueError, match="outside workspace root"):
        validate_cwd(outside, project_tree)
    assert validate_cwd(project_tree, project_tree) == project_tree.resolve()
    nested = project_tree / "src" / "app"
    assert validate_cwd(nested, project_tree) == nested.resolve()


def test_validate_cwd_rejects_non_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "not-a-dir"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="existing directory"):
        validate_cwd(file_path, None)


def test_status_tool_returns_dict(project_tree: Path) -> None:
    server = create_server(workspace_root=project_tree)
    result = asyncio.run(_call_tool(server, "gcpctx_status", {"cwd": str(project_tree)}))
    assert isinstance(result, dict)
    assert "active" in result


def test_explain_plan_denial_does_not_mutate_approvals(project_tree: Path) -> None:
    before = load_store()
    assert before.approvals == []
    server = create_server(workspace_root=project_tree)
    result = asyncio.run(
        _call_tool(server, "gcpctx_explain_plan", {"cwd": str(project_tree)}),
    )
    assert result["denied"] is True
    assert result["exit_code"] == 3
    assert result.get("remediation") == "gcpctx approve"
    assert "message" in result
    assert load_store().approvals == []
    ctx = resolve_project_context(project_tree)
    assert find_matching_approval(ctx) is None


def test_explain_plan_config_not_found(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    server = create_server(workspace_root=empty)
    result = asyncio.run(_call_tool(server, "gcpctx_explain_plan", {"cwd": str(empty)}))
    assert result["error"] == "config_not_found"
    assert result["exit_code"] == 2
