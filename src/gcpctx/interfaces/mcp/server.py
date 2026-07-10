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
"""Read-only gcpctx MCP server (stdio transport only).

Workspace binding: pass ``workspace_root`` to :func:`create_server` / :func:`run_stdio`,
or set ``GCPCTX_MCP_ROOT``. Dynamic MCP ``roots`` negotiation is not wired yet; the CLI
``gcpctx mcp --cwd`` flag sets the same bound root.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import FastMCP

from gcpctx.errors import ConfigNotFoundError
from gcpctx.interfaces.wiring import default_engine
from gcpctx.models import ActivationRequest
from gcpctx.services.doctor import run_doctor, status_info

if TYPE_CHECKING:
    from gcpctx.core.plan import Plan

_HUMAN_APPROVAL_NOTE = "Approval cannot be granted via MCP; a human must run `gcpctx approve`."

_STATUS_DESC = (
    "Return gcpctx activation status for a directory (posture metadata only; "
    f"no credentials or tokens). Read-only. {_HUMAN_APPROVAL_NOTE}"
)
_DOCTOR_DESC = (
    "Run gcpctx doctor diagnostics (JSON-safe fields only; no credentials). "
    f"Read-only. {_HUMAN_APPROVAL_NOTE}"
)
_EXPLAIN_DESC = (
    "Dry-run activation plan (steps or denial + remediation). Does not mutate "
    f"approvals or initialize credentials. {_HUMAN_APPROVAL_NOTE}"
)


def resolve_workspace_root(explicit: Path | None = None) -> Path | None:
    """Resolve optional workspace root from constructor arg or ``GCPCTX_MCP_ROOT``."""
    if explicit is not None:
        return explicit.expanduser().resolve()
    env = os.environ.get("GCPCTX_MCP_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    return None


def validate_cwd(cwd: str | Path | None, root: Path | None) -> Path:
    """Resolve ``cwd`` to an existing directory; refuse paths outside ``root``."""
    path = Path(cwd).expanduser().resolve() if cwd is not None else Path.cwd().resolve()
    if not path.is_dir():
        msg = f"cwd must be an existing directory: {path}"
        raise ValueError(msg)
    if root is not None:
        bound = root.expanduser().resolve()
        if not path.is_relative_to(bound):
            msg = f"cwd {path} is outside workspace root {bound}"
            raise ValueError(msg)
    return path


def summarize_plan(plan: Plan) -> dict[str, Any]:
    """Serialize a plan for MCP: denial fields or step types + export keys only."""
    if plan.denial is not None:
        return {
            "denied": True,
            "message": plan.denial.message,
            "exit_code": plan.denial.exit_code,
            "remediation": plan.denial.remediation,
        }
    return {
        "denied": False,
        "steps": [type(step).__name__ for step in plan.steps],
        "env_delta_export_keys": sorted(plan.env_delta.exports),
        "readiness": plan.readiness,
    }


def _status_payload(work: Path) -> dict[str, str]:
    return status_info(work)


def _doctor_payload(work: Path, *, strict: bool) -> dict[str, Any]:
    result = run_doctor(work, profile=None, strict=strict, interactive=False)
    return result.model_dump()


def _explain_plan_payload(work: Path, *, profile: str | None) -> dict[str, Any]:
    engine = default_engine(interactive=False)
    try:
        plan = engine.explain_plan(
            ActivationRequest(
                cwd=work,
                shell_name="zsh",
                profile=profile,
                interactive=False,
            )
        )
    except ConfigNotFoundError as exc:
        return {
            "error": "config_not_found",
            "message": str(exc),
            "exit_code": int(exc.exit_code),
        }
    return summarize_plan(plan)


def create_server(*, workspace_root: Path | None = None) -> FastMCP:
    """Build a FastMCP server with three read-only gcpctx tools."""
    bound = resolve_workspace_root(workspace_root)
    mcp = FastMCP(
        "gcpctx",
        instructions=(
            "Read-only gcpctx diagnostics. Never approve or activate via MCP. "
            "Ask a human to run `gcpctx approve` when a plan is denied."
        ),
    )

    @mcp.tool(name="gcpctx_status", description=_STATUS_DESC)
    def gcpctx_status(cwd: str | None = None) -> dict[str, str]:
        return _status_payload(validate_cwd(cwd, bound))

    @mcp.tool(name="gcpctx_doctor", description=_DOCTOR_DESC)
    def gcpctx_doctor(
        cwd: str | None = None,
        strict: bool = False,
    ) -> dict[str, Any]:
        return _doctor_payload(validate_cwd(cwd, bound), strict=strict)

    @mcp.tool(name="gcpctx_explain_plan", description=_EXPLAIN_DESC)
    def gcpctx_explain_plan(
        cwd: str | None = None,
        profile: str | None = None,
    ) -> dict[str, Any]:
        return _explain_plan_payload(validate_cwd(cwd, bound), profile=profile)

    return mcp


def run_stdio(*, workspace_root: Path | None = None) -> None:
    """Run the read-only MCP server on stdio (never HTTP)."""
    server = create_server(workspace_root=workspace_root)
    server.run(transport="stdio")


__all__ = [
    "create_server",
    "resolve_workspace_root",
    "run_stdio",
    "summarize_plan",
    "validate_cwd",
]
