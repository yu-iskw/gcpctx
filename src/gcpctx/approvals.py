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
"""First-use approval persistence and matching."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal

from rich.console import Console

from gcpctx import paths
from gcpctx.errors import ApprovalRequiredError
from gcpctx.models import ApprovalRecord, ApprovalsStore
from gcpctx.security import ensure_dir, ensure_file
from gcpctx.timeutil import utc_now_iso

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.project_context import ResolvedProjectContext

ApprovalMode = Literal["once", "remembered"]


def load_store() -> ApprovalsStore:
    """Load approvals from disk or return empty store."""
    path = paths.approvals_file()
    if not path.is_file():
        return ApprovalsStore()
    data = json.loads(path.read_text(encoding="utf-8"))
    return ApprovalsStore.model_validate(data)


def save_store(store: ApprovalsStore) -> None:
    """Persist approvals to disk."""
    ensure_dir(paths.approvals_file().parent)
    ensure_file(paths.approvals_file(), store.model_dump_json(indent=2))


def find_matching_approval(ctx: ResolvedProjectContext) -> ApprovalRecord | None:
    """Return matching approval record if one exists."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    for record in store.approvals:
        if _record_matches(record, ctx, root_str):
            return record
    return None


def add_approval(ctx: ResolvedProjectContext, *, mode: ApprovalMode) -> ApprovalRecord:
    """Add or replace approval for this binding."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    store.approvals = [r for r in store.approvals if not _record_matches(r, ctx, root_str)]
    record = ApprovalRecord(
        root=root_str,
        profile=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        config_sha256=ctx.config_sha256,
        approved_at=utc_now_iso(),
        mode=mode,
    )
    store.approvals.append(record)
    save_store(store)
    return record


def revoke_approval(ctx: ResolvedProjectContext) -> bool:
    """Remove matching approval; return True if removed."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    before = len(store.approvals)
    store.approvals = [r for r in store.approvals if not _record_matches(r, ctx, root_str)]
    if len(store.approvals) == before:
        return False
    save_store(store)
    return True


def consume_once_approval(record: ApprovalRecord) -> None:
    """Remove a once-mode approval after use."""
    if record.mode != "once":
        return
    store = load_store()
    store.approvals = [
        r
        for r in store.approvals
        if not (
            r.root == record.root
            and r.profile == record.profile
            and r.project == record.project
            and r.service_account == record.service_account
            and r.config_sha256 == record.config_sha256
        )
    ]
    save_store(store)


def prompt_for_approval(
    ctx: ResolvedProjectContext,
    *,
    cloudsdk_config: Path,
    interactive: bool,
) -> ApprovalRecord:
    """Prompt user for approval or fail closed in non-interactive mode."""
    if not interactive:
        msg = "approval required for activation (non-interactive mode)"
        raise ApprovalRequiredError(msg)

    console = Console(stderr=True)
    console.print("\n[bold]gcpctx wants to activate this Google Cloud context:[/bold]\n")
    console.print(f"Directory:        {ctx.root}")
    console.print(f"Profile:          {ctx.profile_name}")
    console.print(f"Project:          {ctx.project}")
    console.print(f"Service account:  {ctx.service_account}")
    console.print(f"CLOUDSDK_CONFIG:  {cloudsdk_config}\n")
    console.print("Approve this directory/profile/service-account binding?\n")
    console.print("[A] Approve once  [R] Remember approval  [D] Deny")

    while True:
        choice = console.input("[bold cyan]Choice[/bold cyan] (A/R/D): ").strip().upper()
        if choice == "D":
            msg = "activation denied by user"
            raise ApprovalRequiredError(msg)
        if choice in {"A", "R"}:
            mode: ApprovalMode = "once" if choice == "A" else "remembered"
            return add_approval(ctx, mode=mode)
        console.print("Invalid choice. Enter A, R, or D.")


def _record_matches(
    record: ApprovalRecord,
    ctx: ResolvedProjectContext,
    root_str: str,
) -> bool:
    return (
        record.root == root_str
        and record.profile == ctx.profile_name
        and record.project == ctx.project
        and record.service_account == ctx.service_account
        and record.config_sha256 == ctx.config_sha256
        and record.schema_version == 1
    )
