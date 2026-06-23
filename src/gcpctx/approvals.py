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

import hashlib
import json
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from rich.console import Console

from gcpctx import audit, paths
from gcpctx.config import service_account_project
from gcpctx.errors import ApprovalRequiredError
from gcpctx.models import ApprovalRecord, ApprovalsStore
from gcpctx.policy import SecurityPolicy, load_policy
from gcpctx.security import ensure_dir, ensure_managed_file, file_lock, secure_read_text
from gcpctx.timeutil import utc_now_iso

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.gcloud_trust import GcloudTrustResult
    from gcpctx.project_context import ResolvedProjectContext

ApprovalMode = Literal["once", "remembered"]
APPROVAL_SCHEMA_V2 = 2


def load_store() -> ApprovalsStore:
    """Load approvals from disk or return empty store."""
    path = paths.approvals_file()
    if not path.is_file():
        return ApprovalsStore()
    with file_lock(path):
        data = json.loads(secure_read_text(path))
    return ApprovalsStore.model_validate(data)


def save_store(store: ApprovalsStore) -> None:
    """Persist approvals to disk."""
    path = paths.approvals_file()
    ensure_dir(path.parent)
    with file_lock(path):
        ensure_managed_file(path, store.model_dump_json(indent=2))


def find_matching_approval(
    ctx: ResolvedProjectContext,
    *,
    policy: SecurityPolicy | None = None,
    gcloud_trust: GcloudTrustResult | None = None,
) -> ApprovalRecord | None:
    """Return matching approval record if one exists."""
    active_policy = policy or load_policy()
    store = load_store()
    root_str = str(ctx.root.resolve())
    for record in store.approvals:
        if not _record_matches(record, ctx, root_str, active_policy, gcloud_trust):
            continue
        if _is_expired(record):
            continue
        return record
    return None


def find_identity_approval(ctx: ResolvedProjectContext) -> ApprovalRecord | None:
    """Return the newest identity-matching approval regardless of expiry or gcloud binding."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    matches = [r for r in store.approvals if _identity_matches(r, ctx, root_str)]
    if not matches:
        return None
    return max(matches, key=lambda record: record.approved_at)


def find_expired_remembered_approval(ctx: ResolvedProjectContext) -> ApprovalRecord | None:
    """Return a remembered approval that matches identity but has expired."""
    record = find_identity_approval(ctx)
    if record is None or record.mode != "remembered":
        return None
    if not _is_expired(record):
        return None
    return record


@dataclass(frozen=True, slots=True)
class ApprovalDoctorState:
    """Approval facts for doctor checks from a single store read."""

    matching: ApprovalRecord | None
    identity: ApprovalRecord | None
    expired_remembered: ApprovalRecord | None


def resolve_approval_doctor_state(
    ctx: ResolvedProjectContext,
    *,
    policy: SecurityPolicy,
    gcloud_trust: GcloudTrustResult | None,
) -> ApprovalDoctorState:
    """Load approval state once for doctor approval and approval_expiry checks."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    identity_matches = [r for r in store.approvals if _identity_matches(r, ctx, root_str)]
    identity = (
        max(identity_matches, key=lambda record: record.approved_at) if identity_matches else None
    )
    matching: ApprovalRecord | None = None
    for record in store.approvals:
        if not _record_matches(record, ctx, root_str, policy, gcloud_trust):
            continue
        if _is_expired(record):
            continue
        matching = record
        break
    expired_remembered: ApprovalRecord | None = None
    if identity is not None and identity.mode == "remembered" and _is_expired(identity):
        expired_remembered = identity
    return ApprovalDoctorState(
        matching=matching,
        identity=identity,
        expired_remembered=expired_remembered,
    )


def approval_evidence_id(record: ApprovalRecord) -> str:
    """Return a stable, non-secret identifier for an approval record."""
    digest = hashlib.sha256(
        f"{record.root}:{record.profile}:{record.approved_at}".encode()
    ).hexdigest()
    return f"sha256:{digest[:16]}"


def add_approval(
    ctx: ResolvedProjectContext,
    *,
    mode: ApprovalMode,
    policy: SecurityPolicy | None = None,
    gcloud_trust: GcloudTrustResult | None = None,
) -> ApprovalRecord:
    """Add or replace approval for this binding."""
    active_policy = policy or load_policy()
    store = load_store()
    root_str = str(ctx.root.resolve())
    store.approvals = [r for r in store.approvals if not _identity_matches(r, ctx, root_str)]
    expires_at = None
    if mode == "remembered":
        expires_at = (
            datetime.now(tz=UTC) + timedelta(days=active_policy.approval_ttl_days)
        ).isoformat()
    record = ApprovalRecord(
        root=root_str,
        profile=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        config_sha256=ctx.config_sha256,
        approved_at=utc_now_iso(),
        mode=mode,
        schema_version=APPROVAL_SCHEMA_V2,
        gcloud_path=gcloud_trust.path if gcloud_trust else None,
        gcloud_sha256=gcloud_trust.sha256 if gcloud_trust else None,
        expires_at=expires_at,
    )
    store.approvals.append(record)
    save_store(store)
    audit.log_event(
        "approval_granted",
        root=root_str,
        profile=ctx.profile_name,
        mode=mode,
        expires_at=expires_at,
    )
    return record


def revoke_approval(ctx: ResolvedProjectContext) -> bool:
    """Remove matching approval; return True if removed."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    before = len(store.approvals)
    store.approvals = [r for r in store.approvals if not _identity_matches(r, ctx, root_str)]
    if len(store.approvals) == before:
        return False
    save_store(store)
    audit.log_event("approval_revoked", root=root_str, profile=ctx.profile_name)
    return True


def consume_once_approval(record: ApprovalRecord) -> None:
    """Remove a once-mode approval after use."""
    if record.mode != "once":
        return
    store = load_store()
    store.approvals = [r for r in store.approvals if not _record_matches_once(record, r)]
    save_store(store)


def prompt_for_approval(  # noqa: C901, PLR0912
    ctx: ResolvedProjectContext,
    *,
    cloudsdk_config: Path,
    interactive: bool,
    policy: SecurityPolicy | None = None,
    gcloud_trust: GcloudTrustResult | None = None,
) -> ApprovalRecord:
    """Prompt user for approval or fail closed in non-interactive mode."""
    if not interactive:
        audit.log_event(
            "approval_denied",
            root=str(ctx.root),
            profile=ctx.profile_name,
            reason="non_interactive",
        )
        msg = "approval required for activation (non-interactive mode)"
        raise ApprovalRequiredError(msg)

    active_policy = policy or load_policy()
    console = Console(stderr=True)
    console.print("\n[bold]gcpctx wants to activate this Google Cloud context:[/bold]\n")
    console.print(f"Directory:        {ctx.root}")
    console.print(f"Profile:          {ctx.profile_name}")
    console.print(f"Project:          {ctx.project}")
    console.print(f"Service account:  {ctx.service_account}")
    console.print(f"Config SHA-256:   {ctx.config_sha256[:12]}...")
    console.print(f"CLOUDSDK_CONFIG:  {cloudsdk_config}")
    if ctx.profile.quota_project:
        console.print(f"Quota project:    {ctx.profile.quota_project}")
    if ctx.profile.env:
        env_keys = ", ".join(sorted(ctx.profile.env))
        console.print(f"Env overrides:    {env_keys}")
    if gcloud_trust is not None:
        fp = gcloud_trust.sha256[:12] if gcloud_trust.sha256 else "unavailable"
        console.print(f"gcloud path:      {gcloud_trust.path}")
        console.print(f"gcloud SHA-256:   {fp}...")
    sa_project = service_account_project(ctx.service_account)
    if sa_project is not None and sa_project != ctx.project:
        console.print(
            f"[yellow]Warning: service account project {sa_project!r} "
            f"differs from profile project {ctx.project!r}[/yellow]"
        )
    git_remote, git_branch = _git_metadata(ctx.root)
    if git_remote:
        console.print(f"Git remote:       {git_remote}")
    if git_branch:
        console.print(f"Git branch:       {git_branch}")
    if active_policy.approval_ttl_days:
        expiry = (datetime.now(tz=UTC) + timedelta(days=active_policy.approval_ttl_days)).date()
        console.print(f"Remember until:   {expiry} ({active_policy.approval_ttl_days} days)")
    console.print("\nApprove this directory/profile/service-account binding?\n")
    console.print("[A] Approve once  [R] Remember approval  [D] Deny")

    while True:
        choice = console.input("[bold cyan]Choice[/bold cyan] (A/R/D): ").strip().upper()
        if choice == "D":
            audit.log_event(
                "approval_denied",
                root=str(ctx.root),
                profile=ctx.profile_name,
                reason="user_denied",
            )
            msg = "activation denied by user"
            raise ApprovalRequiredError(msg)
        if choice in {"A", "R"}:
            mode: ApprovalMode = "once" if choice == "A" else "remembered"
            return add_approval(
                ctx,
                mode=mode,
                policy=active_policy,
                gcloud_trust=gcloud_trust,
            )
        console.print("Invalid choice. Enter A, R, or D.")


def _record_matches_once(record: ApprovalRecord, other: ApprovalRecord) -> bool:
    return (
        other.root == record.root
        and other.profile == record.profile
        and other.project == record.project
        and other.service_account == record.service_account
        and other.config_sha256 == record.config_sha256
    )


def _identity_matches(
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
    )


def _record_matches(  # noqa: PLR0911, PLR0912
    record: ApprovalRecord,
    ctx: ResolvedProjectContext,
    root_str: str,
    policy: SecurityPolicy,
    gcloud_trust: GcloudTrustResult | None,
) -> bool:
    if not _identity_matches(record, ctx, root_str):
        return False
    if record.schema_version < APPROVAL_SCHEMA_V2 and policy.strict:
        return False
    if policy.require_gcloud_path_approval:
        if gcloud_trust is None:
            return False
        if record.gcloud_path != gcloud_trust.path:
            return False
        if (
            record.gcloud_sha256 is not None
            and gcloud_trust.sha256 is not None
            and record.gcloud_sha256 != gcloud_trust.sha256
        ):
            return False
    return True


def _is_expired(record: ApprovalRecord) -> bool:
    if record.mode != "remembered" or not record.expires_at:
        return False
    try:
        expires = datetime.fromisoformat(record.expires_at)
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return datetime.now(tz=UTC) >= expires


def _git_metadata(root: Path) -> tuple[str | None, str | None]:
    remote = _git_output(root, ["config", "--get", "remote.origin.url"])
    branch = _git_output(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    return remote, branch


def _git_output(root: Path, args: list[str]) -> str | None:  # noqa: PLR0911
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603
            [git, *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )  # nosec B603
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None
