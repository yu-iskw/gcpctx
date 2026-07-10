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
"""First-use approval persistence and matching."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from gcpctx import audit
from gcpctx.adapters.state import FilesystemStateStore
from gcpctx.adapters.system import NullPrompter, RichPrompter
from gcpctx.config import service_account_project
from gcpctx.core.approval_rules import (
    APPROVAL_SCHEMA_V2,
    approval_evidence_id,
    build_approval_record,
    identity_matches,
    is_expired,
    record_matches,
    record_matches_once,
)
from gcpctx.errors import ApprovalRequiredError
from gcpctx.models import ApprovalRecord, ApprovalsStore
from gcpctx.policy import SecurityPolicy, load_policy
from gcpctx.ports import ApprovalRequest
from gcpctx.timeutil import utc_now_iso

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.gcloud_trust import GcloudTrustResult
    from gcpctx.ports import Prompter, StateStore
    from gcpctx.project_context import ResolvedProjectContext

ApprovalMode = Literal["once", "remembered"]

_APPROVALS_KEY = "approvals"

__all__ = [
    "APPROVAL_SCHEMA_V2",
    "ApprovalDoctorState",
    "ApprovalMode",
    "add_approval",
    "approval_evidence_id",
    "consume_once_approval",
    "find_expired_remembered_approval",
    "find_identity_approval",
    "find_matching_approval",
    "load_store",
    "prompt_for_approval",
    "resolve_approval_doctor_state",
    "revoke_approval",
    "save_store",
]


def _default_state_store() -> StateStore:
    return FilesystemStateStore()


def load_store(*, state_store: StateStore | None = None) -> ApprovalsStore:
    """Load approvals from disk or return empty store."""
    store = state_store or _default_state_store()
    with store.lock(_APPROVALS_KEY):
        data = store.read(_APPROVALS_KEY)
    if data is None:
        return ApprovalsStore()
    return ApprovalsStore.model_validate_json(data)


def save_store(store: ApprovalsStore, *, state_store: StateStore | None = None) -> None:
    """Persist approvals to disk."""
    backend = state_store or _default_state_store()
    payload = store.model_dump_json(indent=2).encode("utf-8")
    with backend.lock(_APPROVALS_KEY):
        backend.write(_APPROVALS_KEY, payload)


def _now_utc() -> datetime:
    return datetime.now(tz=UTC)


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
    now = _now_utc()
    for record in store.approvals:
        if not record_matches(record, ctx, root_str, active_policy, gcloud_trust):
            continue
        if is_expired(record, now):
            continue
        return record
    return None


def find_identity_approval(ctx: ResolvedProjectContext) -> ApprovalRecord | None:
    """Return the newest identity-matching approval regardless of expiry or gcloud binding."""
    store = load_store()
    root_str = str(ctx.root.resolve())
    matches = [r for r in store.approvals if identity_matches(r, ctx, root_str)]
    if not matches:
        return None
    return max(matches, key=lambda record: record.approved_at)


def find_expired_remembered_approval(ctx: ResolvedProjectContext) -> ApprovalRecord | None:
    """Return a remembered approval that matches identity but has expired."""
    record = find_identity_approval(ctx)
    if record is None or record.mode != "remembered":
        return None
    if not is_expired(record, _now_utc()):
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
    now = _now_utc()
    identity_hits = [r for r in store.approvals if identity_matches(r, ctx, root_str)]
    identity = max(identity_hits, key=lambda record: record.approved_at) if identity_hits else None
    matching: ApprovalRecord | None = None
    for record in store.approvals:
        if not record_matches(record, ctx, root_str, policy, gcloud_trust):
            continue
        if is_expired(record, now):
            continue
        matching = record
        break
    expired_remembered: ApprovalRecord | None = None
    if identity is not None and identity.mode == "remembered" and is_expired(identity, now):
        expired_remembered = identity
    return ApprovalDoctorState(
        matching=matching,
        identity=identity,
        expired_remembered=expired_remembered,
    )


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
    store.approvals = [r for r in store.approvals if not identity_matches(r, ctx, root_str)]
    expires_at = None
    if mode == "remembered":
        expires_at = (_now_utc() + timedelta(days=active_policy.approval_ttl_days)).isoformat()
    record = build_approval_record(
        root=root_str,
        profile=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        config_sha256=ctx.config_sha256,
        approved_at=utc_now_iso(),
        mode=mode,
        expires_at=expires_at,
        gcloud_path=gcloud_trust.path if gcloud_trust else None,
        gcloud_sha256=gcloud_trust.sha256 if gcloud_trust else None,
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
    store.approvals = [r for r in store.approvals if not identity_matches(r, ctx, root_str)]
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
    store.approvals = [r for r in store.approvals if not record_matches_once(record, r)]
    save_store(store)


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


def _git_metadata(root: Path) -> tuple[str | None, str | None]:
    remote = _git_output(root, ["config", "--get", "remote.origin.url"])
    branch = _git_output(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    return remote, branch


def _build_approval_request(
    ctx: ResolvedProjectContext,
    *,
    cloudsdk_config: Path,
    policy: SecurityPolicy,
    gcloud_trust: GcloudTrustResult | None,
) -> ApprovalRequest:
    sa_project = service_account_project(ctx.service_account)
    mismatch = sa_project if sa_project is not None and sa_project != ctx.project else None
    git_remote, git_branch = _git_metadata(ctx.root)
    env_keys = tuple(sorted(ctx.profile.env)) if ctx.profile.env else ()
    return ApprovalRequest(
        root=ctx.root,
        profile=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        config_sha256=ctx.config_sha256,
        cloudsdk_config=cloudsdk_config,
        quota_project=ctx.profile.quota_project,
        env_keys=env_keys,
        gcloud_path=gcloud_trust.path if gcloud_trust is not None else None,
        gcloud_sha256=gcloud_trust.sha256 if gcloud_trust is not None else None,
        approval_ttl_days=policy.approval_ttl_days,
        git_remote=git_remote,
        git_branch=git_branch,
        sa_project_mismatch=mismatch,
    )


def prompt_for_approval(  # noqa: PLR0913
    ctx: ResolvedProjectContext,
    *,
    cloudsdk_config: Path,
    interactive: bool,
    policy: SecurityPolicy | None = None,
    gcloud_trust: GcloudTrustResult | None = None,
    prompter: Prompter | None = None,
) -> ApprovalRecord:
    """Prompt user for approval or fail closed in non-interactive mode."""
    active_policy = policy or load_policy()
    ui = prompter if prompter is not None else (RichPrompter() if interactive else NullPrompter())
    if not interactive and prompter is None:
        audit.log_event(
            "approval_denied",
            root=str(ctx.root),
            profile=ctx.profile_name,
            reason="non_interactive",
        )
        msg = "approval required for activation (non-interactive mode)"
        raise ApprovalRequiredError(msg)

    request = _build_approval_request(
        ctx,
        cloudsdk_config=cloudsdk_config,
        policy=active_policy,
        gcloud_trust=gcloud_trust,
    )
    try:
        answer = ui.confirm(request)
    except ApprovalRequiredError:
        if interactive:
            raise
        audit.log_event(
            "approval_denied",
            root=str(ctx.root),
            profile=ctx.profile_name,
            reason="non_interactive",
        )
        raise

    if answer.decision == "deny":
        audit.log_event(
            "approval_denied",
            root=str(ctx.root),
            profile=ctx.profile_name,
            reason="user_denied",
        )
        msg = "activation denied by user"
        raise ApprovalRequiredError(msg)

    mode: ApprovalMode = "once" if answer.decision == "once" else "remembered"
    return add_approval(
        ctx,
        mode=mode,
        policy=active_policy,
        gcloud_trust=gcloud_trust,
    )
