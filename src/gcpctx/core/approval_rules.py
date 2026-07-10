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
"""Pure approval matching and record construction (no I/O)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, Protocol

from gcpctx.core.model import ApprovalRecord

if TYPE_CHECKING:
    from gcpctx.core.policy import SecurityPolicy

ApprovalMode = Literal["once", "remembered"]
APPROVAL_SCHEMA_V2 = 2


class ApprovalIdentity(Protocol):
    """Minimal identity fields for approval matching."""

    @property
    def profile_name(self) -> str:
        raise NotImplementedError

    @property
    def project(self) -> str:
        raise NotImplementedError

    @property
    def service_account(self) -> str:
        raise NotImplementedError

    @property
    def config_sha256(self) -> str:
        raise NotImplementedError


class GcloudTrustInfo(Protocol):
    """Minimal gcloud trust fields for approval binding checks."""

    @property
    def path(self) -> str:
        raise NotImplementedError

    @property
    def sha256(self) -> str | None:
        raise NotImplementedError


@dataclass(frozen=True)
class ApprovalRecordInput:
    """Inputs for constructing an ApprovalRecord."""

    root: str
    profile: str
    project: str
    service_account: str
    config_sha256: str
    approved_at: str
    mode: ApprovalMode
    expires_at: str | None = None
    gcloud_path: str | None = None
    gcloud_sha256: str | None = None
    gcloud_version: str | None = None


def identity_matches(
    record: ApprovalRecord,
    identity: ApprovalIdentity,
    root_str: str,
) -> bool:
    """Return True when record matches directory/profile/config identity."""
    return (
        record.root == root_str
        and record.profile == identity.profile_name
        and record.project == identity.project
        and record.service_account == identity.service_account
        and record.config_sha256 == identity.config_sha256
    )


def _gcloud_binding_matches(
    record: ApprovalRecord,
    policy: SecurityPolicy,
    gcloud_trust: GcloudTrustInfo | None,
) -> bool:
    if not policy.require_gcloud_path_approval:
        return True
    if gcloud_trust is None or record.gcloud_path != gcloud_trust.path:
        return False
    return not (
        record.gcloud_sha256 is not None
        and gcloud_trust.sha256 is not None
        and record.gcloud_sha256 != gcloud_trust.sha256
    )


def record_matches(
    record: ApprovalRecord,
    identity: ApprovalIdentity,
    root_str: str,
    policy: SecurityPolicy,
    gcloud_trust: GcloudTrustInfo | None,
) -> bool:
    """Return True when record is a valid match under the active policy."""
    if not identity_matches(record, identity, root_str):
        return False
    if record.schema_version < APPROVAL_SCHEMA_V2 and policy.strict:
        return False
    return _gcloud_binding_matches(record, policy, gcloud_trust)


def is_expired(record: ApprovalRecord, now: datetime) -> bool:
    """Return True when a remembered approval has passed its expiry."""
    if record.mode != "remembered" or not record.expires_at:
        return False
    try:
        expires = datetime.fromisoformat(record.expires_at)
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    aware_now = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    return aware_now >= expires


def record_matches_once(record: ApprovalRecord, other: ApprovalRecord) -> bool:
    """Return True when *other* is the same once-approval binding as *record*."""
    return (
        other.root == record.root
        and other.profile == record.profile
        and other.project == record.project
        and other.service_account == record.service_account
        and other.config_sha256 == record.config_sha256
    )


def approval_evidence_id(record: ApprovalRecord) -> str:
    """Return a stable, non-secret identifier for an approval record."""
    digest = hashlib.sha256(
        f"{record.root}:{record.profile}:{record.approved_at}".encode()
    ).hexdigest()
    return f"sha256:{digest[:16]}"


def build_approval_record(inp: ApprovalRecordInput) -> ApprovalRecord:
    """Construct an ApprovalRecord (caller supplies timestamps)."""
    return ApprovalRecord(
        root=inp.root,
        profile=inp.profile,
        project=inp.project,
        service_account=inp.service_account,
        config_sha256=inp.config_sha256,
        approved_at=inp.approved_at,
        mode=inp.mode,
        schema_version=APPROVAL_SCHEMA_V2,
        gcloud_path=inp.gcloud_path,
        gcloud_sha256=inp.gcloud_sha256,
        gcloud_version=inp.gcloud_version,
        expires_at=inp.expires_at,
    )
