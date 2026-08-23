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
"""Approval store tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from gcpctx import paths
from gcpctx.approvals import (
    RUN_APPROVAL_TTL,
    add_approval,
    consume_once_approval,
    find_matching_approval,
    load_store,
    revoke_approval,
    save_store,
)
from gcpctx.policy import SecurityPolicy
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context
from gcpctx.tests.conftest import matching_gcloud_trust

if TYPE_CHECKING:
    from pathlib import Path


def _ctx(project_tree: Path, config_sha256: str | None = None) -> ResolvedProjectContext:
    ctx = resolve_project_context(project_tree)
    if config_sha256 is None:
        return ctx
    return ResolvedProjectContext(
        root=ctx.root,
        profile_name=ctx.profile_name,
        profile=ctx.profile,
        config_sha256=config_sha256,
    )


def test_persist_and_match(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    record = find_matching_approval(ctx)
    assert record is not None
    assert record.mode == "remembered"
    assert paths.approvals_file().is_file()


def test_config_hash_invalidation(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    assert find_matching_approval(_ctx(project_tree, "sha2")) is None


def test_revoke(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    assert revoke_approval(ctx)


def test_gcloud_binding_requires_trust(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered")
    strict_policy = replace(SecurityPolicy(), require_gcloud_path_approval=True, mode="strict")
    assert find_matching_approval(ctx, policy=strict_policy, gcloud_trust=None) is None


def test_shell_remember_does_not_match_run_scope(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered", scope="shell")
    assert find_matching_approval(ctx, required_scope="shell") is not None
    assert find_matching_approval(ctx, required_scope="run") is None


def test_approve_run_ttl_is_eight_hours(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    before = datetime.now(tz=UTC)
    record = add_approval(ctx, mode="remembered", scope="run")
    after = datetime.now(tz=UTC)
    assert record.scope == "run"
    assert record.expires_at is not None
    expires = datetime.fromisoformat(record.expires_at)
    expected_min = before + RUN_APPROVAL_TTL
    expected_max = after + RUN_APPROVAL_TTL
    assert expected_min <= expires <= expected_max
    assert expires - before < timedelta(days=1)


def test_run_scope_keys_on_root_and_config_hash(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered", scope="run")
    assert find_matching_approval(_ctx(project_tree, "sha2"), required_scope="run") is None


def test_consume_run_once_preserves_shell_remember(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered", scope="shell")
    once = add_approval(ctx, mode="once", scope="run")
    consume_once_approval(once)
    assert find_matching_approval(ctx, required_scope="shell") is not None
    assert find_matching_approval(ctx, required_scope="run") is None


def test_scopes_coexist_and_gcloud_pin_on_run(project_tree: Path) -> None:
    ctx = _ctx(project_tree, "sha1")
    add_approval(ctx, mode="remembered", scope="shell")
    add_approval(
        ctx,
        mode="remembered",
        scope="run",
        gcloud_trust=matching_gcloud_trust(),
    )
    store = load_store()
    assert {record.scope for record in store.approvals} == {"shell", "run"}
    save_store(store)
    assert find_matching_approval(ctx, required_scope="shell") is not None
    assert find_matching_approval(ctx, required_scope="run") is not None
