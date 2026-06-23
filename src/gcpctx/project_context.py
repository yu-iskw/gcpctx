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
"""Resolve project root, config, profile, and config hash in one pass."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gcpctx.config import hash_config_bytes, load_project_config_bytes, select_profile
from gcpctx.context_id import ContextIdInput, derive_context_id
from gcpctx.discovery import find_project_root
from gcpctx.errors import ConfigNotFoundError
from gcpctx.paths import cloudsdk_config_dir
from gcpctx.policy import SecurityPolicy, load_policy

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.models import ProfileConfig


@dataclass(frozen=True)
class ResolvedProjectContext:
    """Canonical project root, profile, and config hash."""

    root: Path
    profile_name: str
    profile: ProfileConfig
    config_sha256: str
    gcloud_path: str | None = None

    @property
    def project(self) -> str:
        return self.profile.project

    @property
    def service_account(self) -> str:
        return self.profile.service_account

    def context_id(self) -> str:
        return derive_context_id(
            ContextIdInput(
                root=self.root,
                profile=self.profile_name,
                project=self.project,
                service_account=self.service_account,
                config_sha256=self.config_sha256,
            )
        )

    def expected_cloudsdk_config(self) -> Path:
        return cloudsdk_config_dir(self.context_id())


def resolve_project_context(
    cwd: Path,
    profile: str | None = None,
    *,
    policy: SecurityPolicy | None = None,
) -> ResolvedProjectContext:
    """Discover, validate, and load project context from *cwd*."""
    root = find_project_root(cwd)
    if root is None:
        msg = "No .gcpctx.toml found"
        raise ConfigNotFoundError(msg)
    active_policy = policy or load_policy()
    config, raw = load_project_config_bytes(root, policy=active_policy)
    profile_name, prof = select_profile(config, profile)
    return ResolvedProjectContext(
        root=root,
        profile_name=profile_name,
        profile=prof,
        config_sha256=hash_config_bytes(raw),
        gcloud_path=config.gcloud_path,
    )
