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

from gcpctx.config import hash_config_bytes, load_config_from_bytes, select_profile
from gcpctx.discovery import config_path, find_project_root
from gcpctx.errors import ConfigNotFoundError
from gcpctx.security import check_config_permissions

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

    @property
    def project(self) -> str:
        return self.profile.project

    @property
    def service_account(self) -> str:
        return self.profile.service_account


def resolve_project_context(
    cwd: Path,
    profile: str | None = None,
) -> ResolvedProjectContext:
    """Discover, validate, and load project context from *cwd*."""
    root = find_project_root(cwd)
    if root is None:
        msg = "No .gcpctx.toml found"
        raise ConfigNotFoundError(msg)
    check_config_permissions(root)
    raw = config_path(root).read_bytes()
    config = load_config_from_bytes(raw)
    profile_name, prof = select_profile(config, profile)
    return ResolvedProjectContext(
        root=root,
        profile_name=profile_name,
        profile=prof,
        config_sha256=hash_config_bytes(raw),
    )
