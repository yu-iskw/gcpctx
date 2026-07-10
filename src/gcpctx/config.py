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
"""Load and validate .gcpctx.toml."""

from __future__ import annotations

from pathlib import Path

import tomli_w

from gcpctx.core.config import (
    ALLOWED_ENV_KEYS,
    PROFILE_NAME_RE,
    PROJECT_ID_RE,
    SERVICE_ACCOUNT_RE,
    hash_config_bytes,
    parse_and_validate,
    render_init_project_toml,
    select_profile,
    service_account_project,
    validate_init_project_inputs,
)
from gcpctx.core.model import GcpctxConfig
from gcpctx.core.policy import SecurityPolicy
from gcpctx.discovery import config_path
from gcpctx.errors import ConfigValidationError
from gcpctx.policy import load_policy
from gcpctx.security import (
    check_config_permissions,
    ensure_file,
    reject_symlink,
    secure_read_text,
)

__all__ = [
    "ALLOWED_ENV_KEYS",
    "PROFILE_NAME_RE",
    "PROJECT_ID_RE",
    "SERVICE_ACCOUNT_RE",
    "config_sha256",
    "hash_config_bytes",
    "load_config",
    "load_config_from_bytes",
    "load_project_config",
    "load_project_config_bytes",
    "parse_and_validate",
    "render_init_project_toml",
    "resolve_existing_gcloud_binary",
    "save_config",
    "select_profile",
    "service_account_project",
    "set_project_gcloud_path",
    "unset_project_gcloud_path",
    "validate_init_project_inputs",
]


def config_sha256(root: Path) -> str:
    """Return SHA-256 hex digest of raw .gcpctx.toml bytes."""
    return hash_config_bytes(config_path(root).read_bytes())


def load_config_from_bytes(
    raw: bytes,
    *,
    policy: SecurityPolicy | None = None,
) -> GcpctxConfig:
    """Load and validate configuration from raw TOML bytes."""
    active_policy = policy or load_policy()
    return parse_and_validate(raw, active_policy)


def load_config(root: Path, *, policy: SecurityPolicy | None = None) -> GcpctxConfig:
    """Load and validate configuration from a project root."""
    return load_config_from_bytes(config_path(root).read_bytes(), policy=policy)


def load_project_config_bytes(
    root: Path,
    *,
    policy: SecurityPolicy | None = None,
) -> tuple[GcpctxConfig, bytes]:
    """Load project config and return parsed model plus raw bytes."""
    check_config_permissions(root)
    cfg_path = config_path(root)
    reject_symlink(cfg_path)
    raw = secure_read_text(cfg_path).encode("utf-8")
    return load_config_from_bytes(raw, policy=policy), raw


def load_project_config(root: Path, *, policy: SecurityPolicy | None = None) -> GcpctxConfig:
    """Load project config with permission and symlink checks."""
    return load_project_config_bytes(root, policy=policy)[0]


def save_config(root: Path, config: GcpctxConfig) -> None:
    """Write validated project configuration to .gcpctx.toml."""
    payload = config.model_dump(mode="json", exclude_none=True)
    ensure_file(config_path(root), tomli_w.dumps(payload))


def resolve_existing_gcloud_binary(gcloud_path: str | Path) -> Path:
    """Resolve and verify a gcloud binary exists."""
    resolved = Path(gcloud_path).resolve()
    if not resolved.is_file():
        msg = f"gcloud binary not found: {resolved}"
        raise ConfigValidationError(msg)
    return resolved


def set_project_gcloud_path(root: Path, gcloud_path: str) -> None:
    """Set gcloud_path in .gcpctx.toml after validating the binary exists."""
    resolved = resolve_existing_gcloud_binary(gcloud_path)
    config = load_project_config(root)
    updated = config.model_copy(update={"gcloud_path": str(resolved)})
    save_config(root, updated)


def unset_project_gcloud_path(root: Path) -> None:
    """Remove gcloud_path from .gcpctx.toml."""
    config = load_project_config(root)
    updated = config.model_copy(update={"gcloud_path": None})
    save_config(root, updated)
