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
"""Load and validate .gcpctx.toml."""

from __future__ import annotations

import hashlib
import re
import tomllib
from typing import TYPE_CHECKING, Any

from gcpctx.discovery import config_path
from gcpctx.errors import ConfigValidationError
from gcpctx.models import GcpctxConfig, ProfileConfig
from gcpctx.policy import (
    DEPRECATED_PROFILE_ENV_KEYS,
    SecurityPolicy,
    load_policy,
    validate_env_keys_allowed,
    validate_project_allowed,
    validate_quota_project_allowed,
    validate_service_account_allowed,
)

if TYPE_CHECKING:
    from pathlib import Path

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
SERVICE_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9-]+\.iam\.gserviceaccount\.com$")

ALLOWED_ENV_KEYS = frozenset(
    {
        "CLOUDSDK_CORE_DISABLE_PROMPTS",
        "CLOUDSDK_COMPUTE_REGION",
        "CLOUDSDK_COMPUTE_ZONE",
    }
)


def hash_config_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of raw config bytes."""
    return hashlib.sha256(data).hexdigest()


def config_sha256(root: Path) -> str:
    """Return SHA-256 hex digest of raw .gcpctx.toml bytes."""
    return hash_config_bytes(config_path(root).read_bytes())


def load_config_from_bytes(
    raw: bytes,
    *,
    policy: SecurityPolicy | None = None,
) -> GcpctxConfig:
    """Load and validate configuration from raw TOML bytes."""
    parsed = tomllib.loads(raw.decode("utf-8"))
    active_policy = policy or load_policy()
    _validate_raw(parsed, active_policy)
    return GcpctxConfig.model_validate(parsed)


def load_config(root: Path, *, policy: SecurityPolicy | None = None) -> GcpctxConfig:
    """Load and validate configuration from a project root."""
    return load_config_from_bytes(config_path(root).read_bytes(), policy=policy)


def select_profile(config: GcpctxConfig, profile: str | None) -> tuple[str, ProfileConfig]:
    """Resolve profile name and return (name, ProfileConfig)."""
    name = profile or config.default_profile
    if name not in config.profiles:
        msg = f"Profile {name!r} not found in configuration"
        raise ConfigValidationError(msg)
    return name, config.profiles[name]


def service_account_project(service_account: str) -> str | None:
    """Extract GCP project ID from a service account email."""
    match = re.match(r"^[^@]+@([^.]+)\.iam\.gserviceaccount\.com$", service_account)
    if match is None:
        return None
    return match.group(1)


def _validate_raw(raw: dict[str, Any], policy: SecurityPolicy) -> None:
    if raw.get("version") != 1:
        msg = "version must be 1"
        raise ConfigValidationError(msg)

    default_profile = raw.get("default_profile")
    profiles = raw.get("profiles")
    if not isinstance(default_profile, str):
        msg = "default_profile must be a string"
        raise ConfigValidationError(msg)
    if not isinstance(profiles, dict) or not profiles:
        msg = "profiles must be a non-empty table"
        raise ConfigValidationError(msg)
    if default_profile not in profiles:
        msg = f"default_profile {default_profile!r} not in profiles"
        raise ConfigValidationError(msg)

    _validate_profiles(profiles, policy)


def _validate_profiles(profiles: dict[str, Any], policy: SecurityPolicy) -> None:
    for name, profile in profiles.items():
        _validate_profile_name(name)
        if not isinstance(profile, dict):
            msg = f"profile {name!r} must be a table"
            raise ConfigValidationError(msg)
        _validate_profile_fields(name, profile, policy)


def _validate_profile_name(name: str) -> None:
    if not PROFILE_NAME_RE.match(name):
        msg = f"invalid profile name: {name!r}"
        raise ConfigValidationError(msg)


def _validate_profile_fields(name: str, profile: dict[str, Any], policy: SecurityPolicy) -> None:
    _validate_profile_identity(name, profile, policy)
    _validate_profile_env(name, profile.get("env", {}), policy)


def _validate_profile_identity(
    name: str,
    profile: dict[str, Any],
    policy: SecurityPolicy,
) -> None:
    project = profile.get("project")
    service_account = profile.get("service_account")
    if not isinstance(project, str) or not PROJECT_ID_RE.match(project):
        msg = f"profile {name!r}: invalid project ID"
        raise ConfigValidationError(msg)
    if not isinstance(service_account, str) or not SERVICE_ACCOUNT_RE.match(service_account):
        msg = f"profile {name!r}: invalid service account email"
        raise ConfigValidationError(msg)

    quota = profile.get("quota_project")
    if quota is not None and (not isinstance(quota, str) or not PROJECT_ID_RE.match(quota)):
        msg = f"profile {name!r}: invalid quota_project"
        raise ConfigValidationError(msg)

    sa_project = service_account_project(service_account)
    if sa_project is not None and sa_project != project:
        msg = (
            f"profile {name!r}: service account project {sa_project!r} "
            f"does not match profile project {project!r}"
        )
        raise ConfigValidationError(msg)

    validate_project_allowed(project, policy)
    validate_service_account_allowed(service_account, policy)
    validate_quota_project_allowed(quota if isinstance(quota, str) else None, policy)


def _validate_profile_env(name: str, env: object, policy: SecurityPolicy) -> None:
    if not isinstance(env, dict):
        msg = f"profile {name!r}: env must be a table"
        raise ConfigValidationError(msg)
    for key in env:
        if key in DEPRECATED_PROFILE_ENV_KEYS:
            msg = (
                f"profile {name!r}: env key {key!r} is not allowed; "
                "remove it and use profile.project instead"
            )
            raise ConfigValidationError(msg)
        if key not in ALLOWED_ENV_KEYS:
            msg = f"profile {name!r}: env key {key!r} is not allowlisted"
            raise ConfigValidationError(msg)
    validate_env_keys_allowed(set(env), policy)


def validate_init_project_inputs(
    *,
    project: str,
    service_account: str,
    profile: str,
) -> None:
    """Validate user-supplied init-project fields."""
    if not PROJECT_ID_RE.match(project):
        msg = f"invalid GCP project ID: {project!r}"
        raise ConfigValidationError(msg)
    if not SERVICE_ACCOUNT_RE.match(service_account):
        msg = f"invalid service account email: {service_account!r}"
        raise ConfigValidationError(msg)
    sa_project = service_account_project(service_account)
    if sa_project is not None and sa_project != project:
        msg = f"service account project {sa_project!r} does not match project {project!r}"
        raise ConfigValidationError(msg)
    _validate_profile_name(profile)


def render_init_project_toml(
    *,
    project: str,
    service_account: str,
    profile: str = "dev",
) -> str:
    """Return minimal .gcpctx.toml content for init-project."""
    return (
        "version = 1\n"
        f'default_profile = "{profile}"\n\n'
        f"[profiles.{profile}]\n"
        f'project = "{project}"\n'
        f'service_account = "{service_account}"\n'
    )
