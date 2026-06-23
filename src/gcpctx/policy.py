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
"""Security policy loading and enforcement."""

from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from gcpctx import paths
from gcpctx.errors import PolicyViolationError
from gcpctx.security import reject_symlink, secure_read_text

PolicyMode = Literal["default", "strict"]

DEFAULT_DENIED_ENV_KEYS = frozenset(
    {
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "CLOUDSDK_CONFIG",
        "CLOUDSDK_CORE_PROJECT",
    }
)

DEPRECATED_PROFILE_ENV_KEYS = frozenset({"CLOUDSDK_CORE_PROJECT"})


@dataclass(frozen=True)
class GcloudPolicy:
    """gcloud binary trust policy."""

    allowed_paths: tuple[str, ...] = ()
    deny_if_under_cwd: bool = True
    deny_world_writable_parent: bool = True


@dataclass(frozen=True)
class SecurityPolicy:
    """Loaded security policy."""

    source: str | None = None
    mode: PolicyMode = "default"
    approval_ttl_days: int = 30
    require_initialized_adc_for_hook: bool = False
    require_gcloud_path_approval: bool = False
    allow_projects: tuple[str, ...] = ()
    allow_service_account_domains: tuple[str, ...] = ()
    allow_quota_projects: tuple[str, ...] = ()
    deny_env_keys: frozenset[str] = DEFAULT_DENIED_ENV_KEYS
    gcloud: GcloudPolicy = field(default_factory=GcloudPolicy)

    @property
    def strict(self) -> bool:
        return self.mode == "strict"


class PolicySection(BaseModel):
    """Policy table in policy.toml."""

    model_config = ConfigDict(extra="forbid", strict=True)

    mode: Literal["default", "strict"] = "default"
    approval_ttl_days: int = Field(default=30, ge=1, le=365)
    require_initialized_adc_for_hook: bool | None = None
    require_gcloud_path_approval: bool | None = None


class AllowSection(BaseModel):
    """Allowlist table in policy.toml."""

    model_config = ConfigDict(extra="forbid", strict=True)

    projects: list[str] = Field(default_factory=list)
    service_account_domains: list[str] = Field(default_factory=list)
    quota_projects: list[str] = Field(default_factory=list)


class DenyEnvSection(BaseModel):
    """Denied env keys."""

    model_config = ConfigDict(extra="forbid", strict=True)

    keys: list[str] = Field(default_factory=list)


class DenySection(BaseModel):
    """Deny table in policy.toml."""

    model_config = ConfigDict(extra="forbid", strict=True)

    env: DenyEnvSection = Field(default_factory=DenyEnvSection)


class GcloudSection(BaseModel):
    """gcloud trust table in policy.toml."""

    model_config = ConfigDict(extra="forbid", strict=True)

    allowed_paths: list[str] = Field(default_factory=list)
    deny_if_under_cwd: bool = True
    deny_world_writable_parent: bool = True


class PolicyFile(BaseModel):
    """Top-level policy.toml schema."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    policy: PolicySection = Field(default_factory=PolicySection)
    allow: AllowSection = Field(default_factory=AllowSection)
    deny: DenySection = Field(default_factory=DenySection)
    gcloud: GcloudSection = Field(default_factory=GcloudSection)


def load_policy() -> SecurityPolicy:
    """Load policy from GCPCTX_POLICY_PATH or ~/.config/gcpctx/policy.toml."""
    env_path = os.environ.get("GCPCTX_POLICY_PATH")
    if env_path:
        return _load_policy_file(env_path)
    default_path = paths.user_config_path() / "policy.toml"
    if default_path.is_file():
        return _load_policy_file(str(default_path))
    return SecurityPolicy()


def matches_allowlist(value: str, patterns: tuple[str, ...]) -> bool:
    """Return True when *patterns* is empty or *value* matches any glob."""
    if not patterns:
        return True
    return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def validate_project_allowed(project: str, policy: SecurityPolicy) -> None:
    if matches_allowlist(project, policy.allow_projects):
        return
    msg = f"project {project!r} is not allowed by policy"
    raise PolicyViolationError(msg)


def validate_quota_project_allowed(quota_project: str | None, policy: SecurityPolicy) -> None:
    if quota_project is None:
        return
    if matches_allowlist(quota_project, policy.allow_quota_projects):
        return
    msg = f"quota_project {quota_project!r} is not allowed by policy"
    raise PolicyViolationError(msg)


def validate_service_account_allowed(service_account: str, policy: SecurityPolicy) -> None:
    if not policy.allow_service_account_domains:
        return
    domain = service_account.split("@", 1)[-1]
    if matches_allowlist(domain, policy.allow_service_account_domains):
        return
    msg = f"service account domain for {service_account!r} is not allowed by policy"
    raise PolicyViolationError(msg)


def validate_env_keys_allowed(env_keys: set[str], policy: SecurityPolicy) -> None:
    denied = env_keys & policy.deny_env_keys
    if not denied:
        return
    key = sorted(denied)[0]
    msg = f"env key {key!r} is denied by policy"
    raise PolicyViolationError(msg)


def _load_policy_file(path: str) -> SecurityPolicy:
    policy_path = Path(path)
    reject_symlink(policy_path)
    raw = tomllib.loads(secure_read_text(policy_path))
    try:
        parsed = PolicyFile.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors()
        detail = errors[0]["msg"] if errors else "validation failed"
        msg = f"policy {path}: invalid schema: {detail}"
        raise PolicyViolationError(msg) from exc
    return _policy_from_file(path, parsed)


def _policy_from_file(path: str, parsed: PolicyFile) -> SecurityPolicy:
    mode = parsed.policy.mode
    require_adc = parsed.policy.require_initialized_adc_for_hook
    if require_adc is None:
        require_adc = mode == "strict"
    require_gcloud = parsed.policy.require_gcloud_path_approval
    if require_gcloud is None:
        require_gcloud = mode == "strict"
    denied_keys = DEFAULT_DENIED_ENV_KEYS | frozenset(parsed.deny.env.keys)
    return SecurityPolicy(
        source=path,
        mode=mode,
        approval_ttl_days=parsed.policy.approval_ttl_days,
        require_initialized_adc_for_hook=require_adc,
        require_gcloud_path_approval=require_gcloud,
        allow_projects=tuple(parsed.allow.projects),
        allow_service_account_domains=tuple(parsed.allow.service_account_domains),
        allow_quota_projects=tuple(parsed.allow.quota_projects),
        deny_env_keys=denied_keys,
        gcloud=GcloudPolicy(
            allowed_paths=tuple(parsed.gcloud.allowed_paths),
            deny_if_under_cwd=parsed.gcloud.deny_if_under_cwd,
            deny_world_writable_parent=parsed.gcloud.deny_world_writable_parent,
        ),
    )
