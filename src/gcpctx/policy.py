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
    if raw.get("version") != 1:
        msg = f"policy {path}: version must be 1"
        raise PolicyViolationError(msg)
    policy_table = raw.get("policy", {})
    allow_table = raw.get("allow", {})
    deny_table = raw.get("deny", {})
    gcloud_table = raw.get("gcloud", {})
    deny_env = deny_table.get("env", {}) if isinstance(deny_table, dict) else {}
    extra_denied = deny_env.get("keys", []) if isinstance(deny_env, dict) else []
    denied_keys = DEFAULT_DENIED_ENV_KEYS | frozenset(extra_denied)
    mode = policy_table.get("mode", "default")
    if mode not in {"default", "strict"}:
        msg = f"policy {path}: invalid mode {mode!r}"
        raise PolicyViolationError(msg)
    return SecurityPolicy(
        source=path,
        mode=mode,
        approval_ttl_days=int(policy_table.get("approval_ttl_days", 30)),
        require_initialized_adc_for_hook=bool(
            policy_table.get("require_initialized_adc_for_hook", mode == "strict")
        ),
        require_gcloud_path_approval=bool(
            policy_table.get("require_gcloud_path_approval", mode == "strict")
        ),
        allow_projects=_tuple_of_str(allow_table.get("projects")),
        allow_service_account_domains=_tuple_of_str(allow_table.get("service_account_domains")),
        allow_quota_projects=_tuple_of_str(allow_table.get("quota_projects")),
        deny_env_keys=denied_keys,
        gcloud=GcloudPolicy(
            allowed_paths=_tuple_of_str(gcloud_table.get("allowed_paths")),
            deny_if_under_cwd=bool(gcloud_table.get("deny_if_under_cwd", True)),
            deny_world_writable_parent=bool(gcloud_table.get("deny_world_writable_parent", True)),
        ),
    )


def _tuple_of_str(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value)
