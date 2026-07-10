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
"""Security policy loading and enforcement."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import ValidationError

from gcpctx import paths
from gcpctx.core.policy import (
    BLOCKED_PROFILE_EXPORT_ENV_KEYS,
    DEFAULT_DENIED_ENV_KEYS,
    DEPRECATED_PROFILE_ENV_KEYS,
    AllowSection,
    DenyEnvSection,
    DenySection,
    GcloudPolicy,
    GcloudSection,
    PolicyFile,
    PolicyMode,
    PolicySection,
    SecurityPolicy,
    matches_allowlist,
    policy_from_parsed,
    profile_env_for_export,
    validate_env_keys_allowed,
    validate_project_allowed,
    validate_quota_project_allowed,
    validate_service_account_allowed,
)
from gcpctx.errors import PolicyViolationError
from gcpctx.security import reject_symlink, secure_read_text

__all__ = [
    "BLOCKED_PROFILE_EXPORT_ENV_KEYS",
    "DEFAULT_DENIED_ENV_KEYS",
    "DEPRECATED_PROFILE_ENV_KEYS",
    "AllowSection",
    "DenyEnvSection",
    "DenySection",
    "GcloudPolicy",
    "GcloudSection",
    "PolicyFile",
    "PolicyMode",
    "PolicySection",
    "SecurityPolicy",
    "load_policy",
    "matches_allowlist",
    "policy_from_parsed",
    "profile_env_for_export",
    "validate_env_keys_allowed",
    "validate_project_allowed",
    "validate_quota_project_allowed",
    "validate_service_account_allowed",
]


def _load_policy_file(path: str) -> SecurityPolicy:
    policy_path = Path(path)
    reject_symlink(policy_path)
    try:
        raw = tomllib.loads(secure_read_text(policy_path))
    except tomllib.TOMLDecodeError as exc:
        msg = f"policy {path}: invalid TOML: {exc}"
        raise PolicyViolationError(msg) from exc
    try:
        parsed = PolicyFile.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors()
        detail = errors[0]["msg"] if errors else "validation failed"
        msg = f"policy {path}: invalid schema: {detail}"
        raise PolicyViolationError(msg) from exc
    return policy_from_parsed(path, parsed)


def load_policy() -> SecurityPolicy:
    """Load policy from GCPCTX_POLICY_PATH or ~/.config/gcpctx/policy.toml."""
    env_path = os.environ.get("GCPCTX_POLICY_PATH")
    if env_path:
        return _load_policy_file(env_path)
    default_path = paths.user_config_path() / "policy.toml"
    if default_path.is_file():
        return _load_policy_file(str(default_path))
    return SecurityPolicy()
