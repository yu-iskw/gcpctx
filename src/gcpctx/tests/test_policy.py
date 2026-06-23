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
"""Policy loading tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx import paths
from gcpctx.errors import PolicyViolationError
from gcpctx.policy import load_policy

if TYPE_CHECKING:
    from pathlib import Path


def _write_policy(config: Path, content: str) -> None:
    path = config / "policy.toml"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def test_load_valid_minimal_policy() -> None:
    _write_policy(paths.user_config_path(), "version = 1\n")

    policy = load_policy()

    assert policy.source is not None
    assert policy.mode == "default"


def test_policy_rejects_string_bool() -> None:
    _write_policy(
        paths.user_config_path(),
        'version = 1\n\n[policy]\nrequire_initialized_adc_for_hook = "false"\n',
    )

    with pytest.raises(PolicyViolationError):
        load_policy()


def test_policy_rejects_invalid_ttl() -> None:
    _write_policy(
        paths.user_config_path(),
        'version = 1\n\n[policy]\napproval_ttl_days = "abc"\n',
    )

    with pytest.raises(PolicyViolationError):
        load_policy()


def test_policy_rejects_string_allowlist() -> None:
    _write_policy(
        paths.user_config_path(),
        'version = 1\n\n[allow]\nprojects = "prod-*"\n',
    )

    with pytest.raises(PolicyViolationError):
        load_policy()


def test_policy_rejects_unknown_top_level_key() -> None:
    _write_policy(paths.user_config_path(), "version = 1\nunexpected = true\n")

    with pytest.raises(PolicyViolationError):
        load_policy()
