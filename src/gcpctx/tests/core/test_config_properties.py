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
"""Property tests for gcpctx.core.config.parse_and_validate."""

from __future__ import annotations

import pytest
import tomli_w
from hypothesis import assume, given, settings, strategies as st

from gcpctx.core.config import parse_and_validate
from gcpctx.core.model import GcpctxConfig
from gcpctx.core.policy import SecurityPolicy
from gcpctx.errors import ConfigValidationError

_LOWER = "abcdefghijklmnopqrstuvwxyz"
_DIGITS = "0123456789"
_LOWER_DIGITS = _LOWER + _DIGITS
_LOWER_DIGITS_HYPHEN = _LOWER_DIGITS + "-"

# TOML bare-key safe: A-Za-z0-9 + _ + - (no dots to avoid table-hierarchy ambiguity)
_PROFILE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

# Project ID must match ^[a-z][a-z0-9-]{4,28}[a-z0-9]$
_valid_project = st.builds(
    lambda first, middle, last: first + middle + last,
    first=st.text(alphabet=_LOWER, min_size=1, max_size=1),
    middle=st.text(alphabet=_LOWER_DIGITS_HYPHEN, min_size=4, max_size=10),
    last=st.text(alphabet=_LOWER_DIGITS, min_size=1, max_size=1),
)

_valid_profile_name = st.text(alphabet=_PROFILE_ALPHABET, min_size=1, max_size=16)
_valid_sa_local = st.text(alphabet=_LOWER + _DIGITS, min_size=1, max_size=16)

_DEFAULT_POLICY = SecurityPolicy()


@st.composite
def _valid_config_bytes(draw: st.DrawFn) -> bytes:
    profile = draw(_valid_profile_name)
    project = draw(_valid_project)
    sa_local = draw(_valid_sa_local)
    sa = f"{sa_local}@{project}.iam.gserviceaccount.com"
    data: dict = {
        "version": 1,
        "default_profile": profile,
        "profiles": {
            profile: {
                "project": project,
                "service_account": sa,
            }
        },
    }
    return tomli_w.dumps(data).encode("utf-8")


@given(_valid_config_bytes())
@settings(max_examples=50)
def test_valid_config_round_trips(raw: bytes) -> None:
    """Any generated valid config must parse cleanly and expose expected structure."""
    config = parse_and_validate(raw, _DEFAULT_POLICY)
    assert isinstance(config, GcpctxConfig)
    assert config.version == 1
    assert config.default_profile in config.profiles
    profile = config.profiles[config.default_profile]
    assert profile.service_account.endswith(".iam.gserviceaccount.com")
    assert "@" in profile.service_account


@given(st.integers().filter(lambda v: v != 1))
@settings(max_examples=50)
def test_wrong_version_rejects(bad_version: int) -> None:
    """Configs with version != 1 must always be rejected."""
    data: dict = {
        "version": bad_version,
        "default_profile": "dev",
        "profiles": {
            "dev": {
                "project": "my-dev-project",
                "service_account": "svc@my-dev-project.iam.gserviceaccount.com",
            }
        },
    }
    raw = tomli_w.dumps(data).encode("utf-8")
    with pytest.raises(ConfigValidationError):
        parse_and_validate(raw, _DEFAULT_POLICY)


@given(_valid_profile_name, _valid_profile_name)
@settings(max_examples=50)
def test_missing_default_profile_rejects(profile: str, other: str) -> None:
    """default_profile pointing to a non-existent profile must be rejected."""
    assume(profile != other)
    data: dict = {
        "version": 1,
        "default_profile": profile,
        "profiles": {
            other: {
                "project": "my-dev-project",
                "service_account": "svc@my-dev-project.iam.gserviceaccount.com",
            }
        },
    }
    raw = tomli_w.dumps(data).encode("utf-8")
    with pytest.raises(ConfigValidationError):
        parse_and_validate(raw, _DEFAULT_POLICY)


@given(
    # Project IDs shorter than 6 characters can never match the regex.
    st.text(alphabet=_LOWER_DIGITS, min_size=1, max_size=5),
)
@settings(max_examples=50)
def test_too_short_project_id_rejects(bad_project: str) -> None:
    """Project IDs shorter than 6 characters must be rejected."""
    data: dict = {
        "version": 1,
        "default_profile": "dev",
        "profiles": {
            "dev": {
                "project": bad_project,
                "service_account": f"svc@{bad_project}.iam.gserviceaccount.com",
            }
        },
    }
    raw = tomli_w.dumps(data).encode("utf-8")
    with pytest.raises(ConfigValidationError):
        parse_and_validate(raw, _DEFAULT_POLICY)


@given(
    # Strings with no '@' are never valid service account emails.
    st.text(alphabet=_LOWER_DIGITS + "-", min_size=1, max_size=30).filter(lambda s: "@" not in s),
)
@settings(max_examples=50)
def test_invalid_service_account_email_rejects(bad_sa: str) -> None:
    """Service account values without '@' must be rejected."""
    data: dict = {
        "version": 1,
        "default_profile": "dev",
        "profiles": {
            "dev": {
                "project": "my-dev-project",
                "service_account": bad_sa,
            }
        },
    }
    raw = tomli_w.dumps(data).encode("utf-8")
    with pytest.raises(ConfigValidationError):
        parse_and_validate(raw, _DEFAULT_POLICY)


@given(_valid_project, _valid_project)
@settings(max_examples=50)
def test_service_account_project_mismatch_rejects(project_a: str, project_b: str) -> None:
    """SA email referencing a different project than the profile must be rejected."""
    assume(project_a != project_b)
    data: dict = {
        "version": 1,
        "default_profile": "dev",
        "profiles": {
            "dev": {
                "project": project_a,
                "service_account": f"svc@{project_b}.iam.gserviceaccount.com",
            }
        },
    }
    raw = tomli_w.dumps(data).encode("utf-8")
    with pytest.raises(ConfigValidationError):
        parse_and_validate(raw, _DEFAULT_POLICY)
