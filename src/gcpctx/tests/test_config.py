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
"""Config parsing tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.config import load_config, select_profile, validate_init_project_inputs
from gcpctx.errors import ConfigValidationError

if TYPE_CHECKING:
    from pathlib import Path


def test_load_valid_config(project_tree: Path) -> None:
    config = load_config(project_tree)
    assert config.version == 1
    assert config.default_profile == "dev"
    name, profile = select_profile(config, None)
    assert name == "dev"
    assert profile.project == "my-dev-project"


def test_invalid_default_profile(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / ".gcpctx.toml").write_text(
        'version = 1\ndefault_profile = "missing"\n[profiles.dev]\n'
        'project = "my-dev-project"\n'
        'service_account = "a@my-dev-project.iam.gserviceaccount.com"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError):
        load_config(root)


def test_invalid_service_account(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / ".gcpctx.toml").write_text(
        'version = 1\ndefault_profile = "dev"\n[profiles.dev]\n'
        'project = "my-dev-project"\n'
        'service_account = "not-an-email"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError):
        load_config(root)


def test_disallowed_env_key(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / ".gcpctx.toml").write_text(
        'version = 1\ndefault_profile = "dev"\n[profiles.dev]\n'
        'project = "my-dev-project"\n'
        'service_account = "a@my-dev-project.iam.gserviceaccount.com"\n'
        '[profiles.dev.env]\nPATH = "/tmp"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError):
        load_config(root)


def test_malicious_profile_name(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / ".gcpctx.toml").write_text(
        'version = 1\ndefault_profile = "dev"\n'
        '[profiles."; rm -rf /"]\n'
        'project = "my-dev-project"\n'
        'service_account = "a@my-dev-project.iam.gserviceaccount.com"\n',
        encoding="utf-8",
    )
    with pytest.raises(Exception):  # noqa: B017, PT011
        load_config(root)


def test_validate_init_project_inputs_rejects_invalid_project() -> None:
    with pytest.raises(ConfigValidationError, match="invalid GCP project ID"):
        validate_init_project_inputs(
            project="INVALID",
            service_account="a@my-dev-project.iam.gserviceaccount.com",
            profile="dev",
        )


def test_rejects_cloudsdk_core_project_env(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / ".gcpctx.toml").write_text(
        'version = 1\ndefault_profile = "dev"\n[profiles.dev]\n'
        'project = "my-dev-project"\n'
        'service_account = "a@my-dev-project.iam.gserviceaccount.com"\n'
        '[profiles.dev.env]\nCLOUDSDK_CORE_PROJECT = "other-project"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="CLOUDSDK_CORE_PROJECT"):
        load_config(root)


def test_service_account_project_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "r"
    root.mkdir()
    (root / ".gcpctx.toml").write_text(
        'version = 1\ndefault_profile = "dev"\n[profiles.dev]\n'
        'project = "my-dev-project"\n'
        'service_account = "agent@other-project.iam.gserviceaccount.com"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigValidationError, match="does not match"):
        load_config(root)
