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
"""gcloud trust tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gcpctx.errors import GcloudNotFoundError, GcloudTrustError
from gcpctx.gcloud_trust import (
    clear_fingerprint_cache,
    fingerprint_gcloud,
    resolve_gcloud_path,
    resolve_trusted_gcloud,
    validate_gcloud_path,
)
from gcpctx.policy import GcloudPolicy, SecurityPolicy
from gcpctx.settings import UserSettings

if TYPE_CHECKING:
    from pathlib import Path


def test_fingerprint_gcloud_caches_until_content_changes(tmp_path: Path) -> None:
    clear_fingerprint_cache()
    binary = tmp_path / "gcloud"
    binary.write_bytes(b"fake-gcloud-binary")
    first = fingerprint_gcloud(str(binary))
    second = fingerprint_gcloud(str(binary))
    assert first is not None
    assert first == second

    binary.write_bytes(b"changed-binary")
    third = fingerprint_gcloud(str(binary))
    assert third is not None
    assert third != first


def test_validate_gcloud_rejects_binary_under_cwd_by_default(
    project_tree: Path,
) -> None:
    clear_fingerprint_cache()
    binary = project_tree / "gcloud"
    binary.write_bytes(b"fake-gcloud")
    binary.chmod(0o755)
    policy = SecurityPolicy()
    with pytest.raises(GcloudTrustError, match="must not live under project"):
        validate_gcloud_path(str(binary), cwd=project_tree, policy=policy)


def test_validate_gcloud_allows_binary_under_cwd_when_policy_disabled(
    project_tree: Path,
) -> None:
    clear_fingerprint_cache()
    binary = project_tree / "gcloud"
    binary.write_bytes(b"fake-gcloud")
    binary.chmod(0o755)
    policy = SecurityPolicy(
        gcloud=GcloudPolicy(deny_if_under_cwd=False, deny_world_writable_parent=False)
    )
    result = validate_gcloud_path(str(binary), cwd=project_tree, policy=policy)
    assert result.path == str(binary.resolve())


def test_resolve_gcloud_path_falls_back_when_stale_pin(
    fake_gcloud: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "gcpctx.gcloud_trust.load_settings",
        lambda: UserSettings(gcloud_path="/usr/bin/gcloud"),
    )
    gcloud_script = fake_gcloud.parent / "gcloud"
    assert resolve_gcloud_path() == str(gcloud_script)


def test_resolve_trusted_gcloud_warns_on_stale_pin(
    fake_gcloud: Path,
    project_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_fingerprint_cache()
    monkeypatch.setattr(
        "gcpctx.gcloud_trust.load_settings",
        lambda: UserSettings(gcloud_path="/usr/bin/gcloud"),
    )
    gcloud_script = fake_gcloud.parent / "gcloud"
    result = resolve_trusted_gcloud(project_tree)
    assert result.path == str(gcloud_script.resolve())
    assert any(
        "Pinned gcloud_path '/usr/bin/gcloud' not found" in warning for warning in result.warnings
    )


def test_resolve_gcloud_path_fails_when_stale_pin_and_no_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "gcpctx.gcloud_trust.load_settings",
        lambda: UserSettings(gcloud_path="/usr/bin/gcloud"),
    )
    monkeypatch.setenv("PATH", "")
    with pytest.raises(GcloudNotFoundError, match="pinned gcloud_path '/usr/bin/gcloud' not found"):
        resolve_gcloud_path()
