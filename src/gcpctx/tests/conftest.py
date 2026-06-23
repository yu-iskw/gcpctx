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
"""Pytest fixtures."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

import gcpctx.gcloud as gcloud_mod
from gcpctx.gcloud_trust import GcloudTrustResult

if TYPE_CHECKING:
    from pathlib import Path

VALID_TOML = """\
version = 1
default_profile = "dev"

[profiles.dev]
project = "my-dev-project"
service_account = "agent-dev@my-dev-project.iam.gserviceaccount.com"
"""


@pytest.fixture(autouse=True)
def _isolated_gcpctx_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Route gcpctx state under tmp_path with safe permissions."""
    cache = tmp_path / "cache" / "gcpctx"
    config = tmp_path / "config" / "gcpctx"
    cache.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    cache.chmod(0o700)
    config.chmod(0o700)
    monkeypatch.setattr("gcpctx.paths.user_cache_path", lambda: cache)
    monkeypatch.setattr("gcpctx.paths.user_config_path", lambda: config)
    monkeypatch.setattr("gcpctx.paths.context_base_dir", lambda: cache / "contexts")
    monkeypatch.setattr("gcpctx.paths.approvals_file", lambda: config / "approvals.json")
    monkeypatch.setattr("gcpctx.audit.log_event", lambda *_args, **_kwargs: None)


@pytest.fixture(autouse=True)
def _permissive_gcloud_trust(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept the fake gcloud binary in tests without host-specific trust failures."""

    def _trust(
        cwd: Path,
        policy: object = None,
        *,
        strict: bool | None = None,
    ) -> GcloudTrustResult:
        del cwd, policy, strict
        return GcloudTrustResult(path="/usr/bin/gcloud", sha256="test" * 8)

    monkeypatch.setattr("gcpctx.activation.resolve_trusted_gcloud", _trust)
    monkeypatch.setattr("gcpctx.doctor.resolve_trusted_gcloud", _trust)
    monkeypatch.setattr("gcpctx.cli.resolve_trusted_gcloud", _trust)


@pytest.fixture
def project_tree(tmp_path: Path) -> Path:
    """Create a temp project with .gcpctx.toml."""
    root = tmp_path / "repo"
    root.mkdir()
    config = root / ".gcpctx.toml"
    config.write_text(VALID_TOML, encoding="utf-8")
    config.chmod(0o600)
    sub = root / "src" / "app"
    sub.mkdir(parents=True)
    return root


@pytest.fixture
def fake_gcloud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Install a fake gcloud script that logs invocations."""
    gcloud_mod.clear_gcloud_cache()
    log_file = tmp_path / "gcloud.jsonl"
    script = tmp_path / "gcloud"
    script.write_text(
        f"""#!/usr/bin/env python3
import json, os, sys
entry = {{
    "argv": sys.argv[1:],
    "CLOUDSDK_CONFIG": os.environ.get("CLOUDSDK_CONFIG"),
    "has_gac": "GOOGLE_APPLICATION_CREDENTIALS" in os.environ,
    "marker": os.environ.get("GCPCTX_TEST_MARKER"),
}}
with open({str(log_file)!r}, "a") as f:
    f.write(json.dumps(entry) + "\\n")
if len(sys.argv) > 2 and sys.argv[1:3] == ["config", "get-value"]:
    prop = sys.argv[3]
    if prop == "project":
        print("my-dev-project")
    elif prop == "auth/impersonate_service_account":
        print("agent-dev@my-dev-project.iam.gserviceaccount.com")
    sys.exit(0)
if sys.argv[1:4] == ["auth", "application-default", "print-access-token"]:
    print("fake-token")
    sys.exit(0)
sys.exit(0)
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    path_env = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{tmp_path}:{path_env}")
    monkeypatch.setenv("GCPCTX_TEST_GCLOUD_LOG", str(log_file))
    return log_file
