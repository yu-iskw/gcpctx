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
"""User settings tests."""

from __future__ import annotations

import tomllib

import pytest

from gcpctx import paths
from gcpctx.settings import (
    UserSettings,
    deprecated_global_gcloud_path,
    load_settings,
    save_settings,
)


def test_save_settings_writes_version_only(monkeypatch: pytest.MonkeyPatch) -> None:
    settings_path = paths.user_config_path() / "settings.toml"
    monkeypatch.setattr("gcpctx.settings.settings_file", lambda: settings_path)

    save_settings(UserSettings())

    raw = tomllib.loads(settings_path.read_text(encoding="utf-8"))
    assert raw == {"version": 1}
    assert load_settings() == UserSettings()


def test_load_settings_ignores_unknown_keys_and_accepts_version_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = paths.user_config_path() / "settings.toml"
    monkeypatch.setattr("gcpctx.settings.settings_file", lambda: settings_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        'version = 2\ngcloud_path = "/opt/gcloud"\nextra = true\n', encoding="utf-8"
    )
    settings_path.chmod(0o600)

    assert load_settings() == UserSettings()
    assert deprecated_global_gcloud_path() == "/opt/gcloud"
