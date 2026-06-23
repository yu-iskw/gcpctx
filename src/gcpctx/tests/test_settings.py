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
from gcpctx.settings import UserSettings, load_settings, save_settings


def test_save_settings_escapes_special_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings_path = paths.user_config_path() / "settings.toml"
    monkeypatch.setattr("gcpctx.settings.settings_file", lambda: settings_path)

    path_value = '/tmp/gcloud-"x"\\line\nextra'
    save_settings(UserSettings(gcloud_path=path_value))

    raw = tomllib.loads(settings_path.read_text(encoding="utf-8"))
    assert raw["gcloud_path"] == path_value
    assert load_settings().gcloud_path == path_value
