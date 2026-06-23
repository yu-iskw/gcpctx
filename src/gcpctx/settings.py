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
"""User settings persisted under ~/.config/gcpctx."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from typing import TYPE_CHECKING

import tomli_w

from gcpctx import paths
from gcpctx.security import ensure_dir, ensure_managed_file, secure_read_text

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class UserSettings:
    """User-level gcpctx settings."""

    gcloud_path: str | None = None


def settings_file() -> Path:
    return paths.user_config_path() / "settings.toml"


def load_settings() -> UserSettings:
    path = settings_file()
    if not path.is_file():
        return UserSettings()
    raw = tomllib.loads(secure_read_text(path))
    gcloud_path = raw.get("gcloud_path")
    if gcloud_path is not None and not isinstance(gcloud_path, str):
        gcloud_path = None
    return UserSettings(gcloud_path=gcloud_path)


def save_settings(settings: UserSettings) -> None:
    ensure_dir(settings_file().parent)
    payload: dict[str, object] = {"version": 1}
    if settings.gcloud_path:
        payload["gcloud_path"] = settings.gcloud_path
    ensure_managed_file(settings_file(), tomli_w.dumps(payload))
