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
from typing import TYPE_CHECKING, Literal

import tomli_w
from pydantic import BaseModel, ConfigDict, ValidationError

from gcpctx import paths
from gcpctx.errors import SettingsViolationError
from gcpctx.security import ensure_dir, ensure_managed_file, secure_read_text

if TYPE_CHECKING:
    from pathlib import Path


class SettingsFile(BaseModel):
    """Schema for settings.toml."""

    model_config = ConfigDict(extra="ignore", strict=True)

    version: Literal[1, 2]


@dataclass(frozen=True)
class UserSettings:
    """User-level gcpctx settings."""


def settings_file() -> Path:
    return paths.user_config_path() / "settings.toml"


def load_settings() -> UserSettings:
    path = settings_file()
    if not path.is_file():
        return UserSettings()
    try:
        raw = tomllib.loads(secure_read_text(path))
    except tomllib.TOMLDecodeError as exc:
        msg = f"settings {path}: invalid TOML: {exc}"
        raise SettingsViolationError(msg) from exc
    try:
        SettingsFile.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors()
        detail = errors[0]["msg"] if errors else "validation failed"
        msg = f"settings {path}: invalid schema: {detail}"
        raise SettingsViolationError(msg) from exc
    return UserSettings()


def save_settings(settings: UserSettings) -> None:
    del settings
    ensure_dir(settings_file().parent)
    payload: dict[str, object] = {"version": 1}
    ensure_managed_file(settings_file(), tomli_w.dumps(payload))


def deprecated_global_gcloud_path() -> str | None:
    """Return gcloud_path from settings.toml if present (deprecated)."""
    path = settings_file()
    if not path.is_file():
        return None
    try:
        raw = tomllib.loads(secure_read_text(path))
    except tomllib.TOMLDecodeError:
        return None
    value = raw.get("gcloud_path")
    return value if isinstance(value, str) else None
