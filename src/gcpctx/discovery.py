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
"""Discover .gcpctx.toml by walking upward from cwd."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

CONFIG_FILENAME = ".gcpctx.toml"


def find_project_root(cwd: Path) -> Path | None:
    """Walk parents from *cwd* until `.gcpctx.toml` is found.

    Returns the directory containing the config file, or None.
    """
    current = cwd.resolve()
    for directory in (current, *current.parents):
        if (directory / CONFIG_FILENAME).is_file():
            return directory
    return None


def config_path(root: Path) -> Path:
    """Return the config file path for a project root."""
    return root / CONFIG_FILENAME
