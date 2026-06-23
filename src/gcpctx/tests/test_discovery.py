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
"""Discovery tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gcpctx.discovery import find_project_root

if TYPE_CHECKING:
    from pathlib import Path


def test_find_nearest_parent(project_tree: Path) -> None:
    sub = project_tree / "src" / "app"
    assert find_project_root(sub) == project_tree


def test_not_found(tmp_path: Path) -> None:
    assert find_project_root(tmp_path) is None
