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
"""Filesystem paths for gcpctx state."""

from __future__ import annotations

from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir

APP_NAME = "gcpctx"
APP_AUTHOR = "yu-iskw"


def user_config_path() -> Path:
    """Return ~/.config/gcpctx (or platform equivalent)."""
    return Path(user_config_dir(APP_NAME, appauthor=APP_AUTHOR))


def user_cache_path() -> Path:
    """Return ~/.cache/gcpctx (or platform equivalent)."""
    return Path(user_cache_dir(APP_NAME, appauthor=APP_AUTHOR))


def approvals_file() -> Path:
    """Path to approvals.json."""
    return user_config_path() / "approvals.json"


def context_base_dir() -> Path:
    """Base directory for isolated contexts."""
    return user_cache_path() / "contexts"


def context_dir(context_id: str) -> Path:
    """Directory for a single context."""
    return context_base_dir() / context_id


def cloudsdk_config_dir(context_id: str) -> Path:
    """Isolated CLOUDSDK_CONFIG directory."""
    return context_dir(context_id) / "gcloud"


def context_state_file(context_id: str) -> Path:
    """state.json for a context."""
    return context_dir(context_id) / "state.json"
