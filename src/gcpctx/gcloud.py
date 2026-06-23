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
"""Google Cloud SDK subprocess integration."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from gcpctx.errors import GcloudCommandError
from gcpctx.gcloud_trust import resolve_gcloud_path
from gcpctx.models import ContextState, ProfileConfig
from gcpctx.paths import cloudsdk_config_dir, context_state_file
from gcpctx.security import ensure_dir, ensure_managed_file, secure_read_text
from gcpctx.timeutil import utc_now_iso

if TYPE_CHECKING:
    from pathlib import Path

DEBOUNCE_SECONDS = 60
_GCLOUD_PATH: str | None = None
_SUBPROCESS_TIMEOUT_SECONDS = 120


def find_gcloud() -> str:
    """Return path to gcloud executable (resolved, optionally cached)."""
    global _GCLOUD_PATH  # noqa: PLW0603
    if _GCLOUD_PATH is None:
        _GCLOUD_PATH = resolve_gcloud_path()
    return _GCLOUD_PATH


def clear_gcloud_cache() -> None:
    """Reset cached gcloud path (for tests)."""
    global _GCLOUD_PATH  # noqa: PLW0603
    _GCLOUD_PATH = None


def _cloudsdk_env(cloudsdk_config: Path, extra_env: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
    env["CLOUDSDK_CONFIG"] = str(cloudsdk_config)
    if extra_env:
        env.update(extra_env)
    return env


def run_gcloud(
    args: list[str],
    *,
    cloudsdk_config: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run gcloud with isolated CLOUDSDK_CONFIG."""
    gcloud = find_gcloud()
    env = _cloudsdk_env(cloudsdk_config, extra_env)
    result = subprocess.run(
        [gcloud, *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        joined_args = " ".join(args)
        msg = f"gcloud {joined_args} failed: {stderr}"
        raise GcloudCommandError(msg)
    return result


@dataclass(frozen=True)
class InitContext:
    """Inputs required to initialize an isolated gcloud context."""

    context_id: str
    root: Path
    profile_name: str
    profile: ProfileConfig
    config_sha256: str
    force: bool = False


def ensure_initialized(ctx: InitContext) -> ContextState:
    """Initialize isolated gcloud config and ADC if needed."""
    config_dir = cloudsdk_config_dir(ctx.context_id)
    ensure_dir(config_dir.parent)
    ensure_dir(config_dir)

    state_path = context_state_file(ctx.context_id)
    if not ctx.force:
        cached = _load_cached_state(state_path, ctx.config_sha256, ctx.profile)
        if cached is not None:
            return _touch_state_checked(state_path, cached)

    run_gcloud(["config", "set", "project", ctx.profile.project], cloudsdk_config=config_dir)
    run_gcloud(
        ["config", "set", "auth/impersonate_service_account", ctx.profile.service_account],
        cloudsdk_config=config_dir,
    )
    if ctx.profile.region:
        run_gcloud(
            ["config", "set", "compute/region", ctx.profile.region],
            cloudsdk_config=config_dir,
        )
    if ctx.profile.zone:
        run_gcloud(
            ["config", "set", "compute/zone", ctx.profile.zone],
            cloudsdk_config=config_dir,
        )

    run_gcloud(
        [
            "auth",
            "application-default",
            "login",
            "--impersonate-service-account",
            ctx.profile.service_account,
        ],
        cloudsdk_config=config_dir,
        extra_env={"CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
    )

    if ctx.profile.quota_project:
        run_gcloud(
            ["auth", "application-default", "set-quota-project", ctx.profile.quota_project],
            cloudsdk_config=config_dir,
        )

    now = utc_now_iso()
    state = ContextState(
        root=str(ctx.root.resolve()),
        profile=ctx.profile_name,
        project=ctx.profile.project,
        service_account=ctx.profile.service_account,
        quota_project=ctx.profile.quota_project,
        config_sha256=ctx.config_sha256,
        last_checked_at=now,
        last_initialized_at=now,
    )
    ensure_managed_file(state_path, state.model_dump_json(indent=2))
    return state


def read_gcloud_property(cloudsdk_config: Path, prop: str) -> str | None:
    """Read a gcloud config property value."""
    try:
        result = run_gcloud(
            ["config", "get-value", prop],
            cloudsdk_config=cloudsdk_config,
        )
    except GcloudCommandError:
        return None
    value = result.stdout.strip()
    return value if value and value != "(unset)" else None


def adc_exists(cloudsdk_config: Path) -> bool:
    """Return True if ADC credentials file exists for this config."""
    return (cloudsdk_config / "application_default_credentials.json").is_file()


def reset_context(context_id: str) -> None:
    """Delete isolated context directory."""
    context_dir = cloudsdk_config_dir(context_id).parent
    if context_dir.exists():
        shutil.rmtree(context_dir)


def _load_cached_state(
    state_path: Path,
    config_sha256: str,
    profile: ProfileConfig,
) -> ContextState | None:
    if not state_path.is_file():
        return None
    state = _read_state_file(state_path)
    if state is None or not _state_matches_profile(state, config_sha256, profile):
        return None
    config_dir = state_path.parent / "gcloud"
    return state if adc_exists(config_dir) else None


def _read_state_file(state_path: Path) -> ContextState | None:
    try:
        return ContextState.model_validate_json(secure_read_text(state_path))
    except (json.JSONDecodeError, ValueError, OSError):
        return None


def _state_matches_profile(
    state: ContextState,
    config_sha256: str,
    profile: ProfileConfig,
) -> bool:
    if state.config_sha256 != config_sha256:
        return False
    return state.project == profile.project and state.service_account == profile.service_account


def _touch_state_checked(state_path: Path, state: ContextState) -> ContextState:
    checked = datetime.fromisoformat(state.last_checked_at)
    if datetime.now(tz=UTC) - checked <= timedelta(seconds=DEBOUNCE_SECONDS):
        return state
    updated = state.model_copy(update={"last_checked_at": utc_now_iso()})
    ensure_managed_file(state_path, updated.model_dump_json(indent=2))
    return updated
