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
"""gcloud binary trust validation."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from gcpctx.errors import GcloudNotFoundError, GcloudTrustError
from gcpctx.policy import SecurityPolicy, load_policy, matches_allowlist
from gcpctx.settings import load_settings

_FINGERPRINT_CACHE: dict[str, tuple[int, int, str]] = {}


@dataclass(frozen=True)
class GcloudTrustResult:
    """Resolved and validated gcloud binary metadata."""

    path: str
    sha256: str | None
    warnings: tuple[str, ...] = ()


def resolve_gcloud_path() -> str:
    """Resolve gcloud path from user settings or PATH."""
    configured = load_settings().gcloud_path
    if configured:
        return configured
    path = shutil.which("gcloud")
    if path is None:
        msg = "gcloud not found on PATH"
        raise GcloudNotFoundError(msg)
    return path


def resolve_trusted_gcloud(
    cwd: Path,
    policy: SecurityPolicy | None = None,
    *,
    strict: bool | None = None,
) -> GcloudTrustResult:
    """Resolve and validate the gcloud binary for *cwd*."""
    active_policy = policy or load_policy()
    effective_strict = active_policy.strict if strict is None else strict
    return validate_gcloud_path(
        resolve_gcloud_path(),
        cwd=cwd,
        policy=active_policy,
        strict=effective_strict,
    )


def fingerprint_gcloud(path: str) -> str | None:  # noqa: PLR0911
    """Return SHA-256 hex digest of the gcloud binary, if readable."""
    resolved = Path(path)
    try:
        stat_result = resolved.stat()
    except OSError:
        return None
    cache_key = str(resolved)
    cached = _FINGERPRINT_CACHE.get(cache_key)
    if cached and cached[0] == stat_result.st_size and cached[1] == stat_result.st_mtime_ns:
        return cached[2]
    try:
        data = resolved.read_bytes()
    except OSError:
        return None
    digest = hashlib.sha256(data).hexdigest()
    _FINGERPRINT_CACHE[cache_key] = (stat_result.st_size, stat_result.st_mtime_ns, digest)
    return digest


def clear_fingerprint_cache() -> None:
    """Reset cached fingerprints (for tests)."""
    _FINGERPRINT_CACHE.clear()


def validate_gcloud_path(
    path: str,
    *,
    cwd: Path,
    policy: SecurityPolicy,
    strict: bool = False,
) -> GcloudTrustResult:
    """Validate gcloud binary trust boundaries."""
    resolved = Path(path).resolve()
    if not resolved.is_file():
        msg = f"gcloud binary not found: {path}"
        raise GcloudTrustError(msg)
    if not os.access(resolved, os.X_OK):
        msg = f"gcloud binary is not executable: {resolved}"
        raise GcloudTrustError(msg)

    warnings: list[str] = []
    gcloud_policy = policy.gcloud
    effective_strict = strict or policy.strict

    if gcloud_policy.allowed_paths and not matches_allowlist(
        str(resolved), gcloud_policy.allowed_paths
    ):
        msg = f"gcloud path {resolved} is not in policy allowed_paths"
        raise GcloudTrustError(msg)

    _reject_gcloud_under_cwd(resolved, cwd)
    _reject_world_writable_parents(resolved, gcloud_policy.deny_world_writable_parent)
    warnings.extend(_owner_warnings(resolved, effective_strict))

    digest = fingerprint_gcloud(str(resolved))
    if digest is None:
        message = f"could not fingerprint gcloud binary at {resolved}"
        if effective_strict:
            raise GcloudTrustError(message)
        warnings.append(message)

    return GcloudTrustResult(path=str(resolved), sha256=digest, warnings=tuple(warnings))


def _reject_gcloud_under_cwd(resolved: Path, cwd: Path) -> None:
    cwd_resolved = cwd.resolve()
    try:
        under_cwd = resolved.is_relative_to(cwd_resolved)
    except AttributeError:
        under_cwd = str(resolved).startswith(f"{cwd_resolved}{os.sep}")
    if under_cwd:
        msg = f"gcloud binary must not live under project directory: {resolved}"
        raise GcloudTrustError(msg)


def _reject_world_writable_parents(resolved: Path, enabled: bool) -> None:
    if not enabled:
        return
    parent = resolved.parent
    while True:
        try:
            mode = parent.stat().st_mode
        except OSError:
            break
        if mode & stat.S_IWOTH:
            msg = f"gcloud path has world-writable parent directory: {parent}"
            raise GcloudTrustError(msg)
        if parent == parent.parent:
            break
        parent = parent.parent


def _owner_warnings(resolved: Path, strict: bool) -> list[str]:
    try:
        owner = resolved.stat().st_uid
    except OSError:
        return []
    if owner in {0, os.getuid()}:
        return []
    message = f"gcloud binary owned by uid {owner}, expected current user or root"
    if strict:
        raise GcloudTrustError(message)
    return [message]
