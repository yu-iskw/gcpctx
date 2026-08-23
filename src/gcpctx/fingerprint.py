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
"""SHA-256 file fingerprints with mtime/size cache."""

from __future__ import annotations

import hashlib
from pathlib import Path

_FINGERPRINT_CACHE: dict[str, tuple[int, int, str]] = {}


def fingerprint_file(path: str) -> str | None:
    """Return SHA-256 hex digest of *path*, if readable."""
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
