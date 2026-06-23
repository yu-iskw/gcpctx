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
"""External toolchain resolution (mise, etc.)."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404

from gcpctx.errors import GcloudNotFoundError


def resolve_mise_gcloud_path() -> str:
    """Return the real gcloud binary path from mise (not the shim)."""
    mise = shutil.which("mise")
    if mise is None:
        msg = "mise not found on PATH"
        raise GcloudNotFoundError(msg)
    try:
        result = subprocess.run(  # noqa: S603
            [mise, "which", "gcloud"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"failed to run mise which gcloud: {exc}"
        raise GcloudNotFoundError(msg) from exc
    if result.returncode != 0:
        msg = "gcloud not found in mise toolchain (run mise install / mise use gcloud@...)"
        raise GcloudNotFoundError(msg)
    path = result.stdout.strip()
    if not path:
        msg = "mise which gcloud returned empty output"
        raise GcloudNotFoundError(msg)
    return path
