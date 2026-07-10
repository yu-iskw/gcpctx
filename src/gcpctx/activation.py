# Copyright 2025 yu-iskw
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Activation orchestration."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from gcpctx.models import ActivationResult

if TYPE_CHECKING:
    from gcpctx.models import ActivationRequest


def missing_config_result() -> ActivationResult:
    """When no .gcpctx.toml: deactivate if active, else emit no-op shell code."""
    if os.environ.get("GCPCTX_ACTIVE") == "1":
        return ActivationResult(active=False, readiness="blocked")
    return ActivationResult(active=False, noop=True, readiness="blocked")


def activate(request: ActivationRequest) -> ActivationResult:
    """Activate gcpctx for the given request."""
    # Deferred import: package __init__ loads activation; wiring imports Engine.
    from gcpctx.interfaces.wiring import default_engine  # noqa: PLC0415

    engine = default_engine(interactive=request.interactive)
    return engine.activate(request)


def deactivate() -> ActivationResult:
    """Return deactivation result."""
    return ActivationResult(active=False, readiness="blocked")


def child_environ(
    result: ActivationResult,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build subprocess environment from activation exports and unsets."""
    env = (base or os.environ).copy()
    for key in result.unsets:
        env.pop(key, None)
    env.update(result.exports)
    return env
