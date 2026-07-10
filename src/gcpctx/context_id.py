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
"""Deterministic context ID derivation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from gcpctx.core import identity as core_identity

if TYPE_CHECKING:
    from pathlib import Path

SCHEMA_VERSION = core_identity.SCHEMA_VERSION


@dataclass(frozen=True)
class ContextIdInput:
    """Inputs for context ID derivation (Path root for backward compatibility)."""

    root: Path
    profile: str
    project: str
    service_account: str
    config_sha256: str


def derive_context_id(input_: ContextIdInput) -> str:
    """Return deterministic 24-char hex context ID."""
    return core_identity.derive_context_id(
        core_identity.ContextIdInput(
            root=str(input_.root.resolve()),
            profile=input_.profile,
            project=input_.project,
            service_account=input_.service_account,
            config_sha256=input_.config_sha256,
        )
    )
