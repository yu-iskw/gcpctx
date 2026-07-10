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
"""Deterministic context ID derivation (pure; caller supplies resolved root)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

SCHEMA_VERSION = "schema-v1"


@dataclass(frozen=True)
class ContextIdInput:
    """Inputs for context ID derivation.

    ``root`` must already be a resolved absolute path string; this module does
    not call ``Path.resolve()``.
    """

    root: str
    profile: str
    project: str
    service_account: str
    config_sha256: str


def derive_context_id(input_: ContextIdInput) -> str:
    """Return deterministic 24-char hex context ID."""
    payload = "\0".join(
        [
            input_.root,
            input_.profile,
            input_.project,
            input_.service_account,
            input_.config_sha256,
            SCHEMA_VERSION,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
