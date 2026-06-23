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
"""Context ID tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gcpctx.context_id import ContextIdInput, derive_context_id

if TYPE_CHECKING:
    from pathlib import Path


CONTEXT_ID_HEX_LENGTH = 24


def test_deterministic(project_tree: Path) -> None:
    inp = ContextIdInput(
        root=project_tree,
        profile="dev",
        project="my-dev-project",
        service_account="agent-dev@my-dev-project.iam.gserviceaccount.com",
        config_sha256="abc",
    )
    assert derive_context_id(inp) == derive_context_id(inp)
    assert len(derive_context_id(inp)) == CONTEXT_ID_HEX_LENGTH


def test_changes_with_service_account(project_tree: Path) -> None:
    base = ContextIdInput(
        root=project_tree,
        profile="dev",
        project="my-dev-project",
        service_account="agent-dev@my-dev-project.iam.gserviceaccount.com",
        config_sha256="abc",
    )
    other = ContextIdInput(
        root=project_tree,
        profile="dev",
        project="my-dev-project",
        service_account="other@my-dev-project.iam.gserviceaccount.com",
        config_sha256="abc",
    )
    assert derive_context_id(base) != derive_context_id(other)
