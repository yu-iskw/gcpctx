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
"""gcloud trust tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gcpctx.gcloud_trust import clear_fingerprint_cache, fingerprint_gcloud

if TYPE_CHECKING:
    from pathlib import Path


def test_fingerprint_gcloud_caches_until_content_changes(tmp_path: Path) -> None:
    clear_fingerprint_cache()
    binary = tmp_path / "gcloud"
    binary.write_bytes(b"fake-gcloud-binary")
    first = fingerprint_gcloud(str(binary))
    second = fingerprint_gcloud(str(binary))
    assert first is not None
    assert first == second

    binary.write_bytes(b"changed-binary")
    third = fingerprint_gcloud(str(binary))
    assert third is not None
    assert third != first
