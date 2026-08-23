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
"""gcpctx identity pin tests (ADR-0010)."""

from __future__ import annotations

import base64
import hashlib
from typing import TYPE_CHECKING

import pytest

from gcpctx.errors import GcpctxTrustError
from gcpctx.fingerprint import clear_fingerprint_cache
from gcpctx.gcpctx_trust import fingerprint_gcpctx, hash_package_tree

if TYPE_CHECKING:
    from pathlib import Path


def _urlsafe_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"sha256={encoded}"


def test_package_tree_hash_changes_when_module_swapped(tmp_path: Path) -> None:
    package = tmp_path / "gcpctx"
    package.mkdir()
    (package / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    cli = package / "cli.py"
    cli.write_text("def app() -> None:\n    return None\n", encoding="utf-8")
    first = hash_package_tree(package)
    cli.write_text("def app() -> None:\n    raise RuntimeError('swapped')\n", encoding="utf-8")
    assert hash_package_tree(package) != first


def test_record_verify_detects_swapped_package_file(tmp_path: Path) -> None:
    clear_fingerprint_cache()
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"wrapper")
    python = tmp_path / "python"
    python.write_bytes(b"interpreter")
    package = tmp_path / "gcpctx"
    package.mkdir()
    init = package / "__init__.py"
    original = b"original-module\n"
    init.write_bytes(original)
    record = (
        f"gcpctx/__init__.py,{_urlsafe_sha256(original)},{len(original)}\nRECORD,,\n"
    )
    (tmp_path / "RECORD").write_text(record, encoding="utf-8")
    result = fingerprint_gcpctx(
        argv0=str(launcher),
        executable=str(python),
        record_text=record,
        record_root=str(tmp_path),
    )
    assert result.package_sha256 == hashlib.sha256(record.encode("utf-8")).hexdigest()

    init.write_bytes(b"swapped-module\n")
    with pytest.raises(GcpctxTrustError, match="RECORD hash mismatch"):
        fingerprint_gcpctx(
            argv0=str(launcher),
            executable=str(python),
            record_text=record,
            record_root=str(tmp_path),
        )


def test_origin_fallback_when_injected(tmp_path: Path) -> None:
    clear_fingerprint_cache()
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"wrapper")
    python = tmp_path / "python"
    python.write_bytes(b"interpreter")
    package = tmp_path / "gcpctx"
    package.mkdir()
    origin = package / "__init__.py"
    origin.write_text("from gcpctx.cli import app\n", encoding="utf-8")
    result = fingerprint_gcpctx(
        argv0=str(launcher),
        executable=str(python),
        package_origin=str(origin),
    )
    assert result.package_path == str(origin.resolve())
    assert result.package_sha256 == hash_package_tree(package)
    assert result.launcher_sha256 is not None
    assert result.python_sha256 is not None
