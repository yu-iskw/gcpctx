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
"""gcpctx launcher / interpreter / package identity (ADR-0010)."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from gcpctx.errors import GcpctxTrustError
from gcpctx.fingerprint import fingerprint_file

if TYPE_CHECKING:
    from gcpctx.models import ApprovalRecord

_PACKAGE_NAME = "gcpctx"
_RECORD_FIELD_COUNT = 3


@dataclass(frozen=True, slots=True)
class GcpctxTrustResult:
    """Resolved gcpctx identity triple (path + SHA-256 per leg)."""

    launcher_path: str
    launcher_sha256: str | None
    python_path: str
    python_sha256: str | None
    package_path: str
    package_sha256: str | None


def resolved_launcher_path(argv0: str | None = None) -> Path:
    """Return the resolved console-script / wrapper path for this process."""
    raw = argv0 if argv0 is not None else sys.argv[0]
    path = Path(raw)
    if path.is_file():
        return path.resolve()
    found = shutil.which(path.name if not path.is_absolute() else str(path))
    if found:
        return Path(found).resolve()
    return path.resolve()


def _fingerprinted_path(path: Path, label: str) -> tuple[str, str]:
    digest = fingerprint_file(str(path))
    if digest is None:
        msg = f"could not fingerprint gcpctx {label} at {path}"
        raise GcpctxTrustError(msg)
    return str(path), digest


def _urlsafe_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"sha256={encoded}"


def _record_has_package_files(record_text: str) -> bool:
    for line in record_text.splitlines():
        parts = line.rsplit(",", 2)
        if len(parts) != _RECORD_FIELD_COUNT or not parts[1].startswith("sha256="):
            continue
        rel = parts[0]
        if rel == f"{_PACKAGE_NAME}/__init__.py" or rel.startswith(f"{_PACKAGE_NAME}/"):
            return True
    return False


def _verify_record_files(root: Path, record_text: str) -> None:
    for line in record_text.splitlines():
        if not line.strip():
            continue
        parts = line.rsplit(",", 2)
        if len(parts) != _RECORD_FIELD_COUNT or not parts[1]:
            continue
        rel = parts[0]
        hash_spec = parts[1]
        path = root / rel
        try:
            data = path.read_bytes()
        except OSError as exc:
            msg = f"gcpctx RECORD file missing: {rel}"
            raise GcpctxTrustError(msg) from exc
        if _urlsafe_sha256(data) != hash_spec:
            msg = f"gcpctx RECORD hash mismatch: {rel}"
            raise GcpctxTrustError(msg)


def hash_package_tree(package_dir: Path) -> str:
    """Return SHA-256 over sorted package ``*.py`` files (skip tests/pycache)."""
    hasher = hashlib.sha256()
    for path in sorted(package_dir.rglob("*.py")):
        if "__pycache__" in path.parts or "tests" in path.parts:
            continue
        rel = path.relative_to(package_dir).as_posix()
        hasher.update(rel.encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def _origin_package_identity(origin: Path) -> tuple[str, str]:
    resolved = origin.resolve()
    package_dir = resolved.parent if resolved.name == "__init__.py" else resolved
    if not package_dir.is_dir():
        msg = f"gcpctx package origin is not a directory: {package_dir}"
        raise GcpctxTrustError(msg)
    return str(resolved), hash_package_tree(package_dir)


def _installed_record_identity() -> tuple[str, str] | None:
    try:
        dist = importlib.metadata.distribution(_PACKAGE_NAME)
        record_text = dist.read_text("RECORD")
    except importlib.metadata.PackageNotFoundError:
        return None
    if not record_text or not _record_has_package_files(record_text):
        return None
    site = Path(str(dist.locate_file("")))
    _verify_record_files(site, record_text)
    record_path = Path(str(dist.locate_file("RECORD")))
    digest = hashlib.sha256(record_text.encode("utf-8")).hexdigest()
    return str(record_path), digest


def _injected_record_identity(record_text: str, record_root: Path) -> tuple[str, str]:
    if not _record_has_package_files(record_text):
        msg = "gcpctx RECORD does not list package files"
        raise GcpctxTrustError(msg)
    _verify_record_files(record_root, record_text)
    digest = hashlib.sha256(record_text.encode("utf-8")).hexdigest()
    return str((record_root / "RECORD").resolve()), digest


def _package_identity(
    *,
    package_origin: str | None,
    record_text: str | None,
    record_root: str | None,
) -> tuple[str, str]:
    if record_text is not None and record_root is not None:
        return _injected_record_identity(record_text, Path(record_root))
    origin_path = Path(package_origin) if package_origin is not None else None
    if origin_path is None:
        installed = _installed_record_identity()
        if installed is not None:
            return installed
        origin_path = Path(__file__).resolve().parent / "__init__.py"
    return _origin_package_identity(origin_path)


def fingerprint_gcpctx(
    *,
    argv0: str | None = None,
    executable: str | None = None,
    package_origin: str | None = None,
    record_text: str | None = None,
    record_root: str | None = None,
) -> GcpctxTrustResult:
    """Return the live gcpctx identity triple."""
    launcher_path, launcher_sha256 = _fingerprinted_path(
        resolved_launcher_path(argv0),
        "launcher",
    )
    python = Path(executable if executable is not None else sys.executable).resolve()
    python_path, python_sha256 = _fingerprinted_path(python, "interpreter")
    package_path, package_sha256 = _package_identity(
        package_origin=package_origin,
        record_text=record_text,
        record_root=record_root,
    )
    return GcpctxTrustResult(
        launcher_path=launcher_path,
        launcher_sha256=launcher_sha256,
        python_path=python_path,
        python_sha256=python_sha256,
        package_path=package_path,
        package_sha256=package_sha256,
    )


def approval_pin_fields(live: GcpctxTrustResult) -> dict[str, str | None]:
    """Return ApprovalRecord kwargs for the gcpctx triple."""
    return {
        "gcpctx_launcher_path": live.launcher_path,
        "gcpctx_launcher_sha256": live.launcher_sha256,
        "gcpctx_python_path": live.python_path,
        "gcpctx_python_sha256": live.python_sha256,
        "gcpctx_package_path": live.package_path,
        "gcpctx_package_sha256": live.package_sha256,
    }


def gcpctx_pin_mismatch_reason(
    record: ApprovalRecord,
    live: GcpctxTrustResult,
) -> str | None:
    """Return a short reason if stored pins do not match *live*, else None."""
    legs = (
        (
            "launcher",
            record.gcpctx_launcher_path,
            record.gcpctx_launcher_sha256,
            live.launcher_path,
            live.launcher_sha256,
        ),
        (
            "interpreter",
            record.gcpctx_python_path,
            record.gcpctx_python_sha256,
            live.python_path,
            live.python_sha256,
        ),
        (
            "package",
            record.gcpctx_package_path,
            record.gcpctx_package_sha256,
            live.package_path,
            live.package_sha256,
        ),
    )
    mismatches: list[str] = []
    for name, stored_path, stored_hash, live_path, live_hash in legs:
        if stored_path is None or stored_hash is None or live_hash is None:
            mismatches.append(f"{name}_missing")
        elif stored_path != live_path:
            mismatches.append(f"{name}_path")
        elif stored_hash != live_hash:
            mismatches.append(f"{name}_sha256")
    return mismatches[0] if mismatches else None


def gcpctx_pins_match(record: ApprovalRecord, live: GcpctxTrustResult) -> bool:
    """Return True when all three stored pins match *live*."""
    return gcpctx_pin_mismatch_reason(record, live) is None


def require_gcpctx_match(record: ApprovalRecord, live: GcpctxTrustResult) -> None:
    """Raise GcpctxTrustError when stored pins do not match *live*."""
    reason = gcpctx_pin_mismatch_reason(record, live)
    if reason is None:
        return
    msg = f"gcpctx identity does not match the stored approval pin ({reason})"
    raise GcpctxTrustError(msg)
