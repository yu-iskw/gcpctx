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
"""System adapters: env, clock, prompter, audit sink."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from rich.console import Console

from gcpctx import paths
from gcpctx.errors import ApprovalRequiredError
from gcpctx.ports import ApprovalAnswer, ApprovalRequest
from gcpctx.security import FILE_MODE, ensure_dir, file_lock, is_posix_platform, reject_symlink
from gcpctx.timeutil import utc_now_iso

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class OsEnvPort:
    """Read-only view of ``os.environ``."""

    def get(self, name: str) -> str | None:
        return os.environ.get(name)

    def snapshot(self) -> Mapping[str, str]:
        return dict(os.environ)


class SystemClock:
    """Wall-clock UTC time."""

    def now(self) -> datetime:
        return datetime.now(tz=UTC)


class NullPrompter:
    """Fail-closed prompter for non-interactive / agent modes."""

    def confirm(self, request: ApprovalRequest) -> ApprovalAnswer:
        del request
        msg = "approval required for activation (non-interactive mode)"
        raise ApprovalRequiredError(msg)


class RichPrompter:
    """TTY approval UI extracted from the historical approvals prompt."""

    def __init__(self, *, console: Console | None = None) -> None:
        self._console = console or Console(stderr=True)

    def confirm(self, request: ApprovalRequest) -> ApprovalAnswer:
        console = self._console
        console.print("\n[bold]gcpctx wants to activate this Google Cloud context:[/bold]\n")
        console.print(f"Directory:        {request.root}")
        console.print(f"Profile:          {request.profile}")
        console.print(f"Project:          {request.project}")
        console.print(f"Service account:  {request.service_account}")
        console.print(f"Config SHA-256:   {request.config_sha256[:12]}...")
        console.print(f"CLOUDSDK_CONFIG:  {request.cloudsdk_config}")
        self._print_optional_details(console, request)
        console.print("\nApprove this directory/profile/service-account binding?\n")
        console.print("[A] Approve once  [R] Remember approval  [D] Deny")
        return self._read_choice(console)

    def _print_optional_details(self, console: Console, request: ApprovalRequest) -> None:  # noqa: PLR0912
        if request.quota_project:
            console.print(f"Quota project:    {request.quota_project}")
        if request.env_keys:
            console.print(f"Env overrides:    {', '.join(request.env_keys)}")
        if request.gcloud_path is not None:
            fp = request.gcloud_sha256[:12] if request.gcloud_sha256 else "unavailable"
            console.print(f"gcloud path:      {request.gcloud_path}")
            console.print(f"gcloud SHA-256:   {fp}...")
        if request.sa_project_mismatch is not None:
            console.print(
                f"[yellow]Warning: service account project {request.sa_project_mismatch!r} "
                f"differs from profile project {request.project!r}[/yellow]"
            )
        if request.git_remote:
            console.print(f"Git remote:       {request.git_remote}")
        if request.git_branch:
            console.print(f"Git branch:       {request.git_branch}")
        if request.approval_ttl_days:
            expiry = (datetime.now(tz=UTC) + timedelta(days=request.approval_ttl_days)).date()
            console.print(f"Remember until:   {expiry} ({request.approval_ttl_days} days)")

    def _read_choice(self, console: Console) -> ApprovalAnswer:
        while True:
            choice = console.input("[bold cyan]Choice[/bold cyan] (A/R/D): ").strip().upper()
            if choice == "D":
                return ApprovalAnswer(decision="deny")
            if choice == "A":
                return ApprovalAnswer(decision="once")
            if choice == "R":
                return ApprovalAnswer(decision="remembered")
            console.print("Invalid choice. Enter A, R, or D.")


class FileAuditSink:
    """Append-only JSONL audit log under the user config directory."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path

    def _audit_path(self) -> Path:
        return self._path if self._path is not None else paths.user_config_path() / "audit.jsonl"

    def emit(self, event: str, **fields: object) -> None:
        path = self._audit_path()
        ensure_dir(path.parent)
        record = {"ts": utc_now_iso(), "event": event, **fields}
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with file_lock(path):
            reject_symlink(path)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(path, flags, FILE_MODE)
            handed_off = False
            try:
                if is_posix_platform():
                    os.fchmod(fd, FILE_MODE)
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    handed_off = True
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                if not handed_off:
                    os.close(fd)
                raise
