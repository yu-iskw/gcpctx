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
"""Diagnostics: status and doctor."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from gcpctx import gcloud as gcloud_mod
from gcpctx.approvals import find_matching_approval
from gcpctx.discovery import find_project_root
from gcpctx.errors import ConfigNotFoundError, GcpctxError
from gcpctx.models import DoctorCheck, DoctorResult, ProfileConfig
from gcpctx.paths import user_cache_path
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context

CheckStatus = Literal["ok", "warning", "error"]


@dataclass
class _CheckCollector:
    """Accumulates doctor checks and computes exit status."""

    interactive: bool
    checks: list[DoctorCheck] = field(default_factory=list)
    exit_code: int = 0

    def add(
        self,
        name: str,
        status: CheckStatus,
        message: str,
        remediation: str | None = None,
    ) -> None:
        self.checks.append(
            DoctorCheck(name=name, status=status, message=message, remediation=remediation)
        )
        if status == "error" or (status == "warning" and not self.interactive):
            self.exit_code = max(self.exit_code, _severity_exit(name))

    def result(self) -> DoctorResult:
        return DoctorResult(checks=self.checks, exit_code=self.exit_code)


def run_doctor(
    cwd: Path,
    *,
    profile: str | None = None,
    interactive: bool | None = None,
) -> DoctorResult:
    """Run diagnostic checks and return aggregated result."""
    is_interactive = sys.stdin.isatty() if interactive is None else interactive
    collector = _CheckCollector(interactive=is_interactive)
    _check_gcloud(collector)
    try:
        ctx = resolve_project_context(cwd, profile)
    except ConfigNotFoundError:
        collector.add("config", "error", ".gcpctx.toml not found", "Run gcpctx init-project")
        return DoctorResult(checks=collector.checks, exit_code=collector.exit_code or 2)
    except GcpctxError as exc:
        collector.add("config", "error", str(exc))
        return DoctorResult(checks=collector.checks, exit_code=collector.exit_code or 2)

    collector.add("config", "ok", f"Configuration valid at {ctx.root}")
    collector.add("profile", "ok", f"Profile {ctx.profile_name!r} resolved")
    _check_approval(collector, ctx)
    cloudsdk = os.environ.get("CLOUDSDK_CONFIG", "")
    _check_isolation(collector, cloudsdk)
    if cloudsdk:
        _check_gcloud_state(collector, Path(cloudsdk), ctx.profile, is_interactive)
    _check_gac(collector, is_interactive)
    return collector.result()


def status_info(cwd: Path) -> dict[str, str]:
    """Return status fields for display."""
    if os.environ.get("GCPCTX_ACTIVE") != "1":
        return {"active": "false"}

    info: dict[str, str] = {
        "active": "true",
        "root": os.environ.get("GCPCTX_ROOT", ""),
        "profile": os.environ.get("GCPCTX_PROFILE", ""),
        "project": os.environ.get("GCPCTX_PROJECT", ""),
        "service_account": os.environ.get("GCPCTX_SERVICE_ACCOUNT", ""),
        "cloudsdk_config": os.environ.get("CLOUDSDK_CONFIG", ""),
    }

    root = find_project_root(cwd)
    if root:
        info["approval"] = _approval_status(root, info)

    cloudsdk = info.get("cloudsdk_config", "")
    if cloudsdk:
        info["adc"] = "initialized" if gcloud_mod.adc_exists(Path(cloudsdk)) else "missing"
    return info


def _check_approval(collector: _CheckCollector, ctx: ResolvedProjectContext) -> None:
    approval = find_matching_approval(ctx)
    if approval is None:
        status: CheckStatus = "warning" if collector.interactive else "error"
        collector.add(
            "approval",
            status,
            "No matching approval",
            "Run gcpctx approve or activate interactively",
        )
        return
    collector.add("approval", "ok", f"Approval found ({approval.mode})")


def _check_isolation(collector: _CheckCollector, cloudsdk: str) -> None:
    cache = user_cache_path().resolve()
    if cloudsdk:
        try:
            config_path = Path(cloudsdk).resolve()
        except OSError:
            config_path = None
        if config_path is not None and config_path.is_relative_to(cache):
            collector.add("isolation", "ok", f"CLOUDSDK_CONFIG is isolated: {cloudsdk}")
            return
    cloudsdk_display = cloudsdk or "(unset)"
    collector.add(
        "isolation",
        "error",
        f"CLOUDSDK_CONFIG not under gcpctx cache (ADR-0003): {cloudsdk_display}",
        remediation='eval "$(gcpctx activate --shell zsh)"',
    )


def _check_gcloud_state(
    collector: _CheckCollector,
    config_path: Path,
    prof: ProfileConfig,
    interactive: bool,
) -> None:
    _check_gcloud_project(collector, config_path, prof)
    _check_gcloud_impersonation(collector, config_path, prof)
    _check_gcloud_adc(collector, config_path, interactive)


def _check_gcloud_project(
    collector: _CheckCollector,
    config_path: Path,
    prof: ProfileConfig,
) -> None:
    proj = gcloud_mod.read_gcloud_property(config_path, "project")
    if proj == prof.project:
        collector.add("gcloud_project", "ok", f"Project matches: {proj}")
    else:
        collector.add("gcloud_project", "error", f"Project mismatch: {proj!r} != {prof.project!r}")


def _check_gcloud_impersonation(
    collector: _CheckCollector,
    config_path: Path,
    prof: ProfileConfig,
) -> None:
    imp = gcloud_mod.read_gcloud_property(config_path, "auth/impersonate_service_account")
    if imp == prof.service_account:
        collector.add("impersonation", "ok", f"Impersonation matches: {imp}")
    else:
        collector.add(
            "impersonation",
            "error",
            f"Impersonation mismatch: {imp!r} != {prof.service_account!r}",
        )


def _check_gcloud_adc(
    collector: _CheckCollector,
    config_path: Path,
    interactive: bool,
) -> None:
    adc_status: CheckStatus = (
        "ok" if gcloud_mod.adc_exists(config_path) else ("warning" if interactive else "error")
    )
    if adc_status == "ok":
        collector.add("adc", "ok", "ADC initialized")
    else:
        collector.add("adc", adc_status, "ADC not initialized", "Run gcpctx refresh")


def _check_gac(collector: _CheckCollector, interactive: bool) -> None:
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if not gac:
        collector.add("gac", "ok", "GOOGLE_APPLICATION_CREDENTIALS unset")
        return
    status: CheckStatus = "warning" if interactive else "error"
    collector.add(
        "gac",
        status,
        f"GOOGLE_APPLICATION_CREDENTIALS is set: {gac}",
        "Unset or use --allow-google-application-credentials",
    )


def _check_gcloud(collector: _CheckCollector) -> None:
    try:
        gcloud_mod.find_gcloud()
        collector.add("gcloud", "ok", "gcloud found on PATH")
    except GcpctxError as exc:
        collector.add("gcloud", "error", str(exc), "Install Google Cloud SDK")


def _approval_status(root: Path, info: dict[str, str]) -> str:
    try:
        ctx = resolve_project_context(root, info.get("profile"))
        approval = find_matching_approval(ctx)
    except GcpctxError:
        return "unknown"
    else:
        return approval.mode if approval else "none"


def _severity_exit(name: str) -> int:
    mapping = {
        "config": 2,
        "approval": 3,
        "isolation": 2,
        "gcloud": 5,
        "gac": 6,
        "adc": 5,
    }
    return mapping.get(name, 1)
