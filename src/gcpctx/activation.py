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
"""Activation orchestration."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from gcpctx import audit, gcloud as gcloud_mod
from gcpctx.approvals import (
    consume_once_approval,
    find_matching_approval,
    prompt_for_approval,
)
from gcpctx.errors import ConfigNotFoundError, CredentialConflictError
from gcpctx.gcloud_trust import resolve_trusted_gcloud
from gcpctx.models import ActivationRequest, ActivationResult
from gcpctx.policy import load_policy
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


def activate(request: ActivationRequest) -> ActivationResult:
    """Activate gcpctx for the given request."""
    policy = load_policy()
    try:
        ctx = resolve_project_context(request.cwd, request.profile, policy=policy)
    except ConfigNotFoundError:
        if request.run_mode:
            raise
        return missing_config_result()

    trust = resolve_trusted_gcloud(request.cwd, policy=policy)

    ctx_id = ctx.context_id()
    config_dir = ctx.expected_cloudsdk_config()

    approval = find_matching_approval(ctx, policy=policy, gcloud_trust=trust)
    if approval is None:
        approval = prompt_for_approval(
            ctx,
            cloudsdk_config=config_dir,
            interactive=request.interactive,
            policy=policy,
            gcloud_trust=trust,
        )

    warnings, unsets = _gac_policy(request)
    warnings.extend(trust.warnings)

    adc_ready = gcloud_mod.adc_exists(config_dir)
    if not request.skip_gcloud_init:
        gcloud_mod.ensure_initialized(
            gcloud_mod.InitContext(
                context_id=ctx_id,
                root=ctx.root,
                profile_name=ctx.profile_name,
                profile=ctx.profile,
                config_sha256=ctx.config_sha256,
                force=request.force_refresh,
            )
        )
        adc_ready = True

    if policy.require_initialized_adc_for_hook and request.hook_mode and not adc_ready:
        audit.log_event(
            "activation",
            readiness="approved_not_initialized",
            root=str(ctx.root),
            profile=ctx.profile_name,
        )
        return ActivationResult(
            active=False,
            readiness="approved_not_initialized",
            root=ctx.root,
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            warnings=[*warnings, "ADC not initialized; run gcpctx refresh"],
        )

    consume_once_approval(approval)

    exports = _build_exports(ctx, ctx_id, config_dir)
    audit.log_event(
        "activation",
        readiness="ready",
        root=str(ctx.root),
        profile=ctx.profile_name,
        project=ctx.project,
        context_id=ctx_id,
    )
    return ActivationResult(
        active=True,
        readiness="ready",
        root=ctx.root,
        profile=ctx.profile_name,
        project=ctx.project,
        service_account=ctx.service_account,
        cloudsdk_config=config_dir,
        context_id=ctx_id,
        exports=exports,
        unsets=unsets,
        warnings=warnings,
    )


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


def missing_config_result() -> ActivationResult:
    """When no .gcpctx.toml: deactivate if active, else emit no-op shell code."""
    if os.environ.get("GCPCTX_ACTIVE") == "1":
        return ActivationResult(active=False, readiness="blocked")
    return ActivationResult(active=False, noop=True, readiness="blocked")


def _build_exports(
    ctx: ResolvedProjectContext,
    ctx_id: str,
    config_dir: Path,
) -> dict[str, str]:
    exports: dict[str, str] = {
        "GCPCTX_ACTIVE": "1",
        "GCPCTX_ROOT": str(ctx.root.resolve()),
        "GCPCTX_PROFILE": ctx.profile_name,
        "GCPCTX_PROJECT": ctx.project,
        "GCPCTX_SERVICE_ACCOUNT": ctx.service_account,
        "GCPCTX_CONTEXT_ID": ctx_id,
        "CLOUDSDK_CONFIG": str(config_dir),
        **ctx.profile.env,
    }
    if ctx.profile.region:
        exports["CLOUDSDK_COMPUTE_REGION"] = ctx.profile.region
    if ctx.profile.zone:
        exports["CLOUDSDK_COMPUTE_ZONE"] = ctx.profile.zone
    exports["CLOUDSDK_CORE_PROJECT"] = ctx.project
    return exports


def _gac_policy(request: ActivationRequest) -> tuple[list[str], list[str]]:
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return [], []
    warning = (
        "GOOGLE_APPLICATION_CREDENTIALS is set and may override ADC; "
        "it will be unset for this context"
    )
    if not request.interactive and not request.allow_google_application_credentials:
        msg = (
            "GOOGLE_APPLICATION_CREDENTIALS is set; "
            "pass --allow-google-application-credentials in non-interactive mode"
        )
        raise CredentialConflictError(msg)
    unsets: list[str] = []
    if request.hook_mode or request.run_mode or not request.allow_google_application_credentials:
        unsets.append("GOOGLE_APPLICATION_CREDENTIALS")
    return [warning], unsets
