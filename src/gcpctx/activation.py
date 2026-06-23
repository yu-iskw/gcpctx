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

from gcpctx import gcloud as gcloud_mod
from gcpctx.approvals import (
    consume_once_approval,
    find_matching_approval,
    prompt_for_approval,
)
from gcpctx.context_id import ContextIdInput, derive_context_id
from gcpctx.errors import ConfigNotFoundError, CredentialConflictError
from gcpctx.models import ActivationRequest, ActivationResult
from gcpctx.paths import cloudsdk_config_dir
from gcpctx.project_context import ResolvedProjectContext, resolve_project_context

if TYPE_CHECKING:
    from pathlib import Path


def activate(request: ActivationRequest) -> ActivationResult:
    """Activate gcpctx for the given request."""
    try:
        ctx = resolve_project_context(request.cwd, request.profile)
    except ConfigNotFoundError:
        if request.run_mode:
            raise
        return missing_config_result()
    ctx_id = derive_context_id(
        ContextIdInput(
            root=ctx.root,
            profile=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256=ctx.config_sha256,
        )
    )
    config_dir = cloudsdk_config_dir(ctx_id)

    approval = find_matching_approval(ctx)
    if approval is None:
        approval = prompt_for_approval(
            ctx,
            cloudsdk_config=config_dir,
            interactive=request.interactive,
        )

    warnings, unsets = _gac_policy(request)

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

    consume_once_approval(approval)

    exports = _build_exports(ctx, ctx_id, config_dir)
    return ActivationResult(
        active=True,
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
    return ActivationResult(active=False)


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
        return ActivationResult(active=False)
    return ActivationResult(active=False, noop=True)


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
    if "CLOUDSDK_CORE_PROJECT" not in exports:
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
