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
"""Activation engine: resolve → plan → apply."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from gcpctx.core.contract import ExitCode
from gcpctx.core.plan import (
    ActivationFacts,
    ConsumeOnceApproval,
    Denial,
    InitImpersonatedAdc,
    Plan,
    build_activation_plan,
)
from gcpctx.errors import (
    ApprovalRequiredError,
    ConfigNotFoundError,
    ConfigValidationError,
    CredentialConflictError,
    GcloudTrustError,
    GcpctxError,
)
from gcpctx.gcloud import InitContext
from gcpctx.models import ActivationResult, build_missing_config_result
from gcpctx.policy import load_policy
from gcpctx.project_context import resolve_project_context
from gcpctx.services.approvals import (
    consume_once_approval,
    find_matching_approval,
    prompt_for_approval,
)

if TYPE_CHECKING:
    from gcpctx.gcloud_trust import GcloudTrustResult
    from gcpctx.models import ActivationRequest, ApprovalRecord
    from gcpctx.policy import SecurityPolicy
    from gcpctx.ports import AuditSink, EnvPort, GcloudPort, Prompter
    from gcpctx.project_context import ResolvedProjectContext


@dataclass(frozen=True, slots=True)
class Resolution:
    """Gathered inputs for planning (ports + existing resolvers)."""

    ctx: ResolvedProjectContext
    policy: SecurityPolicy
    trust: GcloudTrustResult
    approval: ApprovalRecord | None
    context_id: str
    cloudsdk_config: Path
    adc_exists: bool
    gac_set: bool


class Engine:
    """Orchestrates resolve → plan → apply for activation."""

    def __init__(
        self,
        gcloud: GcloudPort,
        env: EnvPort,
        audit: AuditSink,
        prompter: Prompter | None = None,
    ) -> None:
        self._gcloud = gcloud
        self._env = env
        self._audit = audit
        self._prompter = prompter

    def resolve(self, cwd: Path, profile: str | None = None) -> Resolution:
        """Gather project context, trust, approval, and env facts via ports."""
        policy = load_policy()
        ctx = resolve_project_context(cwd, profile, policy=policy)
        trust = self._gcloud.resolve_binary(
            cwd,
            policy=policy,
            configured_path=ctx.gcloud_path,
        )
        context_id = ctx.context_id()
        cloudsdk_config = ctx.expected_cloudsdk_config()
        approval = find_matching_approval(ctx, policy=policy, gcloud_trust=trust)
        return Resolution(
            ctx=ctx,
            policy=policy,
            trust=trust,
            approval=approval,
            context_id=context_id,
            cloudsdk_config=cloudsdk_config,
            adc_exists=self._gcloud.adc_exists(cloudsdk_config),
            gac_set=bool(self._env.get("GOOGLE_APPLICATION_CREDENTIALS")),
        )

    def plan(self, res: Resolution, request: ActivationRequest) -> Plan:
        """Build a pure Plan from a Resolution and request flags."""
        ctx = res.ctx
        facts = ActivationFacts(
            root_str=str(ctx.root.resolve()),
            profile_name=ctx.profile_name,
            project=ctx.project,
            service_account=ctx.service_account,
            config_sha256=ctx.config_sha256,
            context_id=res.context_id,
            cloudsdk_config=str(res.cloudsdk_config),
            profile_env=dict(ctx.profile.env),
            region=ctx.profile.region,
            zone=ctx.profile.zone,
            approval_present=res.approval is not None,
            hook_mode=request.hook_mode,
            run_mode=request.run_mode,
            skip_gcloud_init=request.skip_gcloud_init,
            force_refresh=request.force_refresh,
            allow_gac=request.allow_google_application_credentials,
            interactive=request.interactive,
            gac_set=res.gac_set,
            adc_exists=res.adc_exists,
            require_initialized_adc_for_hook=res.policy.require_initialized_adc_for_hook,
            trust_warnings=tuple(res.trust.warnings),
        )
        return build_activation_plan(facts)

    def apply(self, plan: Plan, res: Resolution) -> ActivationResult:
        """Execute plan steps (side effects) and return an ActivationResult."""
        if plan.denial is not None:
            _raise_denial(plan.denial)
        self._apply_gcloud_steps(plan, res)
        self._apply_approval_steps(plan, res)
        self._audit.emit(
            "activation",
            readiness=plan.readiness,
            root=plan.root,
            profile=plan.profile,
            project=plan.project,
            context_id=plan.context_id,
        )
        return _result_from_plan(plan)

    def activate(self, request: ActivationRequest) -> ActivationResult:
        """Full activate pipeline compatible with historical ``activation.activate``."""
        try:
            res = self.resolve(request.cwd, request.profile)
        except ConfigNotFoundError:
            if request.run_mode:
                raise
            return self.missing_config_result()

        plan = self.plan(res, request)
        if plan.denial is not None and plan.denial.exit_code == int(ExitCode.APPROVAL_REQUIRED):
            res, plan = self._prompt_and_replan(res, request)
        if plan.denial is not None:
            _raise_denial(plan.denial)
        return self.apply(plan, res)

    def explain_plan(self, request: ActivationRequest) -> Plan:
        """Resolve and plan without applying (dry-run / MCP)."""
        res = self.resolve(request.cwd, request.profile)
        return self.plan(res, request)

    def missing_config_result(self) -> ActivationResult:
        """When no .gcpctx.toml: deactivate if active, else emit no-op shell code."""
        return build_missing_config_result(gcpctx_active=self._env.get("GCPCTX_ACTIVE"))

    def _prompt_and_replan(
        self,
        res: Resolution,
        request: ActivationRequest,
    ) -> tuple[Resolution, Plan]:
        approval = prompt_for_approval(
            res.ctx,
            cloudsdk_config=res.cloudsdk_config,
            interactive=request.interactive,
            policy=res.policy,
            gcloud_trust=res.trust,
            prompter=self._prompter,
        )
        res = replace(res, approval=approval)
        return res, self.plan(res, request)

    def _apply_gcloud_steps(self, plan: Plan, res: Resolution) -> None:
        init = next((step for step in plan.steps if isinstance(step, InitImpersonatedAdc)), None)
        if init is None:
            return
        trust = self._recheck_trust(res)
        self._gcloud.ensure_initialized(
            InitContext(
                context_id=res.context_id,
                root=res.ctx.root,
                profile_name=res.ctx.profile_name,
                profile=res.ctx.profile,
                config_sha256=res.ctx.config_sha256,
                gcloud_executable=trust.path,
                force=init.force,
            )
        )

    def _apply_approval_steps(self, plan: Plan, res: Resolution) -> None:
        if not any(isinstance(step, ConsumeOnceApproval) for step in plan.steps):
            return
        if res.approval is not None:
            consume_once_approval(res.approval)

    def _recheck_trust(self, res: Resolution) -> GcloudTrustResult:
        """Re-resolve gcloud trust before side effects (narrow TOCTOU window)."""
        ctx = resolve_project_context(
            res.ctx.root,
            res.ctx.profile_name,
            policy=res.policy,
        )
        if ctx.config_sha256 != res.ctx.config_sha256:
            msg = "project config changed during activation"
            raise ConfigValidationError(msg)
        trust = self._gcloud.resolve_binary(
            res.ctx.root,
            policy=res.policy,
            configured_path=ctx.gcloud_path,
        )
        if trust.path != res.trust.path or trust.sha256 != res.trust.sha256:
            msg = "gcloud trust fingerprint changed during activation"
            raise GcloudTrustError(msg)
        return trust


def _raise_denial(denial: Denial) -> None:
    if denial.exit_code == int(ExitCode.APPROVAL_REQUIRED):
        raise ApprovalRequiredError(denial.message)
    if denial.exit_code == int(ExitCode.POLICY_VIOLATION):
        raise CredentialConflictError(denial.message)
    raise GcpctxError(denial.message)


def _result_from_plan(plan: Plan) -> ActivationResult:
    return ActivationResult(
        active=plan.active,
        readiness=plan.readiness,
        root=Path(plan.root) if plan.root else None,
        profile=plan.profile,
        project=plan.project,
        service_account=plan.service_account,
        cloudsdk_config=Path(plan.cloudsdk_config) if plan.cloudsdk_config else None,
        context_id=plan.context_id,
        exports=dict(plan.env_delta.exports),
        unsets=list(plan.env_delta.unsets),
        warnings=list(plan.warnings),
    )


__all__ = [
    "Engine",
    "Resolution",
]
