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
"""Pure activation plan building (no I/O, env, or subprocess)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from gcpctx.core.contract import (
    GCPCTX_ACTIVE,
    GCPCTX_CONTEXT_ID,
    GCPCTX_PROFILE,
    GCPCTX_PROJECT,
    GCPCTX_ROOT,
    GCPCTX_SERVICE_ACCOUNT,
    ExitCode,
)
from gcpctx.core.policy import profile_env_for_export

Readiness = Literal["ready", "approved_not_initialized", "blocked"]

SHELL_BACKUP_VARS: tuple[str, ...] = (
    "CLOUDSDK_CONFIG",
    "GOOGLE_APPLICATION_CREDENTIALS",
)

GAC_WARNING = (
    "GOOGLE_APPLICATION_CREDENTIALS is set and may override ADC; "
    "it will be unset for this context"
)

GAC_CONFLICT_MESSAGE = (
    "GOOGLE_APPLICATION_CREDENTIALS is set; "
    "pass --allow-google-application-credentials in non-interactive mode"
)

APPROVAL_REQUIRED_MESSAGE = "approval required for activation"
ADC_NOT_READY_WARNING = "ADC not initialized; run gcpctx reload"


@dataclass(frozen=True, slots=True)
class EnvDelta:
    """Environment mutations produced by an activation plan."""

    exports: dict[str, str]
    unsets: tuple[str, ...] = ()
    backups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EnsureContextDir:
    """Ensure the isolated context directory exists."""

    context_id: str


@dataclass(frozen=True, slots=True)
class SetGcloudProperty:
    """Set one gcloud config property in the isolated CLOUDSDK_CONFIG."""

    key: str
    value: str


@dataclass(frozen=True, slots=True)
class InitImpersonatedAdc:
    """Create or refresh impersonated application-default credentials."""

    force: bool = False


@dataclass(frozen=True, slots=True)
class WriteContextState:
    """Persist per-context initialization bookkeeping."""


@dataclass(frozen=True, slots=True)
class ConsumeOnceApproval:
    """Consume a once-mode approval after a successful activation."""


Step = (
    EnsureContextDir
    | SetGcloudProperty
    | InitImpersonatedAdc
    | WriteContextState
    | ConsumeOnceApproval
)


@dataclass(frozen=True, slots=True)
class Denial:
    """Plan refusal with a stable exit code and optional remediation."""

    exit_code: int
    message: str
    remediation: str | None = None


@dataclass(frozen=True, slots=True)
class Plan:
    """Frozen activation plan: steps, env delta, or a denial."""

    steps: tuple[Step, ...] = ()
    env_delta: EnvDelta = field(default_factory=lambda: EnvDelta(exports={}))
    denial: Denial | None = None
    readiness: Readiness = "ready"
    warnings: tuple[str, ...] = ()
    active: bool = True
    root: str | None = None
    profile: str | None = None
    project: str | None = None
    service_account: str | None = None
    context_id: str | None = None
    cloudsdk_config: str | None = None
    config_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ActivationFacts:
    """Pure inputs for ``build_activation_plan``."""

    root_str: str
    profile_name: str
    project: str
    service_account: str
    config_sha256: str
    context_id: str
    cloudsdk_config: str
    profile_env: dict[str, str]
    region: str | None = None
    zone: str | None = None
    quota_project: str | None = None
    approval_present: bool = False
    hook_mode: bool = False
    run_mode: bool = False
    skip_gcloud_init: bool = False
    force_refresh: bool = False
    allow_gac: bool = False
    interactive: bool = True
    gac_set: bool = False
    adc_exists: bool = False
    require_initialized_adc_for_hook: bool = False
    trust_warnings: tuple[str, ...] = ()


def build_exports(  # noqa: PLR0913  # pylint: disable=too-many-arguments
    *,
    root_str: str,
    profile_name: str,
    project: str,
    service_account: str,
    context_id: str,
    cloudsdk_config: str,
    profile_env: dict[str, str],
    region: str | None = None,
    zone: str | None = None,
) -> dict[str, str]:
    """Build activation export map (project identity wins over profile.env)."""
    exports: dict[str, str] = {
        GCPCTX_ACTIVE: "1",
        GCPCTX_ROOT: root_str,
        GCPCTX_PROFILE: profile_name,
        GCPCTX_PROJECT: project,
        GCPCTX_SERVICE_ACCOUNT: service_account,
        GCPCTX_CONTEXT_ID: context_id,
        "CLOUDSDK_CONFIG": cloudsdk_config,
        **profile_env_for_export(profile_env),
    }
    if region:
        exports["CLOUDSDK_COMPUTE_REGION"] = region
    if zone:
        exports["CLOUDSDK_COMPUTE_ZONE"] = zone
    # Fail-closed: project identity cannot be overridden by profile.env.
    exports["CLOUDSDK_CORE_PROJECT"] = project
    return exports


def evaluate_gac_policy(
    *,
    gac_set: bool,
    interactive: bool,
    allow_gac: bool,
    hook_mode: bool,
    run_mode: bool,
) -> tuple[Denial | None, tuple[str, ...], tuple[str, ...]]:
    """Return (denial, warnings, unsets) for GOOGLE_APPLICATION_CREDENTIALS."""
    if not gac_set:
        return None, (), ()
    if not interactive and not allow_gac:
        return (
            Denial(exit_code=int(ExitCode.POLICY_VIOLATION), message=GAC_CONFLICT_MESSAGE),
            (),
            (),
        )
    unsets: tuple[str, ...] = ()
    if hook_mode or run_mode or not allow_gac:
        unsets = ("GOOGLE_APPLICATION_CREDENTIALS",)
    return None, (GAC_WARNING,), unsets


def build_init_steps(  # noqa: PLR0913  # pylint: disable=too-many-arguments
    *,
    context_id: str,
    project: str,
    service_account: str,
    region: str | None,
    zone: str | None,
    force_refresh: bool,
) -> tuple[Step, ...]:
    """Ordered gcloud initialization steps for a full activate/reload."""
    steps: list[Step] = [
        EnsureContextDir(context_id=context_id),
        SetGcloudProperty(key="project", value=project),
        SetGcloudProperty(key="auth/impersonate_service_account", value=service_account),
    ]
    if region:
        steps.append(SetGcloudProperty(key="compute/region", value=region))
    if zone:
        steps.append(SetGcloudProperty(key="compute/zone", value=zone))
    steps.append(InitImpersonatedAdc(force=force_refresh))
    steps.append(WriteContextState())
    return tuple(steps)


def _denied(facts: ActivationFacts, denial: Denial) -> Plan:
    return Plan(
        denial=denial,
        active=False,
        readiness="blocked",
        root=facts.root_str,
        profile=facts.profile_name,
        project=facts.project,
        service_account=facts.service_account,
        context_id=facts.context_id,
        cloudsdk_config=facts.cloudsdk_config,
        config_sha256=facts.config_sha256,
    )


def _approved_not_initialized(facts: ActivationFacts, warnings: tuple[str, ...]) -> Plan:
    return Plan(
        steps=(),
        env_delta=EnvDelta(exports={}),
        readiness="approved_not_initialized",
        warnings=(*warnings, ADC_NOT_READY_WARNING),
        active=False,
        root=facts.root_str,
        profile=facts.profile_name,
        project=facts.project,
        service_account=facts.service_account,
        context_id=facts.context_id,
        cloudsdk_config=facts.cloudsdk_config,
        config_sha256=facts.config_sha256,
    )


def _ready_plan(
    facts: ActivationFacts,
    *,
    steps: tuple[Step, ...],
    warnings: tuple[str, ...],
    unsets: tuple[str, ...],
) -> Plan:
    exports = build_exports(
        root_str=facts.root_str,
        profile_name=facts.profile_name,
        project=facts.project,
        service_account=facts.service_account,
        context_id=facts.context_id,
        cloudsdk_config=facts.cloudsdk_config,
        profile_env=facts.profile_env,
        region=facts.region,
        zone=facts.zone,
    )
    return Plan(
        steps=steps,
        env_delta=EnvDelta(
            exports=exports,
            unsets=unsets,
            backups=SHELL_BACKUP_VARS,
        ),
        readiness="ready",
        warnings=warnings,
        active=True,
        root=facts.root_str,
        profile=facts.profile_name,
        project=facts.project,
        service_account=facts.service_account,
        context_id=facts.context_id,
        cloudsdk_config=facts.cloudsdk_config,
        config_sha256=facts.config_sha256,
    )


def build_activation_plan(facts: ActivationFacts) -> Plan:
    """Build a pure activation Plan (steps + env delta) or a Denial."""
    if not facts.approval_present:
        plan = _denied(
            facts,
            Denial(
                exit_code=int(ExitCode.APPROVAL_REQUIRED),
                message=APPROVAL_REQUIRED_MESSAGE,
                remediation="gcpctx approve",
            ),
        )
    else:
        plan = _plan_with_approval(facts)
    return plan


def _plan_with_approval(facts: ActivationFacts) -> Plan:
    gac_denial, gac_warnings, unsets = evaluate_gac_policy(
        gac_set=facts.gac_set,
        interactive=facts.interactive,
        allow_gac=facts.allow_gac,
        hook_mode=facts.hook_mode,
        run_mode=facts.run_mode,
    )
    if gac_denial is not None:
        return _denied(facts, gac_denial)

    warnings = (*gac_warnings, *facts.trust_warnings)
    will_init = not facts.skip_gcloud_init
    adc_ready = True if will_init else facts.adc_exists
    if facts.require_initialized_adc_for_hook and facts.hook_mode and not adc_ready:
        return _approved_not_initialized(facts, warnings)

    steps: list[Step] = []
    if will_init:
        steps.extend(
            build_init_steps(
                context_id=facts.context_id,
                project=facts.project,
                service_account=facts.service_account,
                region=facts.region,
                zone=facts.zone,
                force_refresh=facts.force_refresh,
            )
        )
    steps.append(ConsumeOnceApproval())
    return _ready_plan(facts, steps=tuple(steps), warnings=warnings, unsets=unsets)


__all__ = [
    "ADC_NOT_READY_WARNING",
    "APPROVAL_REQUIRED_MESSAGE",
    "GAC_CONFLICT_MESSAGE",
    "GAC_WARNING",
    "SHELL_BACKUP_VARS",
    "ActivationFacts",
    "ConsumeOnceApproval",
    "Denial",
    "EnsureContextDir",
    "EnvDelta",
    "InitImpersonatedAdc",
    "Plan",
    "SetGcloudProperty",
    "Step",
    "WriteContextState",
    "build_activation_plan",
    "build_exports",
    "build_init_steps",
    "evaluate_gac_policy",
]
