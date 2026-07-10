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
"""GcloudPort adapter wrapping existing gcloud / gcloud_trust modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gcpctx import gcloud as gcloud_mod
from gcpctx.errors import GcpctxError
from gcpctx.gcloud_trust import resolve_trusted_gcloud

if TYPE_CHECKING:
    from pathlib import Path

    from gcpctx.gcloud import InitContext
    from gcpctx.gcloud_trust import GcloudTrustResult
    from gcpctx.models import ContextState
    from gcpctx.policy import SecurityPolicy


class SubprocessGcloudPort:
    """Real gcloud subprocess + trust validation."""

    def resolve_binary(
        self,
        cwd: Path,
        *,
        policy: SecurityPolicy | None = None,
        configured_path: str | None = None,
        strict: bool | None = None,
    ) -> GcloudTrustResult:
        return resolve_trusted_gcloud(cwd, policy, configured_path=configured_path, strict=strict)

    def get_property(
        self,
        cloudsdk_config: Path,
        section_property: str,
        *,
        gcloud_executable: str | None = None,
    ) -> str | None:
        return gcloud_mod.read_gcloud_property(
            cloudsdk_config,
            section_property,
            gcloud_executable=gcloud_executable,
        )

    def set_property(
        self,
        cloudsdk_config: Path,
        section_property: str,
        value: str,
        *,
        gcloud_executable: str | None = None,
    ) -> None:
        gcloud_mod.run_gcloud(
            ["config", "set", section_property, value],
            cloudsdk_config=cloudsdk_config,
            gcloud_executable=gcloud_executable,
        )

    def adc_login_impersonated(
        self,
        cloudsdk_config: Path,
        service_account: str,
        *,
        quota_project: str | None = None,
        gcloud_executable: str | None = None,
    ) -> None:
        gcloud_mod.run_gcloud(
            [
                "auth",
                "application-default",
                "login",
                "--impersonate-service-account",
                service_account,
            ],
            cloudsdk_config=cloudsdk_config,
            extra_env={"CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
            gcloud_executable=gcloud_executable,
        )
        if quota_project:
            gcloud_mod.run_gcloud(
                ["auth", "application-default", "set-quota-project", quota_project],
                cloudsdk_config=cloudsdk_config,
                gcloud_executable=gcloud_executable,
            )

    def adc_exists(self, cloudsdk_config: Path) -> bool:
        return gcloud_mod.adc_exists(cloudsdk_config)

    def ensure_initialized(self, init_context: InitContext) -> ContextState:
        return gcloud_mod.ensure_initialized(init_context)

    def probe_impersonation(
        self,
        cloudsdk_config: Path,
        service_account: str,
        *,
        gcloud_executable: str | None = None,
    ) -> bool:
        try:
            gcloud_mod.run_gcloud(
                [
                    "auth",
                    "print-access-token",
                    "--impersonate-service-account",
                    service_account,
                ],
                cloudsdk_config=cloudsdk_config,
                gcloud_executable=gcloud_executable,
            )
        except GcpctxError:
            return False
        return True
