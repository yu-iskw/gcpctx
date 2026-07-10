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
"""In-memory port fake behavior tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from gcpctx.errors import ApprovalRequiredError
from gcpctx.models import ActivationResult
from gcpctx.ports import ApprovalAnswer, ApprovalRequest
from gcpctx.tests.fakes import (
    FakeAuditSink,
    FakeClock,
    FakeEnv,
    FakeGcloudPort,
    FakePrompter,
    FakeShellRenderer,
    FakeStateStore,
)


def test_fake_state_store_roundtrip_and_lock() -> None:
    store = FakeStateStore()
    assert store.read("approvals") is None
    with store.lock("approvals"):
        store.write("approvals", b"{}")
    assert store.read("approvals") == b"{}"
    assert store.locks_held == ["approvals"]
    store.delete("approvals")
    assert store.read("approvals") is None


def test_fake_env_and_clock() -> None:
    env = FakeEnv({"HOME": "/tmp/home"})
    assert env.get("HOME") == "/tmp/home"
    assert env.get("MISSING") is None
    assert env.snapshot() == {"HOME": "/tmp/home"}
    env.set("FOO", "bar")
    assert env.get("FOO") == "bar"

    clock = FakeClock(datetime(2025, 6, 1, tzinfo=UTC))
    assert clock.now().year == 2025
    clock.advance(days=2)
    assert clock.now().day == 3


def test_fake_prompter_scripted_answers() -> None:
    request = ApprovalRequest(
        root=Path("/repo"),
        profile="dev",
        project="p",
        service_account="sa@p.iam.gserviceaccount.com",
        config_sha256="a" * 64,
        cloudsdk_config=Path("/tmp/gcloud"),
    )
    prompter = FakePrompter(["once", ApprovalAnswer(decision="deny")])
    assert prompter.confirm(request).decision == "once"
    assert prompter.confirm(request).decision == "deny"
    with pytest.raises(ApprovalRequiredError, match="no scripted answers"):
        prompter.confirm(request)
    assert len(prompter.requests) == 3


def test_fake_audit_and_shell() -> None:
    sink = FakeAuditSink()
    sink.emit("approval_granted", root="/repo")
    assert sink.events == [{"event": "approval_granted", "root": "/repo"}]

    renderer = FakeShellRenderer()
    result = ActivationResult(active=True, exports={"A": "1"})
    assert "fake-shell:bash" in renderer.render(result, "bash")
    assert renderer.calls[0][1] == "bash"


def test_fake_gcloud_port_properties_and_probe(tmp_path: Path) -> None:
    port = FakeGcloudPort(default_probe=False)
    cfg = tmp_path / "gcloud"
    port.set_property(cfg, "core/project", "my-proj")
    assert port.get_property(cfg, "core/project") == "my-proj"
    assert port.probe_impersonation(cfg, "sa@x.iam.gserviceaccount.com") is False
    port.probe_results[f"{cfg}:sa@x.iam.gserviceaccount.com"] = True
    assert port.probe_impersonation(cfg, "sa@x.iam.gserviceaccount.com") is True
    assert port.adc_exists(cfg) is False
    port.adc_login_impersonated(cfg, "sa@x.iam.gserviceaccount.com")
    assert port.adc_exists(cfg) is True
    trust = port.resolve_binary(tmp_path)
    assert trust.path.endswith("gcloud")
