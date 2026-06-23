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
"""Shell rendering tests."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from gcpctx.models import ActivationResult
from gcpctx.shell import render_shell, shell_quote


def test_shell_quote_special_chars() -> None:
    assert shell_quote("it's") == "'it'\"'\"'s'"
    assert shell_quote("a;b") == "'a;b'"


def test_render_activate_with_spaces() -> None:
    result = ActivationResult(
        active=True,
        exports={
            "GCPCTX_ROOT": "/path/with spaces/and;semicolons",
            "CLOUDSDK_CONFIG": "/home/user/.cache/gcpctx/contexts/abc/gcloud",
        },
    )
    code = render_shell(result, "bash")
    assert "export GCPCTX_ROOT='/path/with spaces/and;semicolons'" in code
    bash_path = shutil.which("bash")
    if bash_path is None:
        pytest.skip("bash not available")
    proc = subprocess.run([bash_path, "-n"], input=code, text=True, check=False)
    assert proc.returncode == 0


def test_render_deactivate() -> None:
    result = ActivationResult(active=False)
    code = render_shell(result, "zsh")
    assert "unset GCPCTX_ACTIVE" in code
    assert "GCPCTX_PREV_CLOUDSDK_CONFIG" in code


def test_render_noop() -> None:
    result = ActivationResult(active=False, noop=True)
    assert render_shell(result, "bash") == ""
