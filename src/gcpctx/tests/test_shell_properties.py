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
"""Property tests for shell quoting and render_shell output validity."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from hypothesis import given, settings, strategies as st

from gcpctx.models import ActivationResult
from gcpctx.shell import render_shell, shell_quote

# Printable ASCII only (0x20..0x7E) — avoids encoding/locale edge cases with bash.
_PRINTABLE_ASCII = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=0,
    max_size=100,
)

# Fixed export-variable names that are valid env identifiers.
_EXPORT_KEYS = ("GCPCTX_ROOT", "GCPCTX_PROFILE", "GCPCTX_PROJECT", "CLOUDSDK_CONFIG")


def _bash_n(script: str) -> int:
    """Return the exit code of `bash -n` on *script*, or -1 if bash is absent."""
    bash = shutil.which("bash")
    if bash is None:
        return -1
    result = subprocess.run(
        [bash, "-n"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.returncode


@given(_PRINTABLE_ASCII)
@settings(max_examples=50)
def test_shell_quote_produces_valid_bash_syntax(value: str) -> None:
    """shell_quote(s) embedded in 'export VAR=...' must always pass bash -n."""
    quoted = shell_quote(value)
    script = f"export TEST_VAR={quoted}"
    rc = _bash_n(script)
    if rc == -1:
        pytest.skip("bash not available")
    assert rc == 0, f"bash -n failed for value={value!r}, quoted={quoted!r}"


@given(st.fixed_dictionaries(dict.fromkeys(_EXPORT_KEYS, _PRINTABLE_ASCII)))
@settings(max_examples=50)
def test_render_shell_activate_passes_bash_n(exports: dict[str, str]) -> None:
    """render_shell activation output with random export values must pass bash -n."""
    result = ActivationResult(active=True, exports=exports)
    script = render_shell(result, "bash")
    rc = _bash_n(script)
    if rc == -1:
        pytest.skip("bash not available")
    assert rc == 0, f"bash -n failed for exports={exports!r}"


@given(st.fixed_dictionaries(dict.fromkeys(_EXPORT_KEYS, _PRINTABLE_ASCII)))
@settings(max_examples=50)
def test_render_shell_activate_zsh_passes_bash_n(exports: dict[str, str]) -> None:
    """render_shell activation for zsh also produces bash-compatible syntax."""
    result = ActivationResult(active=True, exports=exports)
    script = render_shell(result, "zsh")
    rc = _bash_n(script)
    if rc == -1:
        pytest.skip("bash not available")
    assert rc == 0, f"bash -n failed for exports={exports!r}"
