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
"""Shell code rendering for bash and zsh."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from gcpctx.models import ActivationResult

SUPPORTED_SHELLS = frozenset({"bash", "zsh"})
ShellName = Literal["bash", "zsh"]

GCPCTX_VARS = (
    "GCPCTX_ACTIVE",
    "GCPCTX_ROOT",
    "GCPCTX_PROFILE",
    "GCPCTX_PROJECT",
    "GCPCTX_SERVICE_ACCOUNT",
    "GCPCTX_CONTEXT_ID",
    "CLOUDSDK_CONFIG",
    "CLOUDSDK_CORE_PROJECT",
    "CLOUDSDK_COMPUTE_REGION",
    "CLOUDSDK_COMPUTE_ZONE",
    "CLOUDSDK_CORE_DISABLE_PROMPTS",
)


def shell_quote(value: str) -> str:
    """Return a safely single-quoted shell string."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def render_shell(result: ActivationResult, shell: ShellName) -> str:
    """Render activation or deactivation shell code."""
    if shell not in SUPPORTED_SHELLS:
        msg = f"unsupported shell: {shell}"
        raise ValueError(msg)
    if not result.active:
        if result.noop:
            return ""
        return _render_deactivate()
    return _render_activate(result)


def _render_activate(result: ActivationResult) -> str:
    lines: list[str] = [
        "export GCPCTX_PREV_CLOUDSDK_CONFIG=${CLOUDSDK_CONFIG-}",
        ("export GCPCTX_PREV_GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS-}"),
    ]
    lines.extend(f"export {key}={shell_quote(value)}" for key, value in result.exports.items())
    lines.extend(f"unset {key}" for key in result.unsets)
    return "\n".join(lines)


def _render_deactivate() -> str:
    lines = [f"unset {var}" for var in GCPCTX_VARS]
    lines.append(
        'if [ -n "${GCPCTX_PREV_CLOUDSDK_CONFIG+x}" ]; then '
        'export CLOUDSDK_CONFIG="$GCPCTX_PREV_CLOUDSDK_CONFIG"; '
        "else unset CLOUDSDK_CONFIG; fi"
    )
    lines.append(
        'if [ -n "${GCPCTX_PREV_GOOGLE_APPLICATION_CREDENTIALS+x}" ]; then '
        'export GOOGLE_APPLICATION_CREDENTIALS="$GCPCTX_PREV_GOOGLE_APPLICATION_CREDENTIALS"; '
        "else unset GOOGLE_APPLICATION_CREDENTIALS; fi"
    )
    lines.append("unset GCPCTX_PREV_CLOUDSDK_CONFIG")
    lines.append("unset GCPCTX_PREV_GOOGLE_APPLICATION_CREDENTIALS")
    return "\n".join(lines)


def zsh_hook_snippet() -> str:
    """Return zsh hook installation snippet."""
    return """# >>> gcpctx hook >>>
_gcpctx_hook() {
  eval "$(gcpctx hook eval zsh)"
}

autoload -U add-zsh-hook
add-zsh-hook chpwd _gcpctx_hook
_gcpctx_hook
# <<< gcpctx hook <<<"""


def bash_hook_snippet() -> str:
    """Return bash hook installation snippet."""
    return """# >>> gcpctx hook >>>
_gcpctx_hook() {
  eval "$(gcpctx hook eval bash)"
}

case ";$PROMPT_COMMAND;" in
  *";_gcpctx_hook;"*) ;;
  *) PROMPT_COMMAND="_gcpctx_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
# <<< gcpctx hook <<<"""


def shell_use_wrapper() -> str:
    """Return shell function wrapper for gcpctx-use."""
    return """gcpctx-use() {
  if [ -z "$1" ]; then
    echo "usage: gcpctx-use <profile>" >&2
    return 1
  fi
  eval "$(gcpctx use "$1" --shell "${SHELL##*/}")"
}"""
