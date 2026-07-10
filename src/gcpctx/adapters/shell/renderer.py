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
"""ShellRenderer wrapping the existing shell.render_shell emitter."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from gcpctx.shell import ShellName, render_shell

if TYPE_CHECKING:
    from gcpctx.models import ActivationResult


class SharedShellRenderer:
    """bash/zsh share one render path today; shell name is still validated."""

    def render(self, result: ActivationResult, shell: str) -> str:
        return render_shell(result, cast("ShellName", shell))
