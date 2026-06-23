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
"""gcpctx package."""

from __future__ import annotations

__version__ = "0.1.0"

from gcpctx.activation import activate, deactivate
from gcpctx.config import load_config
from gcpctx.discovery import find_project_root
from gcpctx.doctor import run_doctor
from gcpctx.shell import render_shell

__all__ = [
    "__version__",
    "activate",
    "deactivate",
    "find_project_root",
    "load_config",
    "render_shell",
    "run_doctor",
]
