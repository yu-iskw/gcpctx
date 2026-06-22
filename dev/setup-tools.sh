#!/bin/bash
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

set -Eeuo pipefail

SCRIPT_FILE="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "${SCRIPT_FILE}")"
MODULE_DIR="$(dirname "${SCRIPT_DIR}")"

cd "${MODULE_DIR}"

if ! command -v mise &>/dev/null; then
	echo "Error: 'mise' is not on PATH (required for make setup-tools and make setup)." >&2
	echo "Install mise first: https://mise.jdx.dev/getting-started.html" >&2
	echo "  Or use only Python setup: make setup-python" >&2
	exit 1
fi

# shellcheck source=dev/codeql-platform.sh
source "${SCRIPT_DIR}/codeql-platform.sh"

mise trust --yes "${MODULE_DIR}/mise.toml" 2>/dev/null || mise trust "${MODULE_DIR}"

echo "--- Installing toolchain via mise (mise.toml + mise.lock) ---"
# --locked is preferred for reproducibility; global ~/.config/mise tools not in mise.lock
# can make strict locked install fail (mise settings are global). CI uses --locked via smoke test.
if [[ -f "${MODULE_DIR}/mise.lock" ]]; then
	if ! MISE_LOCKED=false mise install --locked; then
		echo "Note: mise install --locked failed (often extra tools in global mise config)." >&2
		echo "  Retrying: MISE_LOCKED=false mise install" >&2
		MISE_LOCKED=false mise install
	fi
else
	MISE_LOCKED=false mise install
fi

echo "--- Installing Trunk-managed linters (mise run trunk-install) ---"
mise run trunk-install

echo "--- Toolchain versions ---"
mise exec trunk@ -- trunk --version
mise exec trivy@ -- trivy --version
mise exec osv-scanner@ -- osv-scanner --version
mise exec grype@ -- grype version
if [[ ${codeql_run_version_check} == "true" ]]; then
	mise exec codeql@ -- codeql version
else
	echo "codeql: version check skipped on ARM64 (${codeql_os}/${codeql_arch}; mise.lock uses x64 bundle)." >&2
	echo "  Install still succeeds; use x64 Linux/macOS or Rosetta for make codeql." >&2
fi
