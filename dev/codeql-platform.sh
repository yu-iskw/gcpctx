# Shared CodeQL platform guard for mise toolchain scripts.
# shellcheck shell=bash
# shellcheck disable=SC2034  # Sourced; variables used by parent scripts.
# CodeQL in mise.lock uses x64 bundles for linux-arm64 and macos-arm64; native
# version checks and `make codeql` may not work on those hosts without emulation.
codeql_os="$(uname -s)"
codeql_arch="$(uname -m)"
codeql_run_version_check=true
if [[ ${codeql_os} == "Linux" && (${codeql_arch} == "aarch64" || ${codeql_arch} == "arm64") ]]; then
	codeql_run_version_check=false
fi
if [[ ${codeql_os} == "Darwin" && (${codeql_arch} == "arm64" || ${codeql_arch} == "aarch64") ]]; then
	codeql_run_version_check=false
fi
