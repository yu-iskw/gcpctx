#!/usr/bin/env bash
# Verify SHA-pinned Docker container actions have images on ghcr.io.
#
# pypa/gh-action-pypi-publish publishes container images keyed by commit SHA.
# Pinning the annotated tag object SHA (common with Dependabot) causes:
#   docker: Error response from daemon: manifest unknown
set -Eeuo pipefail

SCRIPT_FILE="$(readlink -f "$0" 2>/dev/null || realpath "$0")"
SCRIPT_DIR="$(dirname "${SCRIPT_FILE}")"
MODULE_DIR="$(dirname "${SCRIPT_DIR}")"
cd "${MODULE_DIR}"

readonly WORKFLOW_DIR=".github/workflows"
readonly DOCKER_ACTION="pypa/gh-action-pypi-publish"
readonly GHCR_IMAGE="pypa/gh-action-pypi-publish"
readonly PIN_PATTERN="${DOCKER_ACTION}@[0-9a-f]{40}"

FAILURES=0

require_command() {
	local cmd="$1"
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "Required command not found: ${cmd}" >&2
		exit 2
	fi
}

ghcr_manifest_exists() {
	local sha="$1"
	local token response

	token="$(
		curl -sf \
			"https://ghcr.io/token?service=ghcr.io&scope=repository:${GHCR_IMAGE}:pull" |
			jq -er .token
	)" || return 1

	response="$(
		curl -sS -o /dev/null -w '%{http_code}' \
			-H "Authorization: Bearer ${token}" \
			-H 'Accept: application/vnd.oci.image.index.v1+json' \
			"https://ghcr.io/v2/${GHCR_IMAGE}/manifests/${sha}"
	)"
	[[ ${response} == "200" ]]
}

resolve_tag_object_commit() {
	local sha="$1"
	local tag_json object_type commit_sha

	tag_json="$(
		curl -sf "https://api.github.com/repos/${DOCKER_ACTION}/git/tags/${sha}" 2>/dev/null || true
	)"
	if [[ -z ${tag_json} ]]; then
		return 1
	fi

	object_type="$(jq -er .object.type <<<"${tag_json}")"
	commit_sha="$(jq -er .object.sha <<<"${tag_json}")"
	if [[ ${object_type} != "commit" ]]; then
		return 1
	fi

	printf '%s\n' "${commit_sha}"
}

check_pin() {
	local sha="$1"

	if ghcr_manifest_exists "${sha}"; then
		echo "OK: ${DOCKER_ACTION}@${sha}"
		return 0
	fi

	local commit_sha=""
	if commit_sha="$(resolve_tag_object_commit "${sha}")"; then
		if ghcr_manifest_exists "${commit_sha}"; then
			echo "FAIL: ${DOCKER_ACTION}@${sha} is an annotated tag object SHA;" \
				"use commit ${commit_sha} instead (GHCR has no image for tag objects)." >&2
			return 1
		fi
	fi

	echo "FAIL: ${DOCKER_ACTION}@${sha} has no GHCR manifest at" \
		"ghcr.io/${GHCR_IMAGE}:${sha}" >&2
	return 1
}

main() {
	require_command curl
	require_command jq

	local pins=""
	pins="$(
		grep -rhoE "${PIN_PATTERN}" "${WORKFLOW_DIR}"/*.yml 2>/dev/null | sort -u || true
	)"

	if [[ -z ${pins} ]]; then
		echo "No ${DOCKER_ACTION} SHA pins found; nothing to check."
		return 0
	fi

	while IFS= read -r pin; do
		[[ -z ${pin} ]] && continue
		local sha="${pin#*@}"
		if ! check_pin "${sha}"; then
			FAILURES=$((FAILURES + 1))
		fi
	done <<<"${pins}"

	if [[ ${FAILURES} -gt 0 ]]; then
		echo "${FAILURES} Docker action pin check(s) failed." >&2
		return 1
	fi
}

main "$@"
