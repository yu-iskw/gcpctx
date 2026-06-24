#!/usr/bin/env python3
"""Manual integration demo: gcpctx ADC and chained sub-SA impersonation."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from typing import TYPE_CHECKING

from google import auth
from google.api_core import exceptions as api_exceptions
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request
from google.cloud import bigquery

if TYPE_CHECKING:
    from google.auth.credentials import Credentials

TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
MAX_DATASETS_TO_PRINT = 10
HTTP_ERROR_STATUS = 400


def _http_response_status(response: object) -> int:
    status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(response, "status", None)
    if not isinstance(status, int):
        msg = "HTTP response has no status"
        raise TypeError(msg)
    return status


def _http_response_body(response: object) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    data = getattr(response, "data", b"")
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return str(data)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify gcpctx ADC resolves to the main service account, chained "
            "impersonation reaches the sub service account, and both can list "
            "BigQuery datasets."
        ),
    )
    parser.add_argument(
        "--main-sa",
        default=os.environ.get("GCPCTX_EXAMPLE_MAIN_SA", ""),
        help="Expected main service account email (or GCPCTX_EXAMPLE_MAIN_SA)",
    )
    parser.add_argument(
        "--sub-sa",
        default=os.environ.get("GCPCTX_EXAMPLE_SUB_SA", ""),
        help="Expected sub service account email (or GCPCTX_EXAMPLE_SUB_SA)",
    )
    parser.add_argument(
        "--project",
        default=os.environ.get("GCPCTX_PROJECT", ""),
        help="GCP project for BigQuery listing (or GCPCTX_PROJECT; else ADC project)",
    )
    return parser.parse_args()


def _email_from_cred_info(credentials: Credentials) -> str | None:
    get_cred_info = getattr(credentials, "get_cred_info", None)
    if get_cred_info is None:
        return None
    info = get_cred_info()
    if not isinstance(info, dict):
        return None
    email = None
    for key in ("service_account_email", "principal", "email"):
        value = info.get(key)
        if isinstance(value, str) and value:
            email = value
            break
    return email


def _email_from_tokeninfo(access_token: str, request: Request) -> str:
    query = urllib.parse.urlencode({"access_token": access_token})
    url = f"{TOKENINFO_URL}?{query}"
    response = request(url=url, method="GET")
    status = _http_response_status(response)
    body = _http_response_body(response)
    if status >= HTTP_ERROR_STATUS:
        msg = f"tokeninfo request failed ({status}): {body}"
        raise RuntimeError(msg)
    payload = json.loads(body)
    email = payload.get("email")
    if not isinstance(email, str) or not email:
        msg = f"tokeninfo response missing email: {payload!r}"
        raise RuntimeError(msg)
    return email


def resolve_credential_email(credentials: Credentials, request: Request) -> str:
    """Return the effective service account email for refreshed credentials."""
    service_account_email = getattr(credentials, "service_account_email", None)
    if isinstance(service_account_email, str) and service_account_email:
        return service_account_email

    cred_info_email = _email_from_cred_info(credentials)
    if cred_info_email:
        return cred_info_email

    credentials.refresh(request)
    token = credentials.token
    if not isinstance(token, str) or not token:
        msg = "credentials have no access token after refresh"
        raise RuntimeError(msg)
    return _email_from_tokeninfo(token, request)


def _assert_email(label: str, actual: str, expected: str) -> None:
    if actual != expected:
        print(f"FAIL {label}: expected {expected!r}, got {actual!r}", file=sys.stderr)
        sys.exit(1)
    print(f"OK   {label}: {actual}")


def list_project_datasets(label: str, credentials: Credentials, project: str) -> None:
    """List BigQuery datasets using the given credentials."""
    try:
        client = bigquery.Client(credentials=credentials, project=project)
        refs = list(client.list_datasets())
    except api_exceptions.GoogleAPIError as exc:
        print(f"FAIL {label}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"OK   {label}: listed {len(refs)} dataset(s) in {project!r}")
    for ref in refs[:MAX_DATASETS_TO_PRINT]:
        print(f"     - {ref.dataset_id}")
    if len(refs) > MAX_DATASETS_TO_PRINT:
        print(f"     ... and {len(refs) - MAX_DATASETS_TO_PRINT} more")


def check_adc_main(main_sa: str, request: Request) -> tuple[Credentials, str]:
    """Check 1: auth.default() under gcpctx resolves to the main service account."""
    if not main_sa:
        print(
            "Set --main-sa or GCPCTX_EXAMPLE_MAIN_SA (see examples/README.md)",
            file=sys.stderr,
        )
        sys.exit(2)

    source_creds, adc_project = auth.default()
    print(f"ADC project: {adc_project!r}")
    print(f"ADC credential info: {source_creds.get_cred_info()}")

    actual = resolve_credential_email(source_creds, request)
    _assert_email("auth.default() identity", actual, main_sa)
    return source_creds, adc_project or ""


def check_chained_sub(
    source_creds: Credentials,
    sub_sa: str,
    request: Request,
) -> Credentials:
    """Check 2: chained impersonation from main ADC to the sub service account."""
    if not sub_sa:
        print(
            "Set --sub-sa or GCPCTX_EXAMPLE_SUB_SA (see examples/README.md)",
            file=sys.stderr,
        )
        sys.exit(2)

    sub_creds = impersonated_credentials.Credentials(
        source_credentials=source_creds,
        target_principal=sub_sa,
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        lifetime=300,
    )
    actual = resolve_credential_email(sub_creds, request)
    _assert_email("chained impersonation identity", actual, sub_sa)
    return sub_creds


def main() -> None:
    args = _parse_args()
    request = Request()

    source_creds, adc_project = check_adc_main(args.main_sa, request)
    project = args.project or adc_project
    if not project:
        print(
            "Set --project or GCPCTX_PROJECT, or ensure ADC returns a project",
            file=sys.stderr,
        )
        sys.exit(2)

    list_project_datasets("main SA BigQuery datasets", source_creds, project)

    sub_creds = check_chained_sub(source_creds, args.sub_sa, request)
    list_project_datasets("sub SA BigQuery datasets", sub_creds, project)
    print("All checks passed.")


if __name__ == "__main__":
    main()
