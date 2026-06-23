# ADR 0004: Service account impersonation without long-lived keys

- **Status:** Accepted
- **Date:** 2026-06-23
- **Deciders:** Maintainers

## Context

Repository-local Google Cloud access must avoid long-lived service account key files and align with Google-supported authentication primitives. The `gcloud` CLI does not consume Application Default Credentials (ADC); client libraries do not use `gcloud` impersonation settings directly. Both paths must be configured.

## Decision

`gcpctx` uses **service account impersonation** exclusively. For each isolated context it configures:

1. `gcloud` default project and `auth/impersonate_service_account`
2. Impersonated ADC via `gcloud auth application-default login --impersonate-service-account`
3. Optional quota project, region, and zone through standard `gcloud` commands

All subprocess calls use argument arrays (never shell strings) and always pass the isolated `CLOUDSDK_CONFIG`.

**Stable invariants:**

- No first-class support for service account key files in v0.1.
- Both gcloud CLI defaults and ADC must be initialized for a fully active context.

## Consequences

- Short-lived credentials via Google-supported flows.
- Users must have permission to impersonate the configured service account (IAM outside `gcpctx` scope).
- `gcloud auth application-default login` may require user credentials capable of impersonation.

## Alternatives considered

- **Service account JSON keys in repo or env:** Rejected — leakage risk; discouraged by Google.
- **ADC only (skip gcloud config):** Rejected — breaks direct `gcloud` and tools that shell out to it.
- **gcloud only (skip ADC):** Rejected — breaks Cloud Client Libraries.

## Trade-offs

- Impersonation setup can be slower than reusing a global login; debounced refresh mitigates hook latency.
- Language/runtime ADC impersonation support varies; `doctor` documents gaps.

## References

- [Service account impersonation](https://cloud.google.com/docs/authentication/use-service-account-impersonation)
- [Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc)
- ADR-0003 (isolation)
