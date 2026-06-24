# Examples

Manual integration demos for gcpctx with real GCP resources. These are not run in CI.

## google_auth_credentials.py

Verifies two authentication flows and end-to-end API access:

1. **`google.auth.default()` under gcpctx** — Application Default Credentials resolve to the **main** service account configured in `.gcpctx.toml`.
2. **Chained impersonation to sub** — Python `google.auth.impersonated_credentials` uses the main ADC as source credentials and obtains tokens for the **sub** service account.
3. **BigQuery `list_datasets`** — both credential sets list datasets in the project (requires `roles/bigquery.metadataViewer` from Terraform).

```text
User ──(gcpctx ADC)──> test-gcpctx-main ──(google-auth chain)──> test-gcpctx-sub
```

### Prerequisites

- [Terraform](https://www.terraform.io/) >= 1.14
- [gcloud](https://cloud.google.com/sdk/docs/install) authenticated as your user account
- This repo's dev environment (`make setup` or `uv sync`)
- A GCP project where you can create service accounts and IAM bindings

### 1. Provision IAM

```bash
cd examples/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: project_id and your_google_account_email

terraform init
terraform apply
```

Note the outputs:

```bash
terraform output -raw project_id
terraform output -raw main_service_account_email
terraform output -raw sub_service_account_email
```

Terraform creates:

- `test-gcpctx-main` — gcpctx profile target; your user receives `roles/iam.serviceAccountTokenCreator`
- `test-gcpctx-sub` — chained impersonation target; main receives `roles/iam.serviceAccountTokenCreator` and `roles/iam.serviceAccountUser`
- Enables `iamcredentials.googleapis.com` and `bigquery.googleapis.com` on the project

### 2. Configure gcpctx

From the repo root:

```bash
cd examples
cp .gcpctx.toml.example .gcpctx.toml
```

Fill `.gcpctx.toml` using terraform outputs (`project` and `service_account` for the main profile).

Approve the profile (once per machine / config hash):

```bash
uv run gcpctx approve
```

### 3. Activate gcpctx

**Shell activation** (integrated terminal / IDE):

```bash
eval "$(uv run gcpctx activate --shell zsh)"
```

**Process-scoped** (no shell mutation):

```bash
uv run gcpctx run -- python google_auth_credentials.py \
  --main-sa "$(terraform -chdir=terraform output -raw main_service_account_email)" \
  --sub-sa "$(terraform -chdir=terraform output -raw sub_service_account_email)"
```

### 4. Run the example

With shell activation:

```bash
export GCPCTX_EXAMPLE_MAIN_SA="$(terraform -chdir=terraform output -raw main_service_account_email)"
export GCPCTX_EXAMPLE_SUB_SA="$(terraform -chdir=terraform output -raw sub_service_account_email)"
uv run python google_auth_credentials.py
```

Or pass flags explicitly:

```bash
uv run python google_auth_credentials.py \
  --main-sa test-gcpctx-main@YOUR_PROJECT.iam.gserviceaccount.com \
  --sub-sa test-gcpctx-sub@YOUR_PROJECT.iam.gserviceaccount.com
```

### Expected output

```text
ADC project: 'your-project'
ADC credential info: {...}
OK   auth.default() identity: test-gcpctx-main@your-project.iam.gserviceaccount.com
OK   main SA BigQuery datasets: listed 3 dataset(s) in 'your-project'
     - analytics
     - staging
     - raw
OK   chained impersonation identity: test-gcpctx-sub@your-project.iam.gserviceaccount.com
OK   sub SA BigQuery datasets: listed 3 dataset(s) in 'your-project'
     - analytics
     - staging
     - raw
All checks passed.
```

Exit code `0` on success; non-zero if identity or BigQuery checks fail, or required flags/env are missing. An empty dataset list (`listed 0 dataset(s)`) is still success.

### Troubleshooting

| Symptom                            | What to check                                                                                                         |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `auth.default()` identity mismatch | Run from an activated shell or via `gcpctx run`; confirm `.gcpctx.toml` points at the main SA                         |
| Chained impersonation fails        | `terraform apply` succeeded; main has `TokenCreator` on sub (`sub_token_creator` in `main.tf`)                        |
| ADC not initialized                | `uv run gcpctx doctor --strict`; re-activate with `--force-refresh` if needed                                         |
| IAM Credentials API errors         | `iamcredentials.googleapis.com` enabled (Terraform `google_project_service.iamcredentials`)                           |
| BigQuery `403` or API not enabled  | Re-run `terraform apply` for `google_project_service.bigquery`; confirm both SAs have `roles/bigquery.metadataViewer` |

```bash
uv run gcpctx doctor --strict
uv run gcpctx status
```

### Cleanup

```bash
cd examples/terraform
terraform destroy
```

Remove local `examples/.gcpctx.toml` if you no longer need the example profile.
