output "project_id" {
  description = "GCP project ID used for the example resources"
  value       = var.project_id
}

output "main_service_account_email" {
  description = "Email of the main service account (gcpctx profile target)"
  value       = google_service_account.main.email
}

output "sub_service_account_email" {
  description = "Email of the sub service account (chained impersonation target)"
  value       = google_service_account.sub.email
}
