#############################################################
# Main service account
#############################################################
resource "google_service_account" "main" {
  project      = var.project_id
  account_id   = "test-gcpctx-main"
  display_name = "Test GCPCTX Main Service Account"

  depends_on = [google_project_service.iamcredentials]
}

resource "google_project_iam_member" "main" {
  for_each = toset([
    "roles/bigquery.metadataViewer",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.main.email}"

  depends_on = [google_project_service.bigquery]
}

resource "google_service_account_iam_member" "main_user_token_creator" {
  service_account_id = google_service_account.main.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "user:${var.your_google_account_email}"
}

#############################################################
# Another service account
#############################################################
resource "google_service_account" "sub" {
  project      = var.project_id
  account_id   = "test-gcpctx-sub"
  display_name = "Test GCPCTX Sub Service Account"

  depends_on = [google_project_service.iamcredentials]
}

resource "google_project_iam_member" "sub" {
  for_each = toset([
    "roles/bigquery.metadataViewer",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.sub.email}"

  depends_on = [google_project_service.bigquery]
}

resource "google_service_account_iam_member" "sub_user" {
  service_account_id = google_service_account.sub.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.main.email}"
}

resource "google_service_account_iam_member" "sub_token_creator" {
  service_account_id = google_service_account.sub.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.main.email}"
}
