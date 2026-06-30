# app-dms — a document service, demonstrated as an app-as-a-service that accesses
# pgauthz via the OAuth2 client_credentials grant (no human, no password flow).
# Its identity is fixed on the CLIENT: every token it mints carries
# subject_type=service_account and the per-app db_role=app_dms (hardcoded mappers,
# the recommended pattern for app/tenant properties). The matching authorization
# tuple lives in examples/models/demo/seed.sql
# (service_account:service-account-app-dms is viewer of document:*).
resource "keycloak_openid_client" "app_dms" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "app-dms"
  name      = "Document service (app-dms)"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.app_dms_client_secret

  # client_credentials only.
  standard_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = true

  valid_redirect_uris = []
  web_origins         = []
}

# Tokens must carry the API audience OPA requires (authz-api).
resource "keycloak_openid_audience_protocol_mapper" "app_dms_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.app_dms.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# subject_type is a property of THIS app (a service), hardcoded on the client so
# it applies to the service-account token. Safe here because the client has no
# human logins to clobber.
resource "keycloak_openid_hardcoded_claim_protocol_mapper" "app_dms_subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.app_dms.id
  name                = "subject_type"
  claim_name          = "subject_type"
  claim_value         = "service_account"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

# Per-app DB role (namespace isolation), determined by the client (the app). OPA
# only acts on it when WRITER_DB_ROLE_CLAIM is enabled + a matching Postgres role
# exists — see keycloak/README.md "Per-app DB role". Harmless for reads.
resource "keycloak_openid_hardcoded_claim_protocol_mapper" "app_dms_db_role" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.app_dms.id
  name                = "db_role"
  claim_name          = "db_role"
  claim_value         = "app_dms"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}
