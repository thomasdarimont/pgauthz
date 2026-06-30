# playground-bff — confidential OIDC client for the playground's
# backend-for-frontend. The browser does authorization-code + PKCE; the BFF holds
# the tokens server-side (sessions in the pgauthz_playground DB) and exposes only
# an http-only cookie to the Lit SPA.
resource "keycloak_openid_client" "playground_bff" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "playground-bff"
  name      = "pgauthz Playground (BFF)"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.playground_bff_client_secret

  standard_flow_enabled        = true # authorization code flow (+ PKCE from the BFF)
  direct_access_grants_enabled = false
  service_accounts_enabled     = false

  root_url                        = "https://app.pgauthz.test"
  valid_redirect_uris             = ["https://app.pgauthz.test/playground/auth/callback"]
  valid_post_logout_redirect_uris = ["https://app.pgauthz.test/playground/"]
  web_origins                     = ["https://app.pgauthz.test"]

  # Enforce PKCE server-side: Keycloak rejects any code flow without an S256
  # code_challenge, even though the BFF always sends one.
  pkce_code_challenge_method = "S256"
}

# Tokens must carry the API audience OPA requires (authz-api).
resource "keycloak_openid_audience_protocol_mapper" "playground_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.playground_bff.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# subject_type must be on THIS client too (mappers are per-client), else
# playground tokens lack it and the fail-closed rule denies everything.
resource "keycloak_openid_user_attribute_protocol_mapper" "playground_subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.playground_bff.id
  name                = "subject_type"
  user_attribute      = "subject_type"
  claim_name          = "subject_type"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}
