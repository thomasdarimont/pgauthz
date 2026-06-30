# The pgauthz API client. Its client_id is the JWT audience (authz-api) OPA
# requires, and client roles assigned here surface in resource_access.authz-api.roles.
resource "keycloak_openid_client" "authz_api" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "authz-api"
  name      = "pgauthz API"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.authz_api_client_secret # managed explicitly for reproducible demos

  # No browser authorization-code flow → no redirect URIs / web origins needed.
  # The demo only uses:
  #   grant_type=password           — interactive users  (get-token.sh <user>)
  #   grant_type=client_credentials — the app as a service (get-token.sh --service)
  standard_flow_enabled        = false
  direct_access_grants_enabled = true
  service_accounts_enabled     = true

  # Explicitly empty (not just omitted) so Terraform CLEARS any previously-set
  # values — Keycloak rejects redirect URIs when standard/implicit flow is off.
  valid_redirect_uris = []
  web_origins         = []
}

# Force `authz-api` into the access token's `aud` (authn.rego verifies aud).
resource "keycloak_openid_audience_protocol_mapper" "authz_api_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.authz_api.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# subject_type → access-token claim consumed by authn.rego (internal_user / client_user).
resource "keycloak_openid_user_attribute_protocol_mapper" "subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.authz_api.id
  name                = "subject_type"
  user_attribute      = "subject_type"
  claim_name          = "subject_type"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

# ── Per-app DB role (namespace isolation) — OPTIONAL, left commented ───────────
# The per-app DB role is a property of the CLIENT (the app), not the user. A
# HARDCODED claim mapper stamps the same db_role onto EVERY token this client
# issues — interactive user logins AND the client's service account
# (client_credentials) alike — so the namespace is always "whichever app minted
# the token", with no user-editable attribute / escalation surface.
#
# To enable per-app isolation for this client:
#   1. uncomment this mapper and set claim_value to the app's namespace,
#   2. create a matching Postgres role (the claim_value) with the right
#      namespace_access grants, and
#   3. set WRITER_DB_ROLE_CLAIM=db_role on OPA (compose-keycloak.yml).
# Off by default: the demo store isn't namespaced, so a SET LOCAL ROLE to a
# non-existent role would fail writes. See keycloak/README.md "Per-app DB role".
#
# resource "keycloak_openid_hardcoded_claim_protocol_mapper" "db_role" {
#   realm_id            = keycloak_realm.pgauthz.id
#   client_id           = keycloak_openid_client.authz_api.id
#   name                = "db_role"
#   claim_name          = "db_role"
#   claim_value         = "app_authz_api" # the app's namespace == a Postgres role
#   claim_value_type    = "String"
#   add_to_access_token = true
#   add_to_id_token     = false
#   add_to_userinfo     = false
# }
