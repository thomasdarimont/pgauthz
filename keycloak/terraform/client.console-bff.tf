# console-bff — confidential OIDC client for the management console's
# backend-for-frontend (console/). The browser does authorization-code + PKCE;
# the BFF holds the tokens server-side and gives the Lit SPA an http-only
# cookie. The console authorizes against its own pgauthz store with the
# token's realm roles as team memberships (team:role_<name>), so the realm
# roles below are what makes a person a platform admin there.
resource "keycloak_openid_client" "console_bff" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "console-bff"
  name      = "pgauthz Console (BFF)"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.console_bff_client_secret

  standard_flow_enabled        = true
  direct_access_grants_enabled = false
  service_accounts_enabled     = false

  root_url                        = "https://app.pgauthz.test"
  valid_redirect_uris             = ["https://app.pgauthz.test/console/auth/callback"]
  valid_post_logout_redirect_uris = ["https://app.pgauthz.test/console/"]
  web_origins                     = ["https://app.pgauthz.test"]

  pkce_code_challenge_method = "S256"
}

# The console's tokens carry the API audience too, so the BFF can later call
# pgauthzd on the person's behalf (ADR 0014 PEP client) without a new client.
resource "keycloak_openid_audience_protocol_mapper" "console_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.console_bff.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# Group memberships as a `groups` claim (team:group_<path> in the console).
resource "keycloak_openid_group_membership_protocol_mapper" "console_groups" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.console_bff.id
  name                = "groups"
  claim_name          = "groups"
  full_path           = true
  add_to_access_token = true
  add_to_id_token     = true # the console reads memberships from the ID token
  add_to_userinfo     = false
}

# Platform admin of the console: sees every store, adopts unclaimed ones,
# reassigns owners (examples/models/console: team:role_console_admin#member
# admin platform:default). Not a store role — editing still needs ownership.
resource "keycloak_role" "console_admin_realm" {
  realm_id = keycloak_realm.pgauthz.id
  name     = "console_admin"
}

# subject_type must be on THIS client too (mappers are per-client): the Test
# tab's "as me" mode sends the console token to pgauthzd, whose subject
# resolution reads subject_type + preferred_username from the token.
resource "keycloak_openid_user_attribute_protocol_mapper" "console_subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.console_bff.id
  name                = "subject_type"
  user_attribute      = "subject_type"
  claim_name          = "subject_type"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

# The console derives who signed in and their memberships from the ID token
# (console/README.md → How the access works), so the realm roles go there
# too — the realm-wide "roles" scope puts them into access tokens only.
resource "keycloak_openid_user_realm_role_protocol_mapper" "console_realm_roles_id_token" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.console_bff.id
  name                = "realm roles (ID token)"
  claim_name          = "realm_access.roles"
  multivalued         = true
  add_to_id_token     = true
  add_to_access_token = false
  add_to_userinfo     = false
}
