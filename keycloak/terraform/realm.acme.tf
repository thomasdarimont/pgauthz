# ACME — a second realm: a TENANT's identity provider, the issuer
# https://id.pgauthz.test/realms/acme, brought into pgauthz as a GROUP ISSUER
# of the store group `acme` (ADR 0017; examples/tenants/acme sets the group,
# its stores and the binding up). Self-contained: its own API client (the
# audience), the pgauthz:* scopes, a console-bff client the management
# console registers as a sign-in provider, and four personas — one realm
# role each, which the console turns into team memberships
# (team:role_<name>) that examples/tenants/acme/setup.sql grants on the group:
#
#   acme-admin    acme_group_admin  the store group's admin: every store, its admins, its IdP
#   acme-iam      acme_iam_lead     IAM team lead: the group's identity provider + its models
#   acme-auditor  acme_auditor      auditor: activity and decisions of the group's stores
#   acme-dev      acme_developer    developer: views the models, tests their own access
#
# Usernames are prefixed: the console identifies a person by the token's
# preferred_username whatever the issuer, so a tenant user named like a
# platform user would be the same subject in the console store.

locals {
  acme_roles = {
    acme_group_admin = "ACME store group admin: administers every store of the group, its admins and its identity provider"
    acme_iam_lead    = "ACME IAM team lead: the group's identity provider and its models"
    acme_auditor     = "ACME auditor: activity and decisions of the group's stores, read-only"
    acme_developer   = "ACME developer: views the models and tests their own access"
  }
  acme_users = {
    "acme-admin"   = { first = "Grace", last = "Groupadmin", role = "acme_group_admin" }
    "acme-iam"     = { first = "Ivan", last = "Identity", role = "acme_iam_lead" }
    "acme-auditor" = { first = "Audra", last = "Audit", role = "acme_auditor" }
    "acme-dev"     = { first = "Devin", last = "Developer", role = "acme_developer" }
  }
}

resource "keycloak_realm" "acme" {
  realm                 = "acme"
  enabled               = true
  display_name          = "ACME"
  access_token_lifespan = "30m"
}

resource "keycloak_role" "acme" {
  for_each    = local.acme_roles
  realm_id    = keycloak_realm.acme.id
  name        = each.key
  description = each.value
}

resource "keycloak_user" "acme" {
  for_each   = local.acme_users
  realm_id   = keycloak_realm.acme.id
  username   = each.key
  enabled    = true
  email      = "${each.key}@acme.test"
  first_name = each.value.first
  last_name  = each.value.last
  initial_password {
    value     = var.demo_user_password
    temporary = false
  }
}

resource "keycloak_user_roles" "acme" {
  for_each = local.acme_users
  realm_id = keycloak_realm.acme.id
  user_id  = keycloak_user.acme[each.key].id
  role_ids = [keycloak_role.acme[each.value.role].id]
}

# ── The API client: the audience of the realm's tokens (authz-api, as in the
# pgauthz realm; pgauthzd accepts the client id or the API's URI) ───────────
resource "keycloak_openid_client" "acme_authz_api" {
  realm_id      = keycloak_realm.acme.id
  client_id     = "authz-api"
  name          = "pgauthz API (ACME)"
  enabled       = true
  access_type   = "CONFIDENTIAL"
  client_secret = var.acme_authz_api_client_secret

  standard_flow_enabled        = false
  direct_access_grants_enabled = true # REALM=acme ./keycloak/get-token.sh acme-dev
  service_accounts_enabled     = true
  valid_redirect_uris          = []
  web_origins                  = []
}

resource "keycloak_openid_audience_protocol_mapper" "acme_authz_api_aud" {
  realm_id                 = keycloak_realm.acme.id
  client_id                = keycloak_openid_client.acme_authz_api.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.acme_authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# ── The pgauthz:* scopes (scopes.pgauthz.tf), per realm ─────────────────────
resource "keycloak_openid_client_scope" "acme_pgauthz" {
  for_each               = local.pgauthz_scopes
  realm_id               = keycloak_realm.acme.id
  name                   = "pgauthz:${each.key}"
  description            = each.value
  include_in_token_scope = true
}

resource "keycloak_openid_audience_protocol_mapper" "acme_pgauthz_aud_client" {
  for_each                 = local.pgauthz_scopes
  realm_id                 = keycloak_realm.acme.id
  client_scope_id          = keycloak_openid_client_scope.acme_pgauthz[each.key].id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.acme_authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_audience_protocol_mapper" "acme_pgauthz_aud_uri" {
  for_each                 = local.pgauthz_scopes
  realm_id                 = keycloak_realm.acme.id
  client_scope_id          = keycloak_openid_client_scope.acme_pgauthz[each.key].id
  name                     = "audience-api-uri"
  included_custom_audience = local.pgauthz_api_uri
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_client_default_scopes" "acme_authz_api" {
  realm_id       = keycloak_realm.acme.id
  client_id      = keycloak_openid_client.acme_authz_api.id
  default_scopes = ["basic", "acr", "roles", "profile", "email", "web-origins", keycloak_openid_client_scope.acme_pgauthz["manage"].name]
}

resource "keycloak_openid_client_optional_scopes" "acme_authz_api" {
  realm_id  = keycloak_realm.acme.id
  client_id = keycloak_openid_client.acme_authz_api.id
  optional_scopes = [
    "address", "phone", "offline_access", "microprofile-jwt",
    keycloak_openid_client_scope.acme_pgauthz["admin"].name,
    keycloak_openid_client_scope.acme_pgauthz["read"].name,
    keycloak_openid_client_scope.acme_pgauthz["test"].name,
    keycloak_openid_client_scope.acme_pgauthz["ci"].name,
  ]
}

# ── The console's client at this provider: the management console registers
# it as a sign-in provider of the group (Platform → Issuers → Console sign-in
# through this provider; examples/tenants/acme/setup.sh does it) ─────────────
resource "keycloak_openid_client" "acme_console_bff" {
  realm_id      = keycloak_realm.acme.id
  client_id     = "console-bff"
  name          = "pgauthz Console (BFF)"
  enabled       = true
  access_type   = "CONFIDENTIAL"
  client_secret = var.acme_console_bff_client_secret

  standard_flow_enabled        = true
  direct_access_grants_enabled = false
  service_accounts_enabled     = false

  root_url                        = "https://app.pgauthz.test"
  valid_redirect_uris             = ["https://app.pgauthz.test/console/auth/callback"]
  valid_post_logout_redirect_uris = ["https://app.pgauthz.test/console/"]
  web_origins                     = ["https://app.pgauthz.test"]
  pkce_code_challenge_method      = "S256"
}

# The console calls pgauthzd's admin API with the person's own token: the
# audience, and the realm roles the console reads from the ID token.
resource "keycloak_openid_audience_protocol_mapper" "acme_console_aud" {
  realm_id                 = keycloak_realm.acme.id
  client_id                = keycloak_openid_client.acme_console_bff.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.acme_authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_user_realm_role_protocol_mapper" "acme_console_realm_roles_id_token" {
  realm_id            = keycloak_realm.acme.id
  client_id           = keycloak_openid_client.acme_console_bff.id
  name                = "realm roles (ID token)"
  claim_name          = "realm_access.roles"
  multivalued         = true
  add_to_id_token     = true
  add_to_access_token = false
  add_to_userinfo     = false
}

resource "keycloak_openid_group_membership_protocol_mapper" "acme_console_groups" {
  realm_id            = keycloak_realm.acme.id
  client_id           = keycloak_openid_client.acme_console_bff.id
  name                = "groups"
  claim_name          = "groups"
  full_path           = true
  add_to_access_token = true
  add_to_id_token     = true
  add_to_userinfo     = false
}

resource "keycloak_openid_client_default_scopes" "acme_console_bff" {
  realm_id       = keycloak_realm.acme.id
  client_id      = keycloak_openid_client.acme_console_bff.id
  default_scopes = ["basic", "acr", "roles", "profile", "email", "web-origins", keycloak_openid_client_scope.acme_pgauthz["admin"].name, keycloak_openid_client_scope.acme_pgauthz["test"].name]
}

output "acme_issuer" {
  description = "The ACME tenant's issuer — a group issuer of store group acme (examples/tenants/acme)."
  value       = "${var.kc_url}/realms/acme"
}

output "acme_authz_api_client_secret" {
  description = "Client secret of the ACME realm's authz-api (REALM=acme get-token.sh)."
  value       = keycloak_openid_client.acme_authz_api.client_secret
  sensitive   = true
}

output "acme_console_bff_client_secret" {
  description = "Client secret of the ACME realm's console-bff (the console's sign-in registration)."
  value       = keycloak_openid_client.acme_console_bff.client_secret
  sensitive   = true
}
