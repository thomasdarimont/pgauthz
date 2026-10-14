# ── Agentic delegation demo (examples/agentic) ───────────────────────────────
# Keycloak token-exchange DELEGATION — preview in 26.8, enabled via
# KC_FEATURES=token-exchange-delegation,parameterized-scopes (compose-keycloak.yml):
# a user consents to a client acting on their behalf, and that client exchanges
# the user's token (+ its own) for a DELEGATED token: sub = the user,
# act.client_id = the actor. pgauthzd / OPA map act.client_id to the principal
# agent:<client_id> (ACTOR_CLAIM), so the agent is checked with ITS authority
# in the `agents` store, never the user's.
#
#   acme-app         — the app alice logs in to. Requests the parameterized scope
#                      delegation:client:acme_assist, so her token carries may_act
#                      (consent is mandatory for delegation scopes and is never
#                      stored). Its SERVICE ACCOUNT is the PEP — the agent runtime
#                      that opens a task (writes the agent's task scope, authz_writer)
#                      and closes it. The agent itself never writes its own scope.
#   acme_assist      — the agent (actor client). Confidential + service account +
#                      standard token exchange, and the FGAP v2 `delegate`
#                      permission on Users (below). Named like the agent in
#                      examples/models/agents (agent:acme_assist) so ACTOR_CLAIM
#                      maps it without a lookup table.
#   acme-other-agent — an actor WITHOUT the delegate permission: the negative path
#                      (Keycloak drops the scope at login / refuses the exchange).
#
# All three stamp subject_type=user (the `agents` store's human type) — on the
# user-facing tokens AND on the delegated token (whose claims come from the
# actor client's mappers) — and the authz-api audience OPA/pgauthzd require.

# ── The user-facing app (consent + delegation scope) ─────────────────────────
resource "keycloak_openid_client" "acme_app" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "acme-app"
  name      = "ACME app (delegates to the acme_assist agent)"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.acme_app_client_secret

  # Device Authorization Grant: a browser login + consent with no redirect
  # handling — examples/agentic/delegation-demo.sh drives the login and consent
  # forms itself (or prints the URL for you to open).
  standard_flow_enabled                     = false
  direct_access_grants_enabled              = false
  oauth2_device_authorization_grant_enabled = true
  service_accounts_enabled                  = true # the PEP identity (task open/close)
  consent_required                          = true # delegation scopes REQUIRE consent

  valid_redirect_uris = []
  web_origins         = []
}

# The delegation:client scope is created by Keycloak (parameterized-scopes) as
# an OPTIONAL realm scope; attach it so acme-app may request
# delegation:client:<actor>. This resource REPLACES the client's optional
# scopes, hence the standard ones are listed too.
resource "keycloak_openid_client_optional_scopes" "acme_app" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = keycloak_openid_client.acme_app.id
  optional_scopes = [
    "address", "phone", "offline_access", "microprofile-jwt",
    "delegation:client",
  ]
}

resource "keycloak_openid_audience_protocol_mapper" "acme_app_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.acme_app.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_hardcoded_claim_protocol_mapper" "acme_app_subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.acme_app.id
  name                = "subject_type"
  claim_name          = "subject_type"
  claim_value         = "user"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

# The PEP (acme-app's service account) opens and closes tasks: tuple writes
# (authz_writer) and action-log records (authz_recorder) on pgauthzd-full.
resource "keycloak_openid_client_service_account_realm_role" "acme_app_writer" {
  realm_id                = keycloak_realm.pgauthz.id
  service_account_user_id = keycloak_openid_client.acme_app.service_account_user_id
  role                    = keycloak_role.authz_writer_realm.name
}

resource "keycloak_openid_client_service_account_realm_role" "acme_app_recorder" {
  realm_id                = keycloak_realm.pgauthz.id
  service_account_user_id = keycloak_openid_client.acme_app.service_account_user_id
  role                    = keycloak_role.authz_recorder_realm.name
}

# ── The agent (actor client) ─────────────────────────────────────────────────
resource "keycloak_openid_client" "acme_assist" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "acme_assist"
  name      = "ACME Assist (agent; acts for users via token-exchange delegation)"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.acme_assist_client_secret

  # client_credentials (its actor token) + the token-exchange grant.
  standard_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = true
  standard_token_exchange_enabled = true

  valid_redirect_uris = []
  web_origins         = []
}

# The DELEGATED token's audience and claims come from the ACTOR client's
# mappers (not from the user's original token): keep authz-api + subject_type.
resource "keycloak_openid_audience_protocol_mapper" "acme_assist_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.acme_assist.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_hardcoded_claim_protocol_mapper" "acme_assist_subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.acme_assist.id
  name                = "subject_type"
  claim_name          = "subject_type"
  claim_value         = "user"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}

# ── An actor WITHOUT the delegate permission (negative path) ─────────────────
resource "keycloak_openid_client" "acme_other_agent" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "acme-other-agent"
  name      = "Some other agent (no delegate permission)"
  enabled   = true

  access_type   = "CONFIDENTIAL"
  client_secret = var.acme_other_agent_client_secret

  standard_flow_enabled           = false
  direct_access_grants_enabled    = false
  service_accounts_enabled        = true
  standard_token_exchange_enabled = true

  valid_redirect_uris = []
  web_origins         = []
}

# ── Who may act for whom: FGAP v2 `delegate` on Users ────────────────────────
# Fine-grained admin permissions v2 (admin_permissions_enabled on the realm,
# realm.tf) give Keycloak an `admin-permissions` resource server. A
# `delegate`-scoped permission on the Users resource, granted to a CLIENT
# policy naming acme_assist, is what lets alice's login add may_act for it —
# without it the delegation scope is silently dropped (no consent, no may_act).
data "keycloak_openid_client" "admin_permissions" {
  realm_id   = keycloak_realm.pgauthz.id
  client_id  = "admin-permissions"
  depends_on = [keycloak_realm.pgauthz]
}

resource "keycloak_openid_client_client_policy" "acme_assist_delegator" {
  realm_id           = keycloak_realm.pgauthz.id
  resource_server_id = data.keycloak_openid_client.admin_permissions.id
  name               = "acme_assist-is-a-delegate"
  description        = "The acme_assist agent (its service account) may act for users"
  clients            = [keycloak_openid_client.acme_assist.id]
  logic              = "POSITIVE"
  decision_strategy  = "UNANIMOUS"
}

# The `delegate` scope on Users exists once token-exchange-delegation is on.
# (The provider's typed keycloak_users_admin_permissions resource does not know
# this scope yet — 5.10.0 lists view/manage/map-roles/manage-group-membership/
# impersonate — so the generic permission resource is used, with resource_type
# = "Users" meaning "all users", exactly what the admin console creates.)
data "keycloak_openid_client_authorization_scope" "users_delegate" {
  realm_id           = keycloak_realm.pgauthz.id
  resource_server_id = data.keycloak_openid_client.admin_permissions.id
  name               = "delegate"
}

resource "keycloak_openid_client_authorization_permission" "delegate_to_acme_assist" {
  realm_id           = keycloak_realm.pgauthz.id
  resource_server_id = data.keycloak_openid_client.admin_permissions.id
  name               = "delegate-all-users-to-acme_assist"
  description        = "Any user may delegate to acme_assist (consent is still asked at every login)"
  type               = "scope"
  resource_type      = "Users"
  scopes             = [data.keycloak_openid_client_authorization_scope.users_delegate.id]
  policies           = [keycloak_openid_client_client_policy.acme_assist_delegator.id]
  decision_strategy  = "UNANIMOUS"
}
