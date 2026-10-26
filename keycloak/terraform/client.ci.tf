# ci — a CI pipeline's service account (client_credentials): what
# `pgauthzctl model test … --server` runs as in a job, with a token instead
# of database access. get-token.sh --service ci.
resource "keycloak_openid_client" "ci" {
  realm_id                     = keycloak_realm.pgauthz.id
  client_id                    = "ci"
  name                         = "CI pipeline"
  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = true
  full_scope_allowed           = false
}

# No role at all: pgauthzd's admin rule for this issuer names the client AND
# requires the pgauthz:test scope, and the management console's store decides
# which stores it may test (`azp` ci → service_account:ci, granted `tester`
# on a store in the console's Access tab; compose-keycloak.yml). The token
# says what it is for and carries nothing worth stealing;
# full_scope_allowed = false keeps the realm's default roles (offline_access,
# the account client) out of it.

# only what pgauthzd reads: sub and azp (basic) and the pgauthz:test scope,
# which brings the authz-api audience (scopes.pgauthz.tf); no profile/email,
# no roles
resource "keycloak_openid_client_default_scopes" "ci" {
  realm_id       = keycloak_realm.pgauthz.id
  client_id      = keycloak_openid_client.ci.id
  default_scopes = ["basic", keycloak_openid_client_scope.pgauthz["test"].name]
}

output "ci_client_secret" {
  value     = keycloak_openid_client.ci.client_secret
  sensitive = true
}
