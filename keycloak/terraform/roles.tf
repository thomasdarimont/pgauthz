# Writer role reachable two ways, to exercise OPA's role aggregation across
# realm_access.roles + resource_access.authz-api.roles (JWT_ROLES_CLAIM).

# Realm role → appears in realm_access.roles.
resource "keycloak_role" "authz_writer_realm" {
  realm_id = keycloak_realm.pgauthz.id
  name     = "authz_writer"
}

# Client role on authz-api → appears in resource_access.authz-api.roles.
resource "keycloak_role" "authz_writer_client" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = keycloak_openid_client.authz_api.id
  name      = "authz_writer"
}

# Auditor role: authorizes the AuthZEN reverse-search endpoints (search/subject|
# resource|action), which enumerate the access graph. Named authzen_auditor (not
# authz_admin) to avoid confusion with the PostgreSQL roles in db/security. Realm
# role → realm_access.roles (matched by authzen-opa's SEARCH_REQUIRED_ROLE).
resource "keycloak_role" "authzen_auditor_realm" {
  realm_id = keycloak_realm.pgauthz.id
  name     = "authzen_auditor"
}

# Recorder role: authorizes POST /pgauthz/v1/events (+ /events/reserve) on
# pgauthzd-full (RECORDER_ROLE) — the action log that temporal gates decide on.
# In production this is a PEP/ingestion-service credential, never an end-user
# role (a holder can move a gate); the demo users hold it ONLY so the playground
# can show gates working end to end. Realm role → realm_access.roles.
resource "keycloak_role" "authz_recorder_realm" {
  realm_id = keycloak_realm.pgauthz.id
  name     = "authz_recorder"
}

# Playground admin: may reset (purge) an allowlisted demo store's action log
# through the BFF (PLAYGROUND_RESET_ROLE) so a gate demo can be repeated.
resource "keycloak_role" "playground_admin_realm" {
  realm_id = keycloak_realm.pgauthz.id
  name     = "playground_admin"
}
