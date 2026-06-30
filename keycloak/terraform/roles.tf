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
