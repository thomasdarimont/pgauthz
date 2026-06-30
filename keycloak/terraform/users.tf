# Demo subjects mirroring tests/test-authzen.sh. The subject_type attribute maps
# to the token claim authn.rego reads; the writer role and db_role attribute
# exercise the OPA write path (role aggregation + per-app namespace isolation).

# alice — internal_user, read-only.
resource "keycloak_user" "alice" {
  realm_id   = keycloak_realm.pgauthz.id
  username   = "alice"
  enabled    = true
  email      = "alice@pgauthz.test"
  first_name = "Alice"
  last_name  = "Anderson"
  attributes = { subject_type = "internal_user" }
  initial_password {
    value     = var.demo_user_password
    temporary = false
  }
}

# bob — internal_user, writer via the REALM role (realm_access.roles).
resource "keycloak_user" "bob" {
  realm_id   = keycloak_realm.pgauthz.id
  username   = "bob"
  enabled    = true
  email      = "bob@pgauthz.test"
  first_name = "Bob"
  last_name  = "Brown"
  attributes = { subject_type = "internal_user" }
  initial_password {
    value     = var.demo_user_password
    temporary = false
  }
}

resource "keycloak_user_roles" "bob" {
  realm_id = keycloak_realm.pgauthz.id
  user_id  = keycloak_user.bob.id
  role_ids = [keycloak_role.authz_writer_realm.id]
}

# carol — client_user.
resource "keycloak_user" "carol" {
  realm_id   = keycloak_realm.pgauthz.id
  username   = "carol"
  enabled    = true
  email      = "carol@pgauthz.test"
  first_name = "Carol"
  last_name  = "Clark"
  attributes = { subject_type = "client_user" }
  initial_password {
    value     = var.demo_user_password
    temporary = false
  }
}

# eva — internal_user, writer via the CLIENT role (resource_access.authz-api.roles),
# plus a db_role attribute for per-app namespace isolation.
resource "keycloak_user" "eva" {
  realm_id   = keycloak_realm.pgauthz.id
  username   = "eva"
  enabled    = true
  email      = "eva@pgauthz.test"
  first_name = "Eva"
  last_name  = "Evans"
  attributes = { subject_type = "internal_user" }
  initial_password {
    value     = var.demo_user_password
    temporary = false
  }
}

resource "keycloak_user_roles" "eva" {
  realm_id = keycloak_realm.pgauthz.id
  user_id  = keycloak_user.eva.id
  role_ids = [keycloak_role.authz_writer_client.id]
}
