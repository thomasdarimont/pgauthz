# pgauthz client scopes — what a token is FOR, named in its `scope` claim and
# carrying the API audience with it, so a client that holds a scope gets the
# audience and one that lacks it gets neither. The scopes are the token's own
# cap on what the management console grants the subject (pgauthzd admin API,
# delegated admin rules — pgauthzd/README.md → Admin API):
#
#   pgauthz:test     run fixtures (POST /pgauthz/v1/admin/models/test) on the
#                    stores the console grants
#   pgauthz:read     the GET verbs on those stores
#   pgauthz:manage   writes on those stores (apply a model, settings, recorders,
#                    namespaces), test and read included
#   pgauthz:ci       a pipeline's token: whatever the console grants it on stores
#                    and the registry (test, plan, apply, publish), never the
#                    issuers — platform admins shape CI access in the console
#   pgauthz:admin    everything, the platform included (issuers, the registry,
#                    creating stores) — what the console's own sessions carry
#
# In the management console, pgauthz:test on a session's token is what opens
# the Test pages (a session without it sees no Test tab, whatever the store
# grants); console-bff therefore carries it by default.
#
# Two audiences travel with every scope: the API's client id (authz-api, what
# Keycloak puts in `aud` by default) and the API's URI (https://api.pgauthz.test,
# what other identity providers put there). pgauthzd accepts either
# (compose-keycloak.yml: "audience" + "audiences").

locals {
  pgauthz_scopes = {
    test   = "pgauthz admin API: run model test fixtures on the stores the console grants"
    read   = "pgauthz admin API: read those stores"
    manage = "pgauthz admin API: manage those stores (test and read included)"
    ci     = "pgauthz admin API as a pipeline: whatever the console grants on stores and the registry, never the issuers"
    admin  = "pgauthz admin API: everything, the platform included — the management console's own sessions"
  }
  pgauthz_api_uri = "https://api.pgauthz.test"
}

resource "keycloak_openid_client_scope" "pgauthz" {
  for_each               = local.pgauthz_scopes
  realm_id               = keycloak_realm.pgauthz.id
  name                   = "pgauthz:${each.key}"
  description            = each.value
  include_in_token_scope = true
}

resource "keycloak_openid_audience_protocol_mapper" "pgauthz_aud_client" {
  for_each                 = local.pgauthz_scopes
  realm_id                 = keycloak_realm.pgauthz.id
  client_scope_id          = keycloak_openid_client_scope.pgauthz[each.key].id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

resource "keycloak_openid_audience_protocol_mapper" "pgauthz_aud_uri" {
  for_each                 = local.pgauthz_scopes
  realm_id                 = keycloak_realm.pgauthz.id
  client_scope_id          = keycloak_openid_client_scope.pgauthz[each.key].id
  name                     = "audience-api-uri"
  included_custom_audience = local.pgauthz_api_uri
  add_to_access_token      = true
  add_to_id_token          = false
}

# Who carries which scope by default. The resources REPLACE the clients'
# default / optional scopes, hence the standard ones are listed too.
#   authz-api    the demo users' tokens (get-token.sh alice): manage by default;
#                admin, read and test on request (SCOPE="pgauthz:admin" get-token.sh alice)
#   console-bff  the management console's sessions call the admin API as the
#                person: admin — the console store decides what the person may
#   ci           (client.ci.tf) pgauthz:ci
resource "keycloak_openid_client_default_scopes" "authz_api" {
  realm_id       = keycloak_realm.pgauthz.id
  client_id      = keycloak_openid_client.authz_api.id
  default_scopes = ["basic", "acr", "roles", "profile", "email", "web-origins", keycloak_openid_client_scope.pgauthz["manage"].name]
}

resource "keycloak_openid_client_optional_scopes" "authz_api" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = keycloak_openid_client.authz_api.id
  optional_scopes = [
    "address", "phone", "offline_access", "microprofile-jwt",
    keycloak_openid_client_scope.pgauthz["admin"].name,
    keycloak_openid_client_scope.pgauthz["read"].name,
    keycloak_openid_client_scope.pgauthz["test"].name,
    keycloak_openid_client_scope.pgauthz["ci"].name,
  ]
}

resource "keycloak_openid_client_default_scopes" "console_bff" {
  realm_id       = keycloak_realm.pgauthz.id
  client_id      = keycloak_openid_client.console_bff.id
  default_scopes = ["basic", "acr", "roles", "profile", "email", "web-origins", keycloak_openid_client_scope.pgauthz["admin"].name, keycloak_openid_client_scope.pgauthz["test"].name]
}
