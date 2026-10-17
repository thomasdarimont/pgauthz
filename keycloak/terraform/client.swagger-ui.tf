# swagger-ui — the PUBLIC client pgauthzd's embedded Swagger UI logs in with
# (SWAGGER_UI_ENABLED + SWAGGER_UI_OIDC_ISSUER/CLIENT_ID, see pgauthzd/README.md):
# authorization code + PKCE from the browser, no secret (a browser cannot keep
# one), the token held by the UI only. Redirect URIs are the UI's own
# oauth2-redirect.html on every origin the demo serves pgauthzd on; web origins
# let the browser call Keycloak's token endpoint from those origins (CORS).
resource "keycloak_openid_client" "swagger_ui" {
  realm_id  = keycloak_realm.pgauthz.id
  client_id = "swagger-ui"
  name      = "pgauthzd Swagger UI (embedded, PKCE)"
  enabled   = true

  access_type = "PUBLIC"

  standard_flow_enabled        = true # authorization code (+ PKCE, enforced below)
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false

  # The instances this overlay points at Keycloak (compose-keycloak.yml):
  # pgauthzd-opa (:8091, also api.pgauthz.test through the proxy) and
  # pgauthzd-full (:8092). pgauthzd-decision (:8090) trusts the self-minted demo
  # issuer only, so it is not a redirect target.
  valid_redirect_uris = [
    "http://localhost:8091/pgauthz/v1/docs/oauth2-redirect.html",
    "http://localhost:8092/pgauthz/v1/docs/oauth2-redirect.html",
    "https://api.pgauthz.test/pgauthz/v1/docs/oauth2-redirect.html",
  ]
  web_origins = [
    "http://localhost:8091",
    "http://localhost:8092",
    "https://api.pgauthz.test",
  ]

  # Public client: PKCE S256 is mandatory, Keycloak rejects a code flow without it.
  pkce_code_challenge_method = "S256"
}

# Tokens must carry the API audience pgauthzd requires (authz-api).
resource "keycloak_openid_audience_protocol_mapper" "swagger_ui_aud" {
  realm_id                 = keycloak_realm.pgauthz.id
  client_id                = keycloak_openid_client.swagger_ui.id
  name                     = "audience-authz-api"
  included_client_audience = keycloak_openid_client.authz_api.client_id
  add_to_access_token      = true
  add_to_id_token          = false
}

# subject_type is per client (mappers are), else the UI's tokens lack it and
# the fail-closed rule denies everything.
resource "keycloak_openid_user_attribute_protocol_mapper" "swagger_ui_subject_type" {
  realm_id            = keycloak_realm.pgauthz.id
  client_id           = keycloak_openid_client.swagger_ui.id
  name                = "subject_type"
  user_attribute      = "subject_type"
  claim_name          = "subject_type"
  claim_value_type    = "String"
  add_to_access_token = true
  add_to_id_token     = false
  add_to_userinfo     = false
}
