resource "keycloak_realm" "pgauthz" {
  realm        = var.realm_name
  enabled      = true
  display_name = "pgauthz"

  # Demo-friendly token lifetime.
  access_token_lifespan = "30m"
}
