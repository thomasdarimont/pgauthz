resource "keycloak_realm" "pgauthz" {
  realm        = var.realm_name
  enabled      = true
  display_name = "pgauthz"

  # Demo-friendly token lifetime.
  access_token_lifespan = "30m"

  # Fine-grained admin permissions v2: the `delegate` permission (who may act
  # on whose behalf via token-exchange delegation) lives here — client.agentic.tf.
  admin_permissions_enabled = true
}
