resource "keycloak_realm" "pgauthz" {
  realm        = var.realm_name
  enabled      = true
  display_name = "pgauthz"

  # Demo-friendly token lifetime.
  access_token_lifespan = "30m"

  # Fine-grained admin permissions v2: the `delegate` permission (who may act
  # on whose behalf via token-exchange delegation) lives here — client.agentic.tf.
  admin_permissions_enabled = true

  # CIBA policy (examples/agentic step-up consent): poll mode — the PEP polls the
  # token endpoint with its auth_req_id every `cibaInterval` seconds until the
  # out-of-band answer arrives or the request expires. These are Keycloak's
  # defaults, spelled out; the user is addressed by login_hint (= username).
  attributes = {
    cibaBackchannelTokenDeliveryMode = "poll"
    cibaExpiresIn                    = "120"
    cibaInterval                     = "5"
    cibaAuthRequestedUserHint        = "login_hint"
  }
}
