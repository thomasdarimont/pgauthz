output "issuer" {
  description = "OIDC issuer — set OPA's JWT_ISSUER to this."
  value       = "${var.kc_url}/realms/${var.realm_name}"
}

output "token_endpoint" {
  value = "${var.kc_url}/realms/${var.realm_name}/protocol/openid-connect/token"
}

output "jwks_uri" {
  description = "Public JWKS URL. OPA fetches keys over the internal backchannel instead."
  value       = "${var.kc_url}/realms/${var.realm_name}/protocol/openid-connect/certs"
}

output "authz_api_client_secret" {
  description = "Client secret for authz-api (client_credentials / get-token.sh --service)."
  value       = keycloak_openid_client.authz_api.client_secret
  sensitive   = true
}

output "app_dms_client_secret" {
  description = "Client secret for app-dms (get-token.sh --service app-dms)."
  value       = keycloak_openid_client.app_dms.client_secret
  sensitive   = true
}
