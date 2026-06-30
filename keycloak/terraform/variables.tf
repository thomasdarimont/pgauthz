variable "kc_url" {
  description = "Keycloak base URL (through the nginx proxy; mkcert CA trusted on host)."
  type        = string
  default     = "https://id.pgauthz.test"
}

variable "kc_admin_username" {
  description = "Bootstrap admin username (KC_BOOTSTRAP_ADMIN_USERNAME)."
  type        = string
  default     = "admin"
}

variable "kc_admin_password" {
  description = "Bootstrap admin password (KC_BOOTSTRAP_ADMIN_PASSWORD)."
  type        = string
  default     = "admin"
  sensitive   = true
}

variable "realm_name" {
  description = "Realm to create; its issuer is <kc_url>/realms/<realm_name>."
  type        = string
  default     = "pgauthz"
}

variable "demo_user_password" {
  description = "Initial password for the demo users (alice/bob/carol/eva)."
  type        = string
  default     = "password"
  sensitive   = true
}

variable "authz_api_client_secret" {
  description = "Client secret for the authz-api client, managed explicitly so it is reproducible (get-token.sh / client_credentials). Override for anything real."
  type        = string
  default     = "pgauthz-demo-secret"
  sensitive   = true
}

variable "app_dms_client_secret" {
  description = "Client secret for the app-dms service client (client_credentials demo). Override for anything real."
  type        = string
  default     = "app-dms-demo-secret"
  sensitive   = true
}

variable "playground_bff_client_secret" {
  description = "Client secret for the playground BFF client (must match the BFF's CLIENT_SECRET env). Override for anything real."
  type        = string
  default     = "playground-bff-demo-secret"
  sensitive   = true
}
