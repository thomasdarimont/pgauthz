terraform {
  required_version = ">= 1.15.7"

  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = ">= 5.8.0"
    }
  }
}

# Provision the demo realm through the nginx proxy (https://id.pgauthz.test),
# authenticating as the bootstrap admin (admin-cli). The mkcert root CA must be
# trusted on the host running terraform (generate-mkcerts.sh runs `mkcert
# -install`). For a hardened setup, swap to a dedicated `terraform`
# service-account client + client_secret instead of the admin user.
provider "keycloak" {
  client_id = "admin-cli"
  username  = var.kc_admin_username
  password  = var.kc_admin_password
  url       = var.kc_url
}
