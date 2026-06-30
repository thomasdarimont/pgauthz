# keycloak/themes

Custom Keycloak login/account themes for the demo. This directory is mounted
into the Keycloak container at `/opt/keycloak/themes` (see `compose-keycloak.yml`),
so changes are picked up live in dev mode.

Drop a theme folder here (e.g. `pgauthz/login/…`) and select it on the realm or
client (`login_theme = "pgauthz"` in Terraform). Empty by default.
