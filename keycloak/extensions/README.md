# keycloak/extensions

Keycloak SPI provider JARs (custom authenticators, mappers, event listeners,
…). This directory is mounted into the container at `/opt/keycloak/providers`
(see `compose-keycloak.yml`); Keycloak picks up JARs here on (re)start.

Drop built `*.jar` providers here. Empty by default. Prefer committing build
config over built artifacts — add a `.gitignore` for `*.jar` if you wire a build.
