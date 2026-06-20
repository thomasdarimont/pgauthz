package authn.config

import future.keywords.if

_env := opa.runtime().env

# Required JWT issuer (iss claim).
# Set via JWT_ISSUER env var on the OPA service.
required_issuer := _env.JWT_ISSUER

# Required JWT audience (aud claim).
# Set via JWT_AUDIENCE env var on the OPA service.
required_audience := _env.JWT_AUDIENCE

# Paths to the roles claim(s) inside the JWT, as a comma-separated list of
# dot-separated paths. Roles are aggregated (set-union) across ALL of them, so a
# token's required role may live in any one — useful for issuers that split
# roles across claims. Defaults to "roles". Examples:
#   JWT_ROLES_CLAIM=roles
#   JWT_ROLES_CLAIM=realm_access.roles,resource_access.authz-api.roles   # Keycloak
# (realm roles + this client's roles; the client_id is fixed per deployment.)
roles_claim_paths := [split(trim(p, " "), ".") | some p in split(_env.JWT_ROLES_CLAIM, ",")] if _env.JWT_ROLES_CLAIM

roles_claim_paths := [["roles"]] if not _env.JWT_ROLES_CLAIM

# Role value (within the roles claim) that authorizes tuple writes.
# Defaults to "authz_writer"; set WRITER_ROLE to your issuer's role name.
writer_role := _env.WRITER_ROLE if _env.WRITER_ROLE

writer_role := "authz_writer" if not _env.WRITER_ROLE

# Optional: JWT claim (dot-separated path) carrying the caller's per-app DB role
# for namespace isolation. When set, the write path forwards that role to the
# writer as the X-Authz-Role header, and authz._pre_request() SET LOCAL ROLEs to
# it so namespace enforcement applies per app. Unset → no header (writer stays
# the fixed authz_writer). Set via WRITER_DB_ROLE_CLAIM, e.g. "db_role".
writer_db_role_claim_path := split(_env.WRITER_DB_ROLE_CLAIM, ".") if _env.WRITER_DB_ROLE_CLAIM
