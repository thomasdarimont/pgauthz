package authn.config

import future.keywords.if

_env := opa.runtime().env

# Required JWT issuer (iss claim).
# Set via JWT_ISSUER env var on the OPA service.
required_issuer := _env.JWT_ISSUER

# Required JWT audience (aud claim).
# Set via JWT_AUDIENCE env var on the OPA service.
required_audience := _env.JWT_AUDIENCE

# Optional JWKS source URL (e.g. an OIDC provider's JWKS / certs endpoint). When
# set, OPA fetches and caches the signing keys from here, so issuer key rotation
# is picked up live; when unset, it falls back to the static mounted JWKS file
# (opa/data/jwks.json). Set via JWKS_URL, e.g.
#   JWKS_URL=http://keycloak:8080/realms/pgauthz/protocol/openid-connect/certs
jwks_url := _env.JWKS_URL if _env.JWKS_URL

jwks_url := "" if not _env.JWKS_URL

# Cache lifetime (seconds) for a fetched JWKS. Default 300.
jwks_cache_seconds := to_number(_env.JWKS_CACHE_SECONDS) if _env.JWKS_CACHE_SECONDS

jwks_cache_seconds := 300 if not _env.JWKS_CACHE_SECONDS

# Optional fallback subject type for tokens that omit the subject_type claim.
# UNSET by default → such tokens fail CLOSED (no subject type resolved → the
# authz policy denies) rather than silently defaulting to a privileged type like
# internal_user (which would grant too-broad access). Set DEFAULT_SUBJECT_TYPE
# only if you trust the issuer to scope it, and choose your LEAST-privileged type.
default_subject_type := _env.DEFAULT_SUBJECT_TYPE if _env.DEFAULT_SUBJECT_TYPE

default_subject_type := "" if not _env.DEFAULT_SUBJECT_TYPE

# Opt-in token diagnostics (data.authz.token_debug). When TOKEN_DEBUG=true, OPA
# explains WHY a token is rejected (issuer/audience/expiry/signature) — the common
# "everything silently denies" misconfiguration. Off by default so the expected
# issuer/audience are not exposed to arbitrary callers in production.
token_debug_enabled := object.get(_env, "TOKEN_DEBUG", "") == "true"

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

# Optional: JWT claim (dot-separated path) carrying the caller's per-app DB
# role for namespace isolation, used by BOTH the write path and the read path.
# When set, OPA forwards that role to pgauthzd's native callback as the
# X-Authz-Role header; pgauthzd validates it (reader for reads, writer for
# writes; never admin) and SET LOCAL ROLEs to it, so namespace enforcement
# applies per application.
# Unset → no header (the callback runs as its connection's role: authz_writer
# on the writer, authz_reader on the reader).
# Set via DB_ROLE_CLAIM, e.g. "db_role".
db_role_claim_path := split(_env.DB_ROLE_CLAIM, ".") if _env.DB_ROLE_CLAIM
