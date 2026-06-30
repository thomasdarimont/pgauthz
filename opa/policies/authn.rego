package authn

import future.keywords.if
import future.keywords.in

# JWT verification and claim extraction.
#
# Verifies the Bearer token from input.token against a JWKS — a live issuer
# JWKS_URL when configured (keys fetched + cached, so rotation is picked up), or
# the static mounted file otherwise. Extracts subject identity and roles for the
# authz policy.
#
# Expected JWT claims:
#   sub                — subject identifier (e.g. "alice")
#   preferred_username — display name (optional, falls back to sub)
#   roles              — array of role names (e.g. ["admin", "viewer"])
#   subject_type       — authz user type (e.g. "internal_user", "client_user");
#                        no privileged default — absent → deny (fail closed)
#                        unless DEFAULT_SUBJECT_TYPE is set

import data.authn.config as authn_config

# JWKS source. With JWKS_URL set, fetch the issuer's signing keys live (cached,
# so key rotation is picked up without a restart); otherwise use the static JWKS
# mounted at opa/data/jwks.json — the zero-dependency default the test suite and
# demo keys rely on. OPA merges the mounted file at the data root, so
# {"keys": [...]} becomes data.keys.
jwks := _remote_jwks if authn_config.jwks_url != ""

jwks := {"keys": data.keys} if authn_config.jwks_url == ""

# Fetch + cache the remote JWKS. A fetch failure leaves jwks undefined, so
# decode_verify fails and the token is rejected (fail closed).
_remote_jwks := http.send({
	"method": "GET",
	"url": authn_config.jwks_url,
	"cache": true,
	"force_cache": true,
	"force_cache_duration_seconds": authn_config.jwks_cache_seconds,
}).body

# Verify and decode the token.
# Returns [valid, header, payload].
_token_data := io.jwt.decode_verify(input.token, {
	"cert": json.marshal(jwks),
	"iss": authn_config.required_issuer,
	"aud": authn_config.required_audience,
})

# Token is valid if verification succeeded.
token_is_valid if {
	_token_data[0] == true
}

# Extracted claims from a valid token.
claims := _token_data[2] if token_is_valid

# Subject ID: prefer preferred_username, fall back to sub.
subject_id := claims.preferred_username if {
	token_is_valid
	claims.preferred_username
}

subject_id := claims.sub if {
	token_is_valid
	not claims.preferred_username
}

# Subject type from the token claim. There is intentionally NO hardcoded fallback
# to a privileged type: a token omitting subject_type must not silently become
# internal_user (fail OPEN → too-broad access). When the claim is absent,
# subject_type is left UNSET → the authz policy can't resolve a subject → deny
# (fail closed), unless DEFAULT_SUBJECT_TYPE is configured to an explicit
# (least-privileged) default.
subject_type := claims.subject_type if {
	token_is_valid
	claims.subject_type
}

subject_type := authn_config.default_subject_type if {
	token_is_valid
	not claims.subject_type
	authn_config.default_subject_type != ""
}

# Roles aggregated (set-union) from every configured claim path
# (authn_config.roles_claim_paths, default [["roles"]]). A token's roles may be
# split across claims (e.g. Keycloak's realm_access.roles + resource_access.
# <client>.roles); a missing claim contributes nothing.
roles := {r |
	some path in authn_config.roles_claim_paths
	some r in object.get(claims, path, [])
} if {
	token_is_valid
}
