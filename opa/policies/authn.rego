package authn

import future.keywords.if
import future.keywords.in

# JWT verification and claim extraction.
#
# Verifies the Bearer token from input.token against a static JWKS file.
# Extracts subject identity and roles for use by the authz policy.
#
# Expected JWT claims:
#   sub                — subject identifier (e.g. "alice")
#   preferred_username — display name (optional, falls back to sub)
#   roles              — array of role names (e.g. ["admin", "viewer"])
#   subject_type       — authz user type (e.g. "internal_user", "client_user")
#                        defaults to "internal_user" if not present

# Load the static JWKS from the mounted data file (opa/data/jwks.json).
# OPA merges JSON at the data root, so {"keys": [...]} becomes data.keys.
jwks := {"keys": data.keys}

import data.authn.config as authn_config

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

# Subject type from token claim, defaulting to "internal_user".
subject_type := claims.subject_type if {
	token_is_valid
	claims.subject_type
}

subject_type := "internal_user" if {
	token_is_valid
	not claims.subject_type
}

# Roles aggregated (set-union) from every configured claim path
# (authn_config.roles_claim_paths, default [["roles"]]). A token's roles may be
# split across claims (e.g. Keycloak's realm_access.roles + resource_access.
# <client>.roles); a missing claim contributes nothing.
roles := {r |
	some path in authn_config.roles_claim_paths
	some r in object.get(claims, path, [])
} if token_is_valid
