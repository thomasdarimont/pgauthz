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

# ── Token diagnostics (opt-in: TOKEN_DEBUG=true) ──────────────────────────────
# Explains WHY a token is rejected — most often an issuer/audience mismatch
# between the token and OPA's JWT_ISSUER / JWT_AUDIENCE (the classic "everything
# denies and I can't tell why"). Claims are decoded WITHOUT verifying the
# signature, purely to diagnose configuration — this grants nothing. Exposed as
# data.authz.token_debug; returns undefined when disabled or no token.

_unverified := io.jwt.decode(input.token)[1]

_diag_aud := object.get(_unverified, "aud", "")

_aud_set := {a | some a in _diag_aud} if is_array(_diag_aud)

_aud_set := {_diag_aud} if not is_array(_diag_aud)

diag_issuer_ok := object.get(_unverified, "iss", "") == authn_config.required_issuer

diag_audience_ok := authn_config.required_audience in _aud_set

diag_expired := object.get(_unverified, "exp", 0) < (time.now_ns() / 1000000000)

# Complete boolean: token_is_valid is a PARTIAL rule (undefined, not false, for an
# invalid token), so it can't be embedded directly in the object below.
diag_token_accepted if token_is_valid

diag_token_accepted := false if not token_is_valid

diagnostics := d if {
	authn_config.token_debug_enabled
	input.token
	d := {
		"token_accepted": diag_token_accepted,
		"issuer": {
			"in_token": object.get(_unverified, "iss", null),
			"opa_expects": authn_config.required_issuer,
			"ok": diag_issuer_ok,
		},
		"audience": {
			"in_token": object.get(_unverified, "aud", null),
			"opa_expects": authn_config.required_audience,
			"ok": diag_audience_ok,
		},
		"expired": diag_expired,
		"likely_cause": diag_cause,
	}
}

diag_cause := "issuer mismatch — set OPA's JWT_ISSUER to the token's iss" if not diag_issuer_ok

diag_cause := "audience mismatch — set OPA's JWT_AUDIENCE to one of the token's aud" if {
	diag_issuer_ok
	not diag_audience_ok
}

diag_cause := "token expired" if {
	diag_issuer_ok
	diag_audience_ok
	diag_expired
}

diag_cause := "signature invalid / JWKS does not match the issuer's keys" if {
	diag_issuer_ok
	diag_audience_ok
	not diag_expired
	not token_is_valid
}

diag_cause := "token is valid" if token_is_valid

# Per-app DB role from the verified token (authn_config.db_role_claim_path —
# the DB_ROLE_CLAIM env var). Consumed by the write
# path (X-Authz-Role → writer _pre_request) and the read path (X-Authz-Role →
# reader _pre_request_reader) for per-application namespace isolation. Derived
# from CLAIMS only — never from raw input — so a caller cannot pick another
# app's role; the engine hooks additionally validate membership and reject
# admin-capable roles (fail closed).
db_role := role if {
	token_is_valid
	authn_config.db_role_claim_path
	role := object.get(claims, authn_config.db_role_claim_path, "")
	role != ""
}
