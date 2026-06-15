package authz

import future.keywords.if
import future.keywords.in

import data.authn
import data.authn.config as authn_config
import data.authz.pgauthz
import data.authz.pgauthz.config

# -----------------------------------------------------------------------
# OPA-fronted tuple writes.
#
# The writer PostgREST instance runs as a fixed authz_writer role and does NOT
# verify JWTs. OPA is the front door: it verifies the ES256 token, requires the
# configured writer role (authn_config.writer_role) in the configured roles
# claim (authn_config.roles_claim_path), and only then forwards the write/delete
# to the writer — recording the authenticated subject as the audit author.
#
# Input:
#   {
#     "token":     "eyJ...",            # required — identifies + authorizes the caller
#     "store":     "demo",              # optional — defaults to config.default_store
#     "operation": "write" | "delete",
#     "tuple": {
#       "user_type": "...", "user_id": "...", "relation": "...",
#       "object_type": "...", "object_id": "...",
#       "user_relation": "...",         # optional
#       "condition": "...",             # optional (write only)
#       "condition_context": {...}      # optional (write only)
#     }
#   }
#
# Result (data.authz.write):
#   {"allowed": true,  "result": {"status": 200, "body": <pg return>}}
#   {"allowed": false, "error": "not_authorized" | "invalid_request"}
# -----------------------------------------------------------------------

default write := {"allowed": false, "error": "not_authorized"}

# Read-only deployment: no writer instance configured (POSTGREST_WRITER_URL
# unset) → writes are cleanly disabled. OPA can still reach the read path.
write := {"allowed": false, "error": "writes_disabled"} if not config.postgrest_writer_url

# Authorized but malformed — distinguish from an auth failure.
write := {"allowed": false, "error": "invalid_request"} if {
	config.postgrest_writer_url
	_write_authorized
	not _valid_write_request
}

write := {"allowed": true, "result": pgauthz.write_tuple(_store, input.tuple, _performed_by)} if {
	config.postgrest_writer_url
	_write_authorized
	_valid_write_request
	input.operation == "write"
}

write := {"allowed": true, "result": pgauthz.delete_tuple(_store, input.tuple, _performed_by)} if {
	config.postgrest_writer_url
	_write_authorized
	_valid_write_request
	input.operation == "delete"
}

# Authorized iff a valid token carries the configured writer role.
_write_authorized if {
	input.token
	authn.token_is_valid
	authn_config.writer_role in authn.roles
}

# A well-formed request: a known operation and the required tuple fields.
_valid_write_request if {
	input.operation in {"write", "delete"}
	input.tuple.user_type
	input.tuple.user_id
	input.tuple.relation
	input.tuple.object_type
	input.tuple.object_id
}

_store := input.store if input.store

_store := config.default_store if not input.store

# The audit author is the authenticated subject (defined when token is valid).
_performed_by := authn.subject_id
