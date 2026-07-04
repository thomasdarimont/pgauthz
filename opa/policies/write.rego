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
# Operations:
#   "write"  / "delete"        → single tuple (input.tuple)
#   "write_batch" / "delete_batch" → array of tuples (input.tuples)
#   "delete_user"              → all tuples for a subject (input.user) [offboarding]
#
# Input:
#   {
#     "token":     "eyJ...",            # required — identifies + authorizes the caller
#     "store":     "demo",              # optional — defaults to config.default_store
#     "operation": "write" | "delete" | "write_batch" | "delete_batch" | "delete_user",
#     "tuple":  { "user_type", "user_id", "relation", "object_type", "object_id",
#                 "user_relation"?, "condition"?, "condition_context"? },  # write/delete
#     "tuples": [ {<tuple>}, ... ],                                        # *_batch
#     "user":   { "user_type", "user_id" }                                # delete_user
#   }
#
# Result (data.authz.write):
#   {"allowed": true,  "result": {"status": 200, "body": <pg return>}}
#   {"allowed": false, "error": "not_authorized" | "invalid_request" | "writes_disabled"}
#
# Admin/model operations (create_store, model_*, namespace, OpenFGA import) are
# intentionally NOT exposed here — run them as authz_admin via direct SQL.
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

# Authorized + well-formed → dispatch to the matching writer call.
write := {"allowed": true, "result": _forward} if {
	config.postgrest_writer_url
	_write_authorized
	_valid_write_request
}

# Operation dispatch — each clause is selected by input.operation.
_forward := pgauthz.write_tuple(_store, input.tuple, _performed_by, _headers) if input.operation == "write"

_forward := pgauthz.delete_tuple(_store, input.tuple, _performed_by, _headers) if input.operation == "delete"

_forward := pgauthz.write_tuples(_store, input.tuples, _performed_by, _headers) if input.operation == "write_batch"

_forward := pgauthz.delete_tuples(_store, input.tuples, _performed_by, _headers) if input.operation == "delete_batch"

_forward := pgauthz.delete_user_tuples(_store, input.user, _performed_by, _headers) if input.operation == "delete_user"

# Conditional / atomic write: check preconditions, then apply deletes + writes.
_forward := pgauthz.write_tuples_checked(
	_store,
	object.get(input, "preconditions", []),
	object.get(input, "deletes", []),
	object.get(input, "writes", []),
	_performed_by, _headers,
) if input.operation == "write_checked"

# Headers forwarded to the writer: JSON content type, plus the caller's per-app
# DB role as X-Authz-Role when a db-role claim is configured and present in the
# token. authz._pre_request() on the writer SET LOCAL ROLEs to it for namespace
# isolation. Absent claim → no header → the writer stays the fixed authz_writer.
_headers := object.union(
	object.union({"Content-Type": "application/json"}, _role_header),
	_consistency_header,
)

_role_header := {"X-Authz-Role": _db_role} if _db_role

_role_header := {} if not _db_role

# Per-write consistency mode, forwarded to the writer's _pre_request() hook
# (X-Authz-Consistency → SET LOCAL synchronous_commit). Vocabulary:
#   applied  — ack only after every synchronous standby APPLIED the write
#              (strict revocation); durable — flushed on sync standbys;
#   eventual — primary-only durability. Absent → the writer connection's
# default (remote_apply in the shipped compose/Helm). The engine fails closed
# on unknown values.
# Forwarded verbatim — the engine's _pre_request() is the single validator and
# FAILS CLOSED with a clear error on unknown values (a silently dropped mode
# here would downgrade the guarantee instead).
_consistency_header := {"X-Authz-Consistency": input.consistency} if input.consistency

_consistency_header := {} if not input.consistency

_db_role := role if {
	authn_config.writer_db_role_claim_path
	role := object.get(authn.claims, authn_config.writer_db_role_claim_path, "")
	role != ""
}

# Authorized iff a valid token carries the configured writer role.
_write_authorized if {
	input.token
	authn.token_is_valid
	authn_config.writer_role in authn.roles
}

# A well-formed request, per operation.
_valid_write_request if {
	input.operation in {"write", "delete"}
	_valid_tuple(input.tuple)
}

_valid_write_request if {
	input.operation in {"write_batch", "delete_batch"}
	is_array(input.tuples)
	count(input.tuples) > 0
	every t in input.tuples { _valid_tuple(t) }
}

_valid_write_request if {
	input.operation == "delete_user"
	input.user.user_type
	input.user.user_id
}

# write_checked carries preconditions/deletes/writes arrays — the DB function
# validates their tuple shapes and the precondition semantics.
_valid_write_request if {
	input.operation == "write_checked"
}

# The five identifying fields every tuple needs.
_valid_tuple(t) if {
	t.user_type
	t.user_id
	t.relation
	t.object_type
	t.object_id
}

_store := input.store if input.store

_store := config.default_store if not input.store

# The audit author is the authenticated subject (defined when token is valid).
_performed_by := authn.subject_id
