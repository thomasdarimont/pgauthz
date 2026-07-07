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
# The writer instance runs as a fixed authz_writer role and does NOT verify
# JWTs. OPA is the front door: it verifies the ES256 token, requires the
# configured writer role (authn_config.writer_role) in the configured roles
# claim (authn_config.roles_claim_path), and only then forwards the write/delete
# to pgauthzd's native write callback — recording the authenticated subject as
# the audit author.
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

# Writes are enabled when a write target is configured — pgauthzd's native write
# callback (NATIVE_WRITE_URL). Unset → writes cleanly disabled (read-only
# deployment); OPA can still reach the read path.
_writes_enabled if config.native_write_url

write := {"allowed": false, "error": "writes_disabled"} if not _writes_enabled

# Authorized but malformed — distinguish from an auth failure.
write := {"allowed": false, "error": "invalid_request"} if {
	_writes_enabled
	_write_authorized
	not _valid_write_request
}

# Vetoed by a mounted policy hook (deny_write, ADR 0011) — authorized and
# well-formed, but a write-governance rule said no. Hook identities/reasons are
# disclosed ONLY when the caller is authorized for detail (input.detail, set by
# the front door from X-PGAuthz-Detail) — otherwise just the error code, same
# rule as the decision path.
write := object.union(
	{"allowed": false, "error": "denied_by_policy_hook"},
	_write_veto_detail,
) if {
	_writes_enabled
	_write_authorized
	_valid_write_request
	not _write_hooks_pass
}

_write_veto_detail := object.union(
	{
		"denials": hook_write_denials,
		"denial_count": hook_write_denial_count, # post per-hook caps
		"hooks_loaded": hooks_loaded,
	},
	_write_veto_truncation,
) if input.detail

_write_veto_detail := {} if not input.detail

_write_veto_truncation := {"denials_truncated": true, "denials_dropped": hook_write_denial_count - 64} if {
	hook_write_denial_count > 64
}

_write_veto_truncation := {} if hook_write_denial_count <= 64

# Authorized + well-formed + no hook veto → dispatch to the matching writer call.
write := {"allowed": true, "result": _forward} if {
	_writes_enabled
	_write_authorized
	_valid_write_request
	_write_hooks_pass
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
# DB role as X-PGAuthz-Role when a db-role claim is configured and present in the
# token. pgauthzd on the writer validates it and SET LOCAL ROLEs to it for
# namespace isolation. Absent claim → no header → the writer stays authz_writer.
_headers := object.union(
	object.union({"Content-Type": "application/json"}, _role_header),
	_consistency_header,
)

_role_header := {"X-PGAuthz-Role": _db_role} if _db_role

_role_header := {} if not _db_role

# Per-write consistency mode, forwarded to pgauthzd on the writer
# (X-PGAuthz-Consistency → SET LOCAL synchronous_commit). Vocabulary:
#   applied  — ack only after every synchronous standby APPLIED the write
#              (strict revocation); durable — flushed on sync standbys;
#   eventual — primary-only durability. Absent → the writer connection's
# default (remote_apply in the shipped compose/Helm). The engine fails closed
# on unknown values.
# Forwarded verbatim — pgauthzd is the single validator and
# FAILS CLOSED with a clear error on unknown values (a silently dropped mode
# here would downgrade the guarantee instead).
_consistency_header := {"X-PGAuthz-Consistency": input.consistency} if input.consistency

_consistency_header := {} if not input.consistency

# Single source: authn.db_role (DB_ROLE_CLAIM) — the same verified-claim role
# the read path forwards.
_db_role := authn.db_role

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
