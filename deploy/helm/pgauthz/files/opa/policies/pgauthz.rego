package authz.pgauthz

import future.keywords.if
import future.keywords.in

import data.authz.pgauthz.config

# Resolve cache TTL: store+object_type → store._default → global default.
_cache_ttl(store, object_type) := config.cache_ttl_seconds[store][object_type]

_cache_ttl(store, object_type) := config.cache_ttl_seconds[store]._default if {
	not config.cache_ttl_seconds[store][object_type]
}

_cache_ttl(store, object_type) := config.default_cache_ttl_seconds if {
	not config.cache_ttl_seconds[store]
}

# Per-request cache bypass: input.no_cache=true forces a TTL of 0 for THIS
# decision, so it always hits PostgreSQL — the critical-decision escape hatch
# (e.g. re-checking immediately after a revoke) at the cost of one round-trip.
# Composes with strict revocation: remote_apply bounds DB staleness to zero on
# the sync set, and no_cache removes the last cached layer above it.
_effective_cache_ttl(store, object_type) := 0 if input.no_cache

_effective_cache_ttl(store, object_type) := _cache_ttl(store, object_type) if not input.no_cache

# Per-app DB role forwarded on READ calls as X-Authz-Role, consumed by the
# reader's _pre_request_reader() hook (SET LOCAL ROLE) so the engine's
# read-side namespace checks key on the calling application, not the fixed
# api_anon. Trust ladder mirrors subject resolution:
#   - token present  → data.authn.db_role (verified claim; raw input ignored)
#   - trusted-PEP mode (require_token_for_reads=false) → input.db_role — the
#     PEP is already trusted to assert subjects, asserting the role is the
#     same trust; the engine hook still validates it (member of authz_reader,
#     not admin-capable, fail closed).
# The header is part of the http.send request, so the force_cache entries
# below are automatically partitioned per role — a cached decision for app A
# can never be served to app B.
_read_db_role := data.authn.db_role

_read_db_role := input.db_role if {
	not data.authn.db_role
	not config.require_token_for_reads
	input.db_role != ""
}

_read_role_header := {"X-Authz-Role": _read_db_role} if _read_db_role

_read_role_header := {} if not _read_db_role

_read_headers := object.union({"Content-Type": "application/json"}, _read_role_header)

# check_access delegates to the Zanzibar model in PostgreSQL.
# Returns true if the subject has the given relation on the object.
check_access(store, subject_type, subject_id, relation, object_type, object_id) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# explain_access returns the nested resolution trace tree ("why allowed/denied")
# for a single check — used by the playground / debugging, not for decisions.
explain_access(store, subject_type, subject_id, relation, object_type, object_id) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/explain_access"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
		},
		"raise_error": false,
	})
	response.status_code == 200
}

# check_access_detailed: the rich decision result (state allow|deny|
# conditional, missing_context, conditions, model). Runs the explain
# machinery in the engine — per-decision opt-in, deliberately NOT cached
# (callers use it to react to a specific denial, e.g. step-up).
check_access_detailed(store, subject_type, subject_id, relation, object_type, object_id, ctx) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_detailed"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"context": ctx,
		},
		"raise_error": false,
	})
	response.status_code == 200
}

# check_access_with_context: with request context for condition evaluation.
check_access_with_context(store, subject_type, subject_id, relation, object_type, object_id, ctx) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_with_context"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"context": ctx,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# check_access_batch: evaluate multiple access checks in a single round-trip.
# p_checks is an array of {user_type, user_id, relation, object_type, object_id} objects.
# p_semantic is one of: "execute_all" (default), "deny_on_first_deny", "permit_on_first_permit".
# Returns an array of {decision: bool} objects (same order as input).
check_access_batch(store, checks) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_batch"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_checks": checks,
		},
		"raise_error": false,
	})
	response.status_code == 200
}

check_access_batch_with_options(store, checks, ctx, semantic) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_batch"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_checks": checks,
			"p_context": ctx,
			"p_semantic": semantic,
		},
		"raise_error": false,
	})
	response.status_code == 200
}

# list_objects returns which objects a subject can access.
list_objects(store, subject_type, subject_id, relation, object_type) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := {obj.object_id | some obj in response.body}
}

# list_objects with request context.
list_objects_with_context(store, subject_type, subject_id, relation, object_type, ctx) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"context": ctx,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := {obj.object_id | some obj in response.body}
}

# list_objects with pagination — returns an ordered array (not a set).
list_objects_page(store, subject_type, subject_id, relation, object_type, limit, offset) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_limit": limit,
			"p_offset": offset,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := [obj.object_id | some obj in response.body]
}

# list_objects with pagination and request context.
list_objects_page_with_context(store, subject_type, subject_id, relation, object_type, ctx, limit, offset) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"context": ctx,
			"p_limit": limit,
			"p_offset": offset,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := [obj.object_id | some obj in response.body]
}

# list_objects with keyset pagination — `after` is the last object_id of the
# previous page (the SQL function ignores p_offset when p_after is set). Returns
# an ordered array.
list_objects_page_after(store, subject_type, subject_id, relation, object_type, limit, after) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_limit": limit,
			"p_after": after,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := [obj.object_id | some obj in response.body]
}

# list_objects with keyset pagination and request context.
list_objects_page_after_with_context(store, subject_type, subject_id, relation, object_type, ctx, limit, after) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"context": ctx,
			"p_limit": limit,
			"p_after": after,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := [obj.object_id | some obj in response.body]
}

# list_subjects returns which subjects have access to an object.
list_subjects(store, subject_type, relation, object_type, object_id) := subjects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_subjects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_subject_type": subject_type,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	subjects := {subj.subject_id | some subj in response.body}
}

# list_subjects with pagination — returns an ordered array.
list_subjects_page(store, subject_type, relation, object_type, object_id, limit, offset) := subjects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_subjects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_subject_type": subject_type,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"p_limit": limit,
			"p_offset": offset,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	subjects := [subj.subject_id | some subj in response.body]
}

# list_subjects with keyset pagination — `after` is the last subject_id of the
# previous page. Returns an ordered array.
list_subjects_page_after(store, subject_type, relation, object_type, object_id, limit, after) := subjects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_subjects"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_subject_type": subject_type,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"p_limit": limit,
			"p_after": after,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	subjects := [subj.subject_id | some subj in response.body]
}

# check_access_with_contextual_tuples: access check with ephemeral tuples.
# Contextual tuples are evaluated alongside stored tuples but never persisted.
# Each tuple is {user_type, user_id, user_relation, relation, object_type, object_id}.
check_access_with_contextual_tuples(store, subject_type, subject_id, relation, object_type, object_id, ctx_tuples) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_with_contextual_tuples"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"contextual_tuples": ctx_tuples,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# check_access_with_contextual_tuples with request context.
check_access_with_contextual_tuples_ctx(store, subject_type, subject_id, relation, object_type, object_id, ctx, ctx_tuples) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_with_contextual_tuples"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"context": ctx,
			"contextual_tuples": ctx_tuples,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# list_actions returns what a subject can do on an object.
list_actions(store, subject_type, subject_id, object_type, object_id) := actions if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_actions"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_object_type": object_type,
			"p_object_id": object_id,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	actions := {act.action | some act in response.body}
}

# -----------------------------------------------------------------------
# Writes — forwarded to the fixed-role writer instance (config.postgrest_writer_url).
# OPA has already verified the JWT and the writer role; the writer runs every
# request as authz_writer and does no JWT verification itself. performed_by is
# the authenticated subject, recorded in the audit trail. Writes are never cached.
# -----------------------------------------------------------------------

# write_tuple: persist a single tuple. Returns {status, body}.
write_tuple(store, t, performed_by, headers) := _send_write("/rpc/write_tuple", _write_body(store, t, performed_by), headers)

# delete_tuple: remove a single tuple. Returns {status, body}.
delete_tuple(store, t, performed_by, headers) := _send_write("/rpc/delete_tuple", _delete_body(store, t, performed_by), headers)

# write_tuples / delete_tuples: batch write/delete. The tuples array is passed
# through as-is (same element shape as a single tuple). body = count affected.
write_tuples(store, tuples, performed_by, headers) := _send_write(
	"/rpc/write_tuples_jsonb", {
		"p_store": store,
		"p_tuples": tuples,
		"p_performed_by": performed_by,
	},
	headers,
)

delete_tuples(store, tuples, performed_by, headers) := _send_write(
	"/rpc/delete_tuples_jsonb", {
		"p_store": store,
		"p_tuples": tuples,
		"p_performed_by": performed_by,
	},
	headers,
)

# delete_user_tuples: offboarding — remove every tuple for a subject.
delete_user_tuples(store, user, performed_by, headers) := _send_write(
	"/rpc/delete_user_tuples", {
		"p_store": store,
		"p_user_type": user.user_type,
		"p_user_id": user.user_id,
		"p_performed_by": performed_by,
	},
	headers,
)

# write_tuples_checked: conditional/atomic write — preconditions, then deletes
# and writes, in one transaction (optimistic concurrency).
write_tuples_checked(store, preconditions, deletes, writes, performed_by, headers) := _send_write(
	"/rpc/write_tuples_checked", {
		"p_store": store,
		"p_preconditions": preconditions,
		"p_deletes": deletes,
		"p_writes": writes,
		"p_performed_by": performed_by,
	},
	headers,
)

# headers carries Content-Type and, when namespace isolation is configured, the
# caller's X-Authz-Role (consumed by authz._pre_request on the writer).
_send_write(path, body, headers) := {"status": resp.status_code, "body": resp.body} if {
	resp := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_writer_url, path]),
		"headers": headers,
		"body": body,
		"raise_error": false,
	})
}

# Required write_tuple parameters plus any present optional fields
# (user_relation, condition, condition_context).
_write_body(store, t, performed_by) := object.union(_base_body(store, t, performed_by), _optional_fields(t, {
	"user_relation": "p_user_relation",
	"condition": "p_condition",
	"condition_context": "p_condition_context",
}))

# delete_tuple takes no condition fields — only the optional user_relation.
_delete_body(store, t, performed_by) := object.union(_base_body(store, t, performed_by), _optional_fields(t, {"user_relation": "p_user_relation"}))

_base_body(store, t, performed_by) := {
	"p_store": store,
	"p_user_type": t.user_type,
	"p_user_id": t.user_id,
	"p_relation": t.relation,
	"p_object_type": t.object_type,
	"p_object_id": t.object_id,
	"p_performed_by": performed_by,
}

# Map present tuple fields to their RPC parameter names; absent fields are skipped.
_optional_fields(t, mapping) := {pname: t[sname] |
	some sname, pname in mapping
	t[sname]
}

# list_actions with request context.
list_actions_with_context(store, subject_type, subject_id, object_type, object_id, ctx) := actions if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_actions"]),
		"headers": _read_headers,
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_object_type": object_type,
			"p_object_id": object_id,
			"context": ctx,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _effective_cache_ttl(store, object_type),
	})
	response.status_code == 200
	actions := {act.action | some act in response.body}
}
