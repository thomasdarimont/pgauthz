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

# check_access delegates to the Zanzibar model in PostgreSQL.
# Returns true if the subject has the given relation on the object.
check_access(store, subject_type, subject_id, relation, object_type, object_id) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# check_access_with_context: with request context for condition evaluation.
check_access_with_context(store, subject_type, subject_id, relation, object_type, object_id, ctx) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_with_context"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
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
		"headers": {"Content-Type": "application/json"},
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
		"headers": {"Content-Type": "application/json"},
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
		"headers": {"Content-Type": "application/json"},
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_relation": relation,
			"p_object_type": object_type,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := {obj.object_id | some obj in response.body}
}

# list_objects with request context.
list_objects_with_context(store, subject_type, subject_id, relation, object_type, ctx) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := {obj.object_id | some obj in response.body}
}

# list_objects with pagination — returns an ordered array (not a set).
list_objects_page(store, subject_type, subject_id, relation, object_type, limit, offset) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := [obj.object_id | some obj in response.body]
}

# list_objects with pagination and request context.
list_objects_page_with_context(store, subject_type, subject_id, relation, object_type, ctx, limit, offset) := objects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_objects"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	objects := [obj.object_id | some obj in response.body]
}

# list_subjects returns which subjects have access to an object.
list_subjects(store, subject_type, relation, object_type, object_id) := subjects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_subjects"]),
		"headers": {"Content-Type": "application/json"},
		"body": {
			"p_store": store,
			"p_subject_type": subject_type,
			"p_relation": relation,
			"p_object_type": object_type,
			"p_object_id": object_id,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	subjects := {subj.subject_id | some subj in response.body}
}

# list_subjects with pagination — returns an ordered array.
list_subjects_page(store, subject_type, relation, object_type, object_id, limit, offset) := subjects if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_subjects"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
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
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# check_access_with_contextual_tuples with request context.
check_access_with_contextual_tuples_ctx(store, subject_type, subject_id, relation, object_type, object_id, ctx, ctx_tuples) := response.body if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/check_access_with_contextual_tuples"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
}

# list_actions returns what a subject can do on an object.
list_actions(store, subject_type, subject_id, object_type, object_id) := actions if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_actions"]),
		"headers": {"Content-Type": "application/json"},
		"body": {
			"p_store": store,
			"p_user_type": subject_type,
			"p_user_id": subject_id,
			"p_object_type": object_type,
			"p_object_id": object_id,
		},
		"raise_error": false,
		"force_cache": true,
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	actions := {act.action | some act in response.body}
}

# list_actions with request context.
list_actions_with_context(store, subject_type, subject_id, object_type, object_id, ctx) := actions if {
	response := http.send({
		"method": "POST",
		"url": concat("", [config.postgrest_url, "/rpc/list_actions"]),
		"headers": {"Content-Type": "application/json"},
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
		"force_cache_duration_seconds": _cache_ttl(store, object_type),
	})
	response.status_code == 200
	actions := {act.action | some act in response.body}
}
