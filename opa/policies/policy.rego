package authz

import future.keywords.if
import future.keywords.in

import data.authn
import data.authz.pgauthz
import data.authz.pgauthz.config

# The store to use — from input or falling back to the configured default.
store := input.store if input.store
store := config.default_store if not input.store

# -----------------------------------------------------------------------
# Subject resolution: JWT token or explicit input.
#
# When input.token is present, the subject is extracted from JWT claims:
#   - subject_type: from "subject_type" claim (default: "internal_user")
#   - subject_id:   from "preferred_username" claim (fallback: "sub")
#
# When no token is present, the subject comes from input.subject directly —
# but that path is only honored when config.require_token_for_reads is false
# (trusted-PEP mode); see _subject_valid. In the default token-only mode such
# requests are denied.
# -----------------------------------------------------------------------
subject_type := authn.subject_type if input.token
subject_type := input.subject.type if not input.token

subject_id := authn.subject_id if input.token
subject_id := input.subject.id if not input.token

# Default deny — access must be explicitly granted via the Zanzibar model.
default allow := false

# -----------------------------------------------------------------------
# Access check with context.
# The context is forwarded to the PG engine for condition evaluation.
#
# With token:
#   {
#     "token":    "eyJhbGciOi...",
#     "action":   "can_read",
#     "resource": {"type": "document", "id": "doc_payroll_001"},
#     "context":  {"current_time": "2026-03-12T10:00:00Z"}
#   }
#
# Without token (backward compatible):
#   {
#     "subject":  {"type": "internal_user", "id": "alice"},
#     "action":   "can_read",
#     "resource": {"type": "document", "id": "doc_payroll_001"},
#     "context":  {"current_time": "2026-03-12T10:00:00Z"}
#   }
# -----------------------------------------------------------------------
allow if {
	_subject_valid
	input.context
	not input.contextual_tuples
	pgauthz.check_access_with_context(
		store,
		subject_type,
		subject_id,
		input.action,
		input.resource.type,
		input.resource.id,
		input.context,
	)
}

# Access check without context.
allow if {
	_subject_valid
	not input.context
	not input.contextual_tuples
	pgauthz.check_access(
		store,
		subject_type,
		subject_id,
		input.action,
		input.resource.type,
		input.resource.id,
	)
}

# -----------------------------------------------------------------------
# Access check with contextual (ephemeral) tuples.
# -----------------------------------------------------------------------
allow if {
	_subject_valid
	input.contextual_tuples
	not input.context
	pgauthz.check_access_with_contextual_tuples(
		store,
		subject_type,
		subject_id,
		input.action,
		input.resource.type,
		input.resource.id,
		input.contextual_tuples,
	)
}

# Contextual tuples with request context.
allow if {
	_subject_valid
	input.contextual_tuples
	input.context
	pgauthz.check_access_with_contextual_tuples_ctx(
		store,
		subject_type,
		subject_id,
		input.action,
		input.resource.type,
		input.resource.id,
		input.context,
		input.contextual_tuples,
	)
}

# -----------------------------------------------------------------------
# explain — the resolution trace ("why allowed/denied") for a single check, for
# the playground / debugging. Same subject/store rules as `allow`; returns the
# JSON trace tree from authz.explain_access (decision + nested children).
# -----------------------------------------------------------------------
explain := pgauthz.explain_access(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.resource.id,
) if {
	_subject_valid
}

# token_debug — opt-in (TOKEN_DEBUG=true) diagnostics explaining why a token is
# rejected (issuer/audience/expiry/signature). Returns undefined when disabled or
# no token. Grants nothing — purely a configuration aid.
token_debug := authn.diagnostics

# -----------------------------------------------------------------------
# Subject validation: a valid token, or — only when explicitly allowed for
# trusted-PEP deployments (config.require_token_for_reads = false) — an
# explicit input.subject with no token.
# -----------------------------------------------------------------------
_subject_valid if {
	input.token
	authn.token_is_valid
}

_subject_valid if {
	not input.token
	not config.require_token_for_reads
	input.subject
}

# -----------------------------------------------------------------------
# Batch access checks: evaluate multiple checks in a single round-trip.
# Maps to AuthZEN POST /access/v1/evaluations.
#
# Input format:
#   {
#     "evaluations": [
#       {"subject": {"type": "...", "id": "..."}, "action": "...", "resource": {"type": "...", "id": "..."}},
#       ...
#     ],
#     "semantic": "execute_all"  (optional, default: "execute_all")
#   }
#
# Or with shared subject (top-level defaults):
#   {
#     "subject": {"type": "internal_user", "id": "alice"},
#     "evaluations": [
#       {"action": "can_read",  "resource": {"type": "document", "id": "doc1"}},
#       {"action": "can_edit",  "resource": {"type": "document", "id": "doc1"}}
#     ]
#   }
# -----------------------------------------------------------------------
evaluations := pgauthz.check_access_batch(store, _batch_checks) if {
	_batch_subject_valid
	input.evaluations
	not input.semantic
	not input.context
}

evaluations := pgauthz.check_access_batch_with_options(
	store, _batch_checks,
	object.get(input, "context", null),
	input.semantic,
) if {
	_batch_subject_valid
	input.evaluations
	input.semantic
}

evaluations := pgauthz.check_access_batch_with_options(
	store, _batch_checks,
	input.context,
	"execute_all",
) if {
	_batch_subject_valid
	input.evaluations
	not input.semantic
	input.context
}

# Batch subject validation: either top-level subject/token exists, or — only in
# trusted-PEP mode (config.require_token_for_reads = false) — every evaluation
# carries its own explicit subject.
_batch_subject_valid if _subject_valid

_batch_subject_valid if {
	not input.token
	not config.require_token_for_reads
	not input.subject
	count([1 |
		some eval in input.evaluations
		not eval.subject.type
	]) == 0
	count([1 |
		some eval in input.evaluations
		not eval.subject.id
	]) == 0
}

# Build the checks array from evaluations, merging top-level defaults.
# Uses object.get for safe access to potentially missing top-level fields.
_batch_checks := [check |
	some eval in input.evaluations
	_eval_sub := object.get(eval, "subject", object.get(input, "subject", {}))
	_eval_res := object.get(eval, "resource", object.get(input, "resource", {}))
	check := {
		"user_type": object.get(_eval_sub, "type", ""),
		"user_id": object.get(_eval_sub, "id", ""),
		"relation": object.get(eval, "action", object.get(input, "action", "")),
		"object_type": object.get(_eval_res, "type", ""),
		"object_id": object.get(_eval_res, "id", ""),
	}
]

# -----------------------------------------------------------------------
# Resource search: which objects can the subject access?
# -----------------------------------------------------------------------
accessible_objects := pgauthz.list_objects_with_context(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.context,
) if {
	_subject_valid
	input.context
}

accessible_objects := pgauthz.list_objects(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
) if {
	_subject_valid
	not input.context
}

# -----------------------------------------------------------------------
# Resource search (paginated): ordered page of accessible object IDs.
# Input: { ..., "page": {"limit": 10, "offset": 0} }  (offset paging)
#    or: { ..., "page": {"limit": 10, "after": "doc_042"} }  (keyset paging)
# Returns an array (not a set) to preserve deterministic sort order. The four
# rules are mutually exclusive on (context?, after?) so the complete rule never
# has two matching bodies.
# -----------------------------------------------------------------------
accessible_objects_page := pgauthz.list_objects_page_with_context(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.context,
	input.page.limit,
	input.page.offset,
) if {
	_subject_valid
	input.page
	input.context
	not input.page.after
}

accessible_objects_page := pgauthz.list_objects_page(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.page.limit,
	input.page.offset,
) if {
	_subject_valid
	input.page
	not input.context
	not input.page.after
}

accessible_objects_page := pgauthz.list_objects_page_after_with_context(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.context,
	input.page.limit,
	input.page.after,
) if {
	_subject_valid
	input.page
	input.context
	input.page.after
}

accessible_objects_page := pgauthz.list_objects_page_after(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.page.limit,
	input.page.after,
) if {
	_subject_valid
	input.page
	not input.context
	input.page.after
}

# -----------------------------------------------------------------------
# Subject search: who has access to this resource?
# -----------------------------------------------------------------------
accessible_subjects := pgauthz.list_subjects(
	store,
	input.subject_type,
	input.action,
	input.resource.type,
	input.resource.id,
) if {
	_subject_valid
}

# -----------------------------------------------------------------------
# Subject search (paginated): ordered page of subject IDs.
# Input: { ..., "page": {"limit": 10, "offset": 0} }
# -----------------------------------------------------------------------
accessible_subjects_page := pgauthz.list_subjects_page(
	store,
	input.subject_type,
	input.action,
	input.resource.type,
	input.resource.id,
	input.page.limit,
	input.page.offset,
) if {
	_subject_valid
	input.page
	not input.page.after
}

accessible_subjects_page := pgauthz.list_subjects_page_after(
	store,
	input.subject_type,
	input.action,
	input.resource.type,
	input.resource.id,
	input.page.limit,
	input.page.after,
) if {
	_subject_valid
	input.page
	input.page.after
}

# -----------------------------------------------------------------------
# Action search: what can the subject do on this resource?
# -----------------------------------------------------------------------
permitted_actions := pgauthz.list_actions_with_context(
	store,
	subject_type,
	subject_id,
	input.resource.type,
	input.resource.id,
	input.context,
) if {
	_subject_valid
	input.context
}

permitted_actions := pgauthz.list_actions(
	store,
	subject_type,
	subject_id,
	input.resource.type,
	input.resource.id,
) if {
	_subject_valid
	not input.context
}

# -----------------------------------------------------------------------
# Expose identity info (useful for debugging / middleware).
# -----------------------------------------------------------------------
identity := {
	"subject_type": subject_type,
	"subject_id": subject_id,
	"roles": authn.roles,
	"token_valid": authn.token_is_valid,
} if {
	input.token
	authn.token_is_valid
}
