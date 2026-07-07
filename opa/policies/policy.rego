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

# The public decision: the ReBAC graph answer (one of the _graph_allow bodies
# below) AND no mounted policy hook vetoes it (hooks.rego, ADR 0011). Hooks can
# only narrow — there is deliberately no hook that widens past the graph.
allow if {
	_graph_allow
	_hooks_pass
}

default _graph_allow := false

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
_graph_allow if {
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
_graph_allow if {
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
_graph_allow if {
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
_graph_allow if {
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

# allow_detailed — the allow decision PLUS detail: state allow|deny|
# conditional and the missing condition-context keys, so a caller can
# distinguish "denied" from "denied because you did not supply
# device.trust_level" and step up. Less than `explain` (no trace/tree),
# more than `allow` (a classification, not just a boolean). Same subject
# rules as allow; the AuthZEN services map it into the response context.
allow_detailed := pgauthz.check_access_detailed(
	store,
	subject_type,
	subject_id,
	input.action,
	input.resource.type,
	input.resource.id,
	object.get(input, "context", null),
) if {
	_subject_valid
	_hooks_pass
	count(hooks_loaded) == 0
}

# With hooks mounted, the detail carries WHICH custom policies took part
# (hooks_consulted = the mounted hook packages — all hooks are consulted on
# every decision). pgauthzd's detail channel decides what to do with it:
# discarded on the plain boolean path, returned in the AuthZEN response
# context under X-PGAuthz-Detail.
allow_detailed := object.union(
	pgauthz.check_access_detailed(
		store,
		subject_type,
		subject_id,
		input.action,
		input.resource.type,
		input.resource.id,
		object.get(input, "context", null),
	),
	{"hooks_loaded": hooks_loaded},
) if {
	_subject_valid
	_hooks_pass
	count(hooks_loaded) > 0
}

# A policy-hook veto presents as a plain deny, with the hook denials listed so
# the caller can see WHICH hook fired (decision/state vocabulary matches the
# engine's detail object).
allow_detailed := {
	"decision": false,
	"state": "deny",
	"reason": "policy_hook",
	"hook_denials": hook_denials,
	"hooks_loaded": hooks_loaded,
} if {
	_subject_valid
	not _hooks_pass
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

# Subject search ("who can do X on resource Z?") is special: the subject is the
# RESULT of the search, not the caller, so there is no input.subject to validate
# here (input.subject_type only names the type to enumerate). Authorize the CALLER
# instead: a valid token, or — in trusted-PEP mode (require_token_for_reads=false) —
# an authenticated PEP that forwarded no token (e.g. pgauthzd-opa, which validates
# the JWT itself and forwards only the resolved subject).
_subject_search_valid if {
	input.token
	authn.token_is_valid
}

_subject_search_valid if {
	not input.token
	not config.require_token_for_reads
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
# The graph results for the batch (one {decision} per item, in order). Single
# definition shared by the hook gate and the result, so hooks and results agree.
_graph_evaluations := pgauthz.check_access_batch(store, _batch_checks) if {
	not input.semantic
	not input.context
}

_graph_evaluations := pgauthz.check_access_batch_with_options(
	store, _batch_checks,
	object.get(input, "context", null),
	input.semantic,
) if input.semantic

_graph_evaluations := pgauthz.check_access_batch_with_options(
	store, _batch_checks,
	input.context,
	"execute_all",
) if {
	not input.semantic
	input.context
}

# PER-ITEM hook evaluation (ADR 0011 amendment): decision hooks are evaluated
# against EACH graph-allowed item's normalized single-decision ABI — evaluating
# only the top-level input would let a batch smuggle an item past a per-item
# `deny`. A hook denial on an item the graph already denied is moot, so only
# graph-allowed items are checked. Each denial is tagged with evaluation_index.
_all_batch_hook_denials := [object.union(d, {"evaluation_index": i}) |
	some i
	_graph_evaluations[i].decision == true
	item := _batch_item_input(input.evaluations[i])
	some d in hook_denials with input as item
]

# Capped for the response; count/truncated report the true size (hooks.rego).
_batch_hook_denials := array.slice(_all_batch_hook_denials, 0, 64)

# Synthesize the single-decision input for one batch item (top-level defaults
# merged), with NO token — the subject is already resolved, so hooks see the
# platform-derived subject via the ABI, not the raw token. evaluated_at and
# deployment are carried forward so every item shares the batch's single server
# timestamp and environment.
_batch_item_input(eval) := {
	"store": store,
	"evaluated_at": _evaluated_at,
	"deployment": _deployment,
	"subject": object.get(eval, "subject", object.get(input, "subject", {})),
	"action": object.get(eval, "action", object.get(input, "action", "")),
	"resource": object.get(eval, "resource", object.get(input, "resource", {})),
	"context": object.get(eval, "context", object.get(input, "context", {})),
}

# A per-item hook veto REJECTS the whole batch with a structured error (an
# all-false result would conflate graph denials, hook denials, and items never
# evaluated). pgauthzd maps this to 403 denied_by_policy_hook — /evaluations is
# not a bypass around the decision hooks. denial_count/denials_truncated report
# the true size when the returned list is capped.
evaluations := {
	"error": "denied_by_policy_hook",
	"denials": _batch_hook_denials,
	"denial_count": count(_all_batch_hook_denials), # post per-hook caps
	"denials_truncated": true,
	"denials_dropped": count(_all_batch_hook_denials) - 64,
} if {
	_batch_subject_valid
	input.evaluations
	count(_all_batch_hook_denials) > 64
}

evaluations := {"error": "denied_by_policy_hook", "denials": _batch_hook_denials, "denial_count": count(_all_batch_hook_denials)} if {
	_batch_subject_valid
	input.evaluations
	count(_all_batch_hook_denials) > 0
	count(_all_batch_hook_denials) <= 64
}

# No hook veto → the graph results (identical to pre-hook behavior when no
# hooks are loaded: _all_batch_hook_denials is then empty at no per-item cost).
evaluations := _graph_evaluations if {
	_batch_subject_valid
	input.evaluations
	count(_all_batch_hook_denials) == 0
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
# Enumeration confidentiality (ADR 0011): search results are GRAPH-derived
# supersets — decision hooks veto per-decision but do NOT filter enumeration,
# so a hook-vetoed object would still be listed. SECURE BY DEFAULT: with any
# hook loaded, enumeration is refused unless the operator opts into superset
# semantics (ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true). With no hooks
# loaded nothing changes. permitted_actions is NOT affected — it IS
# hook-filtered per action.
# -----------------------------------------------------------------------
enumeration_refused if {
	count(hooks_loaded) > 0
	not config.allow_unfiltered_enumeration
}

_enumeration_refusal := {"error": "enumeration_refused_with_hooks"}

accessible_objects := _enumeration_refusal if enumeration_refused

accessible_objects_page := _enumeration_refusal if enumeration_refused

accessible_subjects := _enumeration_refusal if enumeration_refused

accessible_subjects_page := _enumeration_refusal if enumeration_refused

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
	not enumeration_refused
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
	not enumeration_refused
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
	not enumeration_refused
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
	not enumeration_refused
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
	not enumeration_refused
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
	not enumeration_refused
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
	not enumeration_refused
	_subject_search_valid
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
	not enumeration_refused
	_subject_search_valid
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
	not enumeration_refused
	_subject_search_valid
	input.page
	input.page.after
}

# -----------------------------------------------------------------------
# Action search: what can the subject do on this resource?
# -----------------------------------------------------------------------
_graph_permitted_actions := pgauthz.list_actions_with_context(
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

_graph_permitted_actions := pgauthz.list_actions(
	store,
	subject_type,
	subject_id,
	input.resource.type,
	input.resource.id,
) if {
	_subject_valid
	not input.context
}

# Clients read permitted_actions as "what can the user actually do", so each
# action is filtered through the decision hooks (ADR 0011 amendment): an
# action a hook would veto is not advertised. Without hooks the graph answer
# passes through untouched.
permitted_actions := _graph_permitted_actions if count(hooks_loaded) == 0

permitted_actions := {a |
	some a in _graph_permitted_actions
	not _action_hook_denied(a)
} if count(hooks_loaded) > 0

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
