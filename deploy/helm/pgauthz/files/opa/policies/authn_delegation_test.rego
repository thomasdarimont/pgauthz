package authn_delegation_test

import future.keywords.if

# ACTOR_CLAIM (delegated actor, mirrors pgauthzd): a token carrying an `act`
# claim (Keycloak token-exchange delegation, RFC 8693) makes the ACTOR the
# principal and keeps the token subject as on_behalf_of.

_delegated := {
	"sub": "0fa1e5d4",
	"preferred_username": "alice",
	"subject_type": "user",
	"act": {"sub": "9b8c7d6e", "client_id": "acme_assist"},
}

_plain := {"sub": "0fa1e5d4", "preferred_username": "alice", "subject_type": "user"}

# Off (ACTOR_CLAIM unset): a delegated token is its subject — the released behavior.
test_off_delegated_token_is_its_subject if {
	data.authn.subject_id == "alice" with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
	data.authn.subject_type == "user" with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
	not data.authn.on_behalf_of with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
}

# On: the actor becomes the principal, the user is on_behalf_of.
test_on_actor_is_principal if {
	data.authn.subject_id == "acme_assist" with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
	data.authn.subject_type == "agent" with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
	data.authn.on_behalf_of == {"type": "user", "id": "alice"} with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
}

# On: a plain token (no act claim) is unaffected.
test_on_plain_token_unaffected if {
	data.authn.subject_id == "alice" with data.authn.claims as _plain
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
	data.authn.subject_type == "user" with data.authn.claims as _plain
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
	not data.authn.on_behalf_of with data.authn.claims as _plain
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
}

# On: a path resolving to a non-string (the whole `act` object) is ignored —
# the principal must be a plain identifier, never a structure.
test_on_non_string_actor_ignored if {
	data.authn.subject_id == "alice" with data.authn.claims as _delegated
		with data.authn.token_is_valid as true
		with data.authn.config.actor_claim_path as ["act"]
		with data.authn.config.actor_subject_type as "agent"
}

# The hook actor carries on_behalf_of ({} for a plain token) so a hook can key
# on it without guarding for undefined.
test_hook_actor_on_behalf_of if {
	actor := data.authz._hook_decision_actor with input as {"token": "x"}
		with data.authn.token_is_valid as true
		with data.authn.claims as _delegated
		with data.authn.config.actor_claim_path as ["act", "client_id"]
		with data.authn.config.actor_subject_type as "agent"
	actor.id == "acme_assist"
	actor.on_behalf_of == {"type": "user", "id": "alice"}
	plain := data.authz._hook_decision_actor with input as {"token": "x"}
		with data.authn.token_is_valid as true
		with data.authn.claims as _plain
	plain.on_behalf_of == {}
}
