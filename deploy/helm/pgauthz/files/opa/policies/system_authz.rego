# System authorization policy for OPA's own API.
#
# Controls which OPA REST endpoints are accessible and to whom.
# Activated by running OPA with --authentication=token --authorization=basic.
#
# Public (no token required):
#   - POST /v1/data/authz/<endpoint>    — policy evaluation, restricted to an
#     EXACT allowlist of the client-facing endpoints (see _public_eval_paths).
#     Package-prefix matching is unsafe — it would expose internal rules such as
#     the admin token under data.system.authz.
#   - GET  /health                      — health checks
#   - GET  /v1/status                   — bundle status (monitoring)
#
# Admin (requires bearer token from OPA_ADMIN_TOKEN env var):
#   - GET/PUT/DELETE /v1/policies/*  — policy management
#   - GET /v1/data/*                 — raw data reads
#   - GET /v1/config                 — running configuration
#
# Always denied (even for admins):
#   - PUT/PATCH/DELETE /v1/data/*    — data writes (JWKS, config data, etc.
#     must be managed via file mounts or bundles, never via the REST API)
#
# Everything else is denied.

package system.authz

import future.keywords.if
import future.keywords.in

# Default deny all API requests.
default allow := false

# -----------------------------------------------------------------------
# Public endpoints: policy evaluation and health checks.
#
# IMPORTANT: Only allow POST to known policy packages — not to raw data
# paths like /v1/data/keys (which would leak JWKS keys).
# -----------------------------------------------------------------------

# Exact data paths a client may evaluate without a token.
#
# SECURITY: this is an allowlist of EXACT endpoint paths, not package prefixes.
# Prefix matching is unsafe — it exposes every rule in the package, including
# internal ones. Allowing the `system` prefix previously leaked the admin token
# via `POST /v1/data/system/authz/admin_token`. Add a line here when you expose
# a new client-facing rule under `data.authz`.
_public_eval_paths := {
	["v1", "data", "authz", "allow"],
	["v1", "data", "authz", "evaluations"],
	["v1", "data", "authz", "accessible_objects"],
	["v1", "data", "authz", "accessible_objects_page"],
	["v1", "data", "authz", "accessible_subjects"],
	["v1", "data", "authz", "accessible_subjects_page"],
	["v1", "data", "authz", "permitted_actions"],
	["v1", "data", "authz", "explain"],
	["v1", "data", "authz", "token_debug"],
	["v1", "data", "authz", "identity"],
	["v1", "data", "authz", "write"],
}

# POST /v1/data/authz/<endpoint> — policy evaluation (exact paths only)
allow if {
	input.method == "POST"
	input.path in _public_eval_paths
}

# GET /health — health checks
allow if {
	input.method == "GET"
	input.path[0] == "health"
}

# GET /v1/status — bundle status (for monitoring)
allow if {
	input.method == "GET"
	input.path[0] == "v1"
	input.path[1] == "status"
}

# -----------------------------------------------------------------------
# Admin endpoints: policy management and read-only data access.
# Require a bearer token matching the OPA_ADMIN_TOKEN environment variable.
#
# Data WRITES (PUT/PATCH/DELETE on /v1/data) are always denied — JWKS keys
# and other data must be managed via file mounts or signed bundles, never
# via the REST API. This prevents a compromised admin token from being used
# to inject malicious JWKS keys or modify authorization data.
# -----------------------------------------------------------------------

# Policy management (GET/PUT/DELETE)
allow if {
	_is_admin
	input.path[0] == "v1"
	input.path[1] == "policies"
}

# Data reads only (GET) — writes are always blocked
allow if {
	_is_admin
	input.method == "GET"
	input.path[0] == "v1"
	input.path[1] == "data"
}

# Configuration reads
allow if {
	_is_admin
	input.method == "GET"
	input.path[0] == "v1"
	input.path[1] == "config"
}

# Admin identity check. The token is read from the env var inline (a local
# var, NOT a package rule) so it can never be exposed as a queryable document
# under data.system.authz. Environment variables are not otherwise readable via
# OPA's REST API.
_is_admin if {
	token := opa.runtime().env.OPA_ADMIN_TOKEN
	token != ""
	input.identity == token
}
