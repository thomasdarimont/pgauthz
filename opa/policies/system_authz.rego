# System authorization policy for OPA's own API.
#
# Controls which OPA REST endpoints are accessible and to whom.
# Activated by running OPA with --authentication=token --authorization=basic.
#
# Public (no token required):
#   - POST /v1/data/<allowed_prefix>/*  — policy evaluation (restricted to
#     known prefixes to prevent leaking raw data like JWKS keys)
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

# Allowed policy path prefixes for unauthenticated evaluation.
# Add entries here when you add new policy packages.
_allowed_prefixes := {"authz", "authn", "system"}

# POST /v1/data/<allowed_prefix>/* — policy evaluation
allow if {
	input.method == "POST"
	input.path[0] == "v1"
	input.path[1] == "data"
	count(input.path) > 2
	input.path[2] in _allowed_prefixes
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

# Admin token from environment variable only.
# Environment variables cannot be read via OPA's REST API.
admin_token := opa.runtime().env.OPA_ADMIN_TOKEN

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

_is_admin if {
	admin_token
	input.identity == admin_token
}
