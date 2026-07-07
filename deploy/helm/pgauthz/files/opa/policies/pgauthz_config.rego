package authz.pgauthz.config

import future.keywords.if

_env := opa.runtime().env

# Default store used by the policy layer.
# Set via DEFAULT_STORE env var on the OPA service.
default_store := _env.DEFAULT_STORE

# pgauthzd native callback base URL — the internal (policy-free) listener the
# read/decision data client calls back into. Set via NATIVE_URL on the OPA
# service (e.g. http://pgauthzd-opa:8081).
native_url := _env.NATIVE_URL

# Shared SERVICE credential presented to the native callback listener
# (Authorization: Bearer). Proves the call came from this OPA. Set via
# NATIVE_SERVICE_TOKEN, matching pgauthzd's INTERNAL_SERVICE_TOKEN.
native_service_token := _env.NATIVE_SERVICE_TOKEN

# pgauthzd native WRITE callback base URL — the writer instance's callback
# listener OPA forwards authorized writes to. Separate from native_url so reads
# and writes can target different (read-only vs writer) pgauthzd instances. Set
# via NATIVE_WRITE_URL.
native_write_url := _env.NATIVE_WRITE_URL

# Optional mTLS to the native callback listener. When a client cert file is
# configured, http.send presents it (and trusts the server via the CA file), so
# the internal listener's RequireAndVerifyClientCert accepts the call. File
# paths are mounted into the OPA container. Set via NATIVE_TLS_CLIENT_CERT /
# NATIVE_TLS_CLIENT_KEY / NATIVE_TLS_CA_CERT.
native_tls_client_cert_file := _env.NATIVE_TLS_CLIENT_CERT

native_tls_client_key_file := _env.NATIVE_TLS_CLIENT_KEY

native_tls_ca_cert_file := _env.NATIVE_TLS_CA_CERT

native_tls_enabled if _env.NATIVE_TLS_CLIENT_CERT

# Default cache TTL for http.send responses (seconds).
# 0 = no caching.
# Set via DEFAULT_CACHE_TTL_SECONDS env var on the OPA service.
default_cache_ttl_seconds := to_number(_env.DEFAULT_CACHE_TTL_SECONDS) if _env.DEFAULT_CACHE_TTL_SECONDS

default_cache_ttl_seconds := 1 if not _env.DEFAULT_CACHE_TTL_SECONDS

# Per-store, per-object-type cache TTL overrides (seconds).
# Use "_default" as a fallback for unlisted object types within a store.
# Set via CACHE_TTL_SECONDS env var as a JSON string, e.g.:
#   CACHE_TTL_SECONDS='{"demo":{"_default":5,"document":10,"team":30}}'
cache_ttl_seconds := json.unmarshal(_env.CACHE_TTL_SECONDS) if _env.CACHE_TTL_SECONDS

cache_ttl_seconds := {} if not _env.CACHE_TTL_SECONDS

# Require a verified JWT for read / evaluation requests (production default).
# When true, explicit-subject requests (input.subject with NO input.token) are
# rejected by the policy — the token is the only trusted source of identity.
# Set REQUIRE_TOKEN_FOR_READS=false ONLY when OPA sits behind a trusted PEP that
# authenticates callers and passes the subject (mirrors AuthZEN's
# ALLOW_SUBJECT_OVERRIDE). The demo opts into false via env.sh.
default require_token_for_reads := true

require_token_for_reads := false if _env.REQUIRE_TOKEN_FOR_READS == "false"

# Enumeration confidentiality with policy hooks (ADR 0011): accessible_objects /
# accessible_subjects are GRAPH-derived supersets — decision hooks do not filter
# them, so an object vetoed per-decision would still be enumerable. SECURE BY
# DEFAULT: when any hook is loaded, enumeration is REFUSED unless the operator
# explicitly accepts the superset semantics.
# Set ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true to opt out.
allow_unfiltered_enumeration if _env.ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS == "true"

# Platform environment guard opt-out (ADR 0011): with hooks loaded and
# DEPLOYMENT_ENVIRONMENT unset ("unknown"), the platform injects a synthetic
# denial — an equality-style environment gate would otherwise silently fail
# OPEN on the unconfigured value. Set ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true
# ONLY when every mounted hook is genuinely environment-independent.
allow_unknown_environment if _env.ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT == "true"
