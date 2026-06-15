package authz.pgauthz.config

import future.keywords.if

_env := opa.runtime().env

# Default store used by the policy layer.
# Set via DEFAULT_STORE env var on the OPA service.
default_store := _env.DEFAULT_STORE

# PostgREST base URL — resolves via Docker network.
# Set via POSTGREST_URL env var on the OPA service.
postgrest_url := _env.POSTGREST_URL

# PostgREST WRITER base URL — the fixed-role (authz_writer) write instance.
# OPA forwards authorized writes here; it is not reachable from the host.
# Set via POSTGREST_WRITER_URL env var on the OPA service.
postgrest_writer_url := _env.POSTGREST_WRITER_URL

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
