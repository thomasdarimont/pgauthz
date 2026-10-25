# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While
pre-1.0, minor versions may include breaking changes.

## [Unreleased]

### Added

- **Relation constraints** (migration 0025, `authz.relation_constraints` +
  audit): per `(type, relation)`, how many subjects may hold the relation on
  one object. `max_direct` is enforced on every write path by a trigger on
  the tuples table — it counts the **active (unexpired)** direct tuples as
  written (a userset is one), under the per-object lock, so two writers
  racing for the last slot serialize and the second is refused with
  SQLSTATE `ZA001` (message and JSON detail carry cap and count); wildcard
  tuples are refused on a capped relation, and a cap is refused where the
  model has no direct rule or allows wildcards. `max_effective` is advisory:
  `authz.relation_usage` reports active direct and resolved holder counts
  with headroom, resolving lazily up to `p_limit` (default `max_effective`),
  with `unbounded` and `limit_reached`. `model_set_relation_constraint` /
  `model_drop_relation_constraint` / `list_relation_constraints`;
  `describe_model` comment line; export, checksum, apply, plan and diff carry
  the constraints. pgauthzd: `POST /pgauthz/v1/relation-usage` and a
  structured `409 relation_full` on `write`, `write-checked`, `grant` and
  `apply-grants` (engine RAISEs on `write` now map to 400 like the other
  writes). Console: Model → Relation constraints tab, "n / max active" in the
  share dialog, Activity history. Scenario fixtures: a seed tuple refused by
  a cap is a result, `refused: true` asserts it. Two-session race test (H).
  Review (Codex, on db28333): a capped write under `REPEATABLE READ` /
  `SERIALIZABLE` is refused with `25000` (its snapshot could miss a
  concurrent commit; race test I); `relation_usage` and the refusal report
  the exact direct count, so an object over a lowered cap is visible; the
  cap and wildcards are refused in both orders (facet, object-wildcard rule,
  stored wildcard tuples), and `apply_model` drops stale constraints before
  syncing rules and restrictions. Round 2 (on 2021177): `apply_model` also
  drops a `max_direct` the definition clears before the sync, so a hard cap
  can become an advisory one next to a new wildcard facet in one apply; the
  cap, the wildcard facet, the object-wildcard rule and wildcard tuple writes
  serialize on a per-(type, relation) advisory lock under `READ COMMITTED`
  (two-session tests J1–J4), closing the interleaving that could commit a cap
  and a wildcard together. Round 3 (on 06f1888): `apply_model` takes the
  relation-model locks of every cap or wildcard declaration it touches, live
  or desired, in sorted order right after its table lock, so a concurrent
  `model_set_relation_constraint` waits instead of deadlocking on the
  constraint row (two-session test K).
- **Review #27 (Codex, on c5fa4fc) fixes — the store's decision-log purge.**
  The purge removed a store's subject tombstones without the lock protocol,
  so a buffered line about an erased subject could flush back (P1). It now
  writes a **store-level fence** (`decisionlog.store_purges`) under the
  erasure barrier before deleting; every sink batch drops its lines about a
  purged store decided at or before the purge, and fences are pruned with
  retention (ADR 0015 addendum; a three-way two-session test). A requested
  purge is never reported done without running: the admin API refuses
  `purge_decisions` with `501` and the console with `400` *before* deleting
  anything when no postgres sink is there (P2). The lines and tombstones go
  in one transaction, and **`DELETE /pgauthz/v1/admin/stores/{store}/decisions`**
  (`pgauthzctl store purge-decisions`) retries the purge alone after the
  store is gone (P2). The console's store deletion mirrors the fence.
- **Store incarnations in the decision log.** `authz.store_id(store)` (reader
  tier) is the store's incarnation; every line the engine decides carries it
  (`store_id`, read in the same statement), and a store purge is keyed by it
  (`decisionlog.store_fences`), so a store recreated under the name keeps its
  lines whatever the clocks say. `delete_store` records a **deletion
  receipt** (migration 0024, `authz.store_deletions`: incarnation, time, actor,
  inside the lifecycle lock; `delete_store_receipt` returns it), and a purge
  names a receipt's incarnation: deletions answer with `store_id` and
  `deleted_at`, `GET …/stores/{store}/deletions` (`pgauthzctl store deletions`)
  lists the receipts, and the retry `DELETE …/decisions?store_id=` refuses an
  incarnation without one — a live store cannot be fenced. Lines without an id
  (OPA-fronted, pre-upgrade) fall back to the receipt's deletion time, best
  effort. The name-keyed fence table of the intermediate commits never
  shipped; a development fleet on one of them upgrades stopped. Purges
  and erasures take the lock before writing their fence or tombstone and
  stamp it after the lock. The console presents its client certificate for
  the local admin only.

- **Console: Platform → Issuers over pgauthzd's admin API, as the signed-in
  person.** With `PGAUTHZD_ADMIN_URL` the tab reads the rows, the history
  and the set in force, and writes bindings, through the admin API with the
  person's own token — pgauthzd's gate and tenant scoping decide (a tenant
  admin: its issuer only), the console still gates on `can_manage_issuers`
  and records every write in its action log; a session without a token (the
  local admin) uses the console's client certificate (`PGAUTHZD_ADMIN_CERT`
  / `_KEY` / `_CA`; Helm `console.adminApi`). The in-force card says which
  transport and credential answered. Without the URL the tab works as before.
  The admin API gained **`GET /pgauthz/v1/admin/issuer-bindings/audit`**
  (paged history within the caller's scope) and the `revision` on the
  bindings list. The Keycloak demo's console admins now hold `pgauthz_admin`
  (ADMIN_ROLE). Go test against a fake admin API; end-to-end check of the
  audit route.

- **Data subject requests over the admin API and pgauthzctl — the takeout
  and the export, deliberately not the erasure.** Store-scoped routes
  `GET …/admin/stores/{store}/subjects/{type}/{id}/objects`
  (`list_subject_objects` as rows, `format=csv` the hand-over file with the
  store and subject in every row) and `GET …/subjects/{type}/{id}`
  (`export_subject`); `pgauthzctl subject objects | export` (admin API only;
  `--csv --out file`, `--relations`, `--object-types`, `--limit`). Erasure
  stays with the console and SQL: it comes last in a data-subject request,
  after the applications deleted their records by the takeout's references,
  and a machine-callable erasure invites a script that runs it first
  (PRODUCTION.md → Data subject requests). The console's erasure is now
  behind **`SUBJECT_ERASURE_ENABLED`** (default off; Helm
  `console.subjectErasure`) and for **platform admins** only
  (`platform#can_manage_access`), no longer store owners. Deleting a store
  can take the store's decision-log lines and tombstones along, **opt-in**
  like the audit history: the console's Delete dialog, the admin API's
  `purge_decisions=true`, `pgauthzctl store delete --purge-decisions`
  (`decisions` in the answer). OpenAPI, handler tests, end-to-end checks in
  `tests/test-authzen.sh` and `tests/test-pgauthzctl.sh`.

### Fixed

- **`grant_options` grantee types are ordered deterministically** (a plain type
  before its wildcard form); the gdrive check compared against one order and
  failed on another database.
- **`pgauthzd_admin` holds `authz_namespace_bypass`:** the data-subject takeout
  and export walk every type, and the management plane is not an application
  bound to a namespace.
- **The derived-permissions worker no longer logs `table "_mp_…" does not
  exist, skipping` on every refresh** — it drops only the work tables that
  exist.

### Changed

- **pg_cel on pgrx 0.19.3 and cel-rust 0.15.0** (was 0.19.2 / 0.14.5). The
  extension's API use is unchanged; cel 0.15 tightens spec conformance
  (duplicate map-literal keys are errors, string `size()` counts code points,
  timestamps and durations follow the spec's ranges and formatting). The
  CEL-gated suite passes unchanged; the extension version stays 0.2.0 (its
  SQL surface did not change). Expressions now compile against the standard
  `strings`, `lists`, `math` and `encoders` extensions and the IP/CIDR
  functions of the Kubernetes CEL library, with its input rules (`ip`, `cidr`,
  `isIP`, `isCIDR`, `containsIP`, `containsCIDR`, `ip()`, `masked`,
  `prefixLength`, `family`, `ip.isCanonical`, `isLoopback`, `isUnspecified`,
  `isGlobalUnicast`, `isLinkLocalUnicast`, `isLinkLocalMulticast`; addresses
  as strings; no whitespace, zone or IPv4-mapped IPv6) — the README's
  "no IP/CIDR" caveat is gone.
- **The engine's per-session temp tables no longer raise a NOTICE on
  reuse.** `_check_memo_v2`, `ctx_tuples`, `_access_trace`, the
  `_snapshot_*` tables and `_check_memo_snap` were created with
  `CREATE TEMP TABLE IF NOT EXISTS`, which emits `relation … already
  exists, skipping` on every top-level check after the first in a session —
  a quarter of a million log lines in one CI job, and the same noise in any
  long-lived connection with `client_min_messages` at its default. They are
  now created only when `to_regclass('pg_temp.…')` finds nothing. No
  behaviour change.
- **`release.sh --release` (part of `--auto`) publishes the GitHub release.**
  After the tag push it runs `gh release create --verify-tag` with the
  `## [X.Y.Z]` CHANGELOG section as the notes; the section, GitHub's
  125,000-character body limit and "no release yet" are checked before the
  tag is created, so a refusal leaves nothing to undo. The extraction lives
  in `scripts/changelog-section.sh` (also used by the empty-notes check and
  the manual recipe). A CI run cancelled by the workflow's concurrency group
  is now reported as superseded, not failed.

## [0.18.0] - 2026-10-24

The management release. pgauthz grows an administration plane next to the
decision plane: a **management console** (`console/`, Go BFF + Lit SPA,
gated by a pgauthz store of its own) covering stores, models as DSL, data,
sharing, rollout, tests, operations, decisions and issuers; an **admin API**
on pgauthzd (`ADMIN_API_ENABLED`, its own listener, mTLS client certificates
as an admin credential, tenant-scoped by issuer) with **pgauthzctl** moved
onto it; **issuer bindings in the database** with hot reload; a
**management listener** that owns the probes and `/metrics`; and the
**`pgauthzadm`** library the console and the CLI share. Around the engine:
**sharing as an API** (`authz.grant` / `revoke`, grant rules, the
`authz_sharer` tier), **data subject requests** (`list_subject_objects` as
CSV for the application teams, `export_subject`, `erase_subject`), **derived
permissions** as a documented feature with changefeed-driven incremental
refresh, condition-bound type restrictions, delegated actors, relation kinds,
and a **decision log with a PostgreSQL sink** (ADR 0015) that now honours
erasures under concurrency (tombstones, advisory-lock ordering, a
retention-bound delivery age — reviews #21–#26). pgauthzd gains
**OpenTelemetry** tracing, AuthZEN `properties` reaching the engine's
conditions, a conformance harness for the OpenID suite, `TRUST_FORWARDED_HEADERS`,
and an embedded Swagger UI. **Security:** a verified token without a subject
claim could assert any subject (ADR 0014 closes it), `model_remove_type` with
`p_force => NULL` skipped the tuple check, and type/relation removal is now
serialized against writes. **Breaking:** AuthZEN search responses carry the
entity under `results`, the console retires the playground, and the base
images move to PostgreSQL 18.6, OPA 1.21.2, Keycloak 26.8.1 and Go 1.27.3.
Documentation is split one owner per topic, with `docs/USE-CASES.md` as the
entry point. Details, by batch, below.

### Added

- **Issuer bindings managed in the database (console gaps item 5; design:
  trust anchors in the environment, bindings in the database).** Migration
  0023 adds `authz.issuer_bindings` (stores, DB roles, client roles, PEP
  clients, `enabled`, description, `created_at/by` kept by a replace and
  `updated_at/by`) with an audit table and a revision row
  bumped and NOTIFYed by trigger; `authz.set_issuer_binding` /
  `delete_issuer_binding` (admin tier, validated as pgauthzd validates,
  recorded with the actor), `list_issuer_bindings` / `issuer_bindings_revision`
  (reader tier), `list_issuer_bindings_audit` (auditor). pgauthzd gains
  `ISSUERS_SOURCE=env+db`: the bindings of each `JWT_ISSUERS` issuer may be
  replaced by its row, merged at start and on every change (poll +
  NOTIFY), swapped atomically into one issuer set the JWT middleware and
  the handlers share (`pkg/issuers`, the model and validation the console
  will reuse); a row can only narrow — the environment keeps the anchors,
  unknown issuers and widening rows are rejected and logged, the set in
  force never changes on a bad row; `enabled=false` refuses an issuer's
  tokens without a deploy. `GET /pgauthz/v1/issuers` reports the effective
  set (keys redacted; `ISSUERS_REQUIRED_ROLE` on the public listener),
  `/readyz` the applied revision, metrics and `doctor` the mode. The demo
  stack runs `env+db`; compose and Helm (`issuers.*`) pass the settings.
- **The admin API (`ADMIN_API_ENABLED`, off by default): the management
  surface for configuration as code** — `/pgauthz/v1/admin/…` on a `full`
  instance whose DB role holds `authz_admin` (new login role
  `pgauthzd_admin`, asserted at startup), on its own listener with
  `ADMIN_LISTEN_ADDR` (the public listener then has no `/admin/` route and
  its OpenAPI document omits them). The gate: a per-issuer `admin` binding
  in `JWT_ISSUERS` (`scopes`, `claims`, `clients` a token must carry) or the
  `ADMIN_ROLE` shorthand. **Scoped per tenant**: an admin binding manages
  the issuer's own binding (`scope: issuer`, default) — a tenant admin
  narrows, pauses or re-enables its own identity provider and sees only it;
  `scope: platform` / `ADMIN_ROLE` reach every issuer. First resources:
  `GET /admin/issuers`, `GET|PUT|DELETE /admin/issuer-bindings` (validated
  as the daemon validates, narrowing only, untrusted issuers refused,
  writes recorded with the token's subject and client). The read-only
  `GET /pgauthz/v1/issuers` now shows a caller its **own** issuer only
  (every issuer for a platform admin; the callback listener the whole set).
  `doctor` reports the admin API; compose/Helm (`admin.*`) and the demo
  stack (`:8096`, `ADMIN_ROLE=pgauthz_admin`) wire it; `tests/test-authzen.sh`
  covers the gate, the scope, narrowing and the fleet applying a PUT.
- **Data subject requests (GDPR).** `authz.list_subject_objects(store, type,
  id, [relations], [object types])` (reader tier) answers the takeout
  question as rows — every object the subject can reach, per relation,
  wildcards as `*`, direct grants marked, per-pair cap — for a JOIN against
  the application's tables or as CSV for the application teams (the console
  downloads it). `authz.export_subject(store, type, id)`
  (auditor tier) returns one JSON document with everything a store holds
  about a subject: direct tuples (expired rows marked), tuples about the
  subject, effective access per type and relation (through teams, computed
  relations and wildcards; per-list cap with `truncated`), its events and
  every audit row naming it. `authz.erase_subject(…)` (admin tier) removes
  the tuples on either side incl. expired ones and the events, optionally
  the audit rows; audited with the actor. Engine files `subject.sql` /
  `subject_admin.sql`, `tests/sql/tests_subject.sql`, PRODUCTION.md section.
  Console: a Store → *Data subject* tab looks a subject up, hands the
  objects to the application teams as CSV, exports everything (with the
  subject's decision-log lines) and erases (with confirmation).
- **The management listener.** `MANAGEMENT_LISTEN_ADDR` (the former
  `METRICS_LISTEN_ADDR`, still accepted) serves the probes `/livez`,
  `/readyz`, `/healthz` next to `/metrics`; `PUBLIC_HEALTH_ENABLED=false`
  takes them off the public listener (needs the management listener; the
  served OpenAPI document omits them then). Helm probes and the console's
  readiness check use the management port when `metrics.enabled`
  (`metrics.publicHealth: false` to close the public probes); the compose
  deployment's healthchecks use it; `doctor` reports both.
- **Console: loading skeletons and a guarded rollout.** Every tab shows a
  skeleton in the shape of its table while its data loads instead of
  "Loading…" (no layout jump; still under `prefers-reduced-motion`).
  Rollout: putting an unmanaged store under a registry model is an explicit
  step, and applying a version that changes the store's model (first
  adoption or another model) asks for confirmation that names the store.
- **Console Decisions tab: reason filter, Reset, Refresh.** A clicked
  "by reason" entry now narrows to that reason (`reason=` on both decisions
  endpoints) instead of just the outcome; Reset clears every filter back to
  the window; Refresh reloads it. A test pins that every filter value
  reaches SQL as a bound argument.
- **Review #21 (Codex, on 1e47927) fixes.** The decision-log sink honours
  **erasure tombstones** (`decisionlog.erasures`, ADR 0015 addendum): a
  line about an erased person that an instance accepted before the erasure
  and flushes afterwards is dropped on insert, so a 200 from the console's
  erasure holds even against buffered writes; the erasure now runs the
  engine first (re-authorized, recorded in the action log) and the decision
  log second, answering 502 `partial` on a decision-log failure;
  `events_about` excludes the person's own actions before the page is cut;
  `decisions_about` includes lines without a subject
  (`IS DISTINCT FROM`). Regression checks for each.
- **Review #22 (Codex, on 19049f6) fixes.** Sink batches and erasures are
  now ordered: every batch holds a transaction-level advisory lock shared,
  the erasure writes its tombstone, takes the lock exclusive for an instant
  and commits before deleting the persisted lines unlocked — a batch in
  flight at the moment of the erasure can no longer commit a line about the
  person afterwards, and the sinks never wait for each other or for the
  delete (P1; a two-session test pins both interleavings). The sink refuses
  lines older than `DECISION_LOG_RETENTION_DAYS` (new counter
  `pgauthzd_decision_log_expired_lines_total`), so a delivery delayed past
  retention cannot outlive the tombstone that covered it (P2). ADR 0015
  addendum, PRODUCTION.md.
- **Review #23 (Codex, on 4aeb62e) fix.** Retention could slip between a
  batch's age check and its commit. The check that binds is now made inside
  the batch transaction, on the database clock, and a retention run is one
  transaction under the exclusive erasure lock that also sweeps the
  default partition; a test parks a batch and shows retention waiting for
  it. Sinks sharing a database must use one `DECISION_LOG_RETENTION_DAYS`.
  Review #24: the sink's local first pass keeps a day of grace so a clock
  ahead of the database's cannot discard a line the database would keep;
  the retention test pins the default-partition sweep together with its
  tombstone. Review #25: the tolerated skew is a day and documented as
  such; an integration test skews the sink's clock 23 hours either way
  against the database's.
- **Review #20 (Codex, on 8782230) fixes.** Issuer-scoped client
  certificates now see their issuer on `GET /admin/issuers` (the listing
  took the issuer from the token context, which a certificate has none of);
  `export_subject` / `erase_subject` and the console's decision-log part
  cover the person as the *object* too — `events_about`,
  `decisions_about`, and erasure of both sides; the console's erasure
  removes the decision-log lines first and answers an error on any
  failure instead of a 200 with a note; `list_subject_objects` no longer
  swallows every error (a non-applicable pair yields no rows, anything
  else propagates). PRODUCTION.md says what typed matching cannot cover.
- **pgauthzctl unit tests for the admin-API mode** (`api_test.go`): a fake
  admin API checks the bearer token, the error mapping, the issuers, model
  and store verbs' requests and output, and an mTLS handshake with a
  generated CA; CI and `tests/test-pgauthzctl.sh` run them.
- **`pgauthzctl store list | get | set | delete | recorders | recorder-set |
  recorder-lift | namespaces | namespace-grant | namespace-revoke`** — the
  first command group on the admin API only (no `--dsn` form).
- **Admin API: recorder allowlists and namespaces.**
  `GET|PUT|DELETE /pgauthz/v1/admin/stores/{store}/recorders[/{role}]` (make
  a role's allowlist exactly the given actions, lift it) and
  `GET|PUT|DELETE …/namespaces[/{ns}/access/{role}]` (make a role's access
  exactly the given flags, remove it), store-scoped like the rest; the
  engine gains the reader-tier read-backs `list_recorder_actions` and
  `list_namespaces`. With that every console management feature has its
  endpoint.
- **`ADMIN_DATABASE_URL`**: management runs on its own small pool as the
  admin tier while the instance's `DATABASE_URL` keeps the writer tier
  (`doctor` warns when the main pool serves management). The demo stack,
  compose and Helm use it; the full instance connects as `pgauthzd_rw`
  again.
- **Helm: the admin listener's mTLS.** `admin.tlsSecret` (a
  `kubernetes.io/tls` secret), `admin.clientCASecret` (+ `clientCASecretKey`)
  and `admin.clientCerts` render `ADMIN_TLS_*`, `ADMIN_CLIENT_CA` and
  `ADMIN_CLIENT_CERTS` on the writer with the secrets mounted; the chart
  README gains "The admin API (configuration as code)".
- **pgauthzctl's model verbs over the admin API.** `publish`, `plan`,
  `diff`, `apply`, `export`, `status`, `versions` and `rollout` run over
  `--server` (publish sends the parsed OpenFGA model; the new engine
  function `authz.publish_model_openfga` converts it through an ephemeral
  store); only `model import` and `model test` still need `--dsn`, and
  routine verbs over `--dsn` print a note that it is on its way out.
  `GET …/stores/{store}/model?dsl=true` adds the DSL rendering; publish
  accepts `openfga` as a third source.
- **Admin API: stores and models.** `GET|PUT|DELETE /pgauthz/v1/admin/stores/{store}`
  (create or update as an upsert — description, docs link, retire — and
  the erasure path), `GET|PUT …/stores/{store}/model` (the canonical
  definition with `model_status`; apply a registry version plan-first,
  `409` with the plan on blockers, `?plan=true` as the dry run),
  `GET /admin/models`, `POST /admin/models/{name}/versions` (publish from a
  store or from a definition — new engine function
  `authz.publish_model_definition`, the model file in git without a staging
  store), `GET /admin/models/{name}/rollout`. Tenant-scoped like the
  issuer bindings: a tenant admin reaches the stores its issuer is bound
  to; the registry needs platform scope. Every write runs as the
  credential's identity (`authz.performed_by`).
- **Client certificates as an admin credential, and pgauthzctl over the
  admin API.** `ADMIN_TLS_CERT` / `ADMIN_TLS_KEY` / `ADMIN_CLIENT_CA` put
  mTLS on the admin listener; `ADMIN_CLIENT_CERTS` maps a verified
  certificate (`cn`, SAN `uri` or full `subject`) to an admin scope, so a
  machine identity — CI, a Terraform runner — manages without a token and
  the audit names the certificate (`cert:spiffe://…`). pgauthzctl gains
  `--server` / `PGAUTHZ_SERVER` with `--token` or `--cert/--key` (`--ca`):
  the `issuers` verbs run over the admin API, the actor being the
  credential's; `--dsn` stays for installation-time work, `model test` and
  the verbs without an endpoint yet, and is on its way out for routine
  operations. `tests/test-pgauthzctl.sh` covers the API mode against the
  demo stack; `tests/lib/make-token.sh` is the shared token helper.
- **`pgauthzctl issuers list | export | import [--prune] [--dry-run] |
  delete`**: the issuer bindings as a JSON file in git, imported as an
  upsert in one transaction (the engine validates; `--prune` drops rows the
  file no longer names); `tests/test-pgauthzctl.sh` covers the round trip.
  [ADR 0016](docs/adr/0016-issuer-bindings-and-admin-api.md) records the
  design (anchors in the environment, bindings in the database, the
  tenant-scoped admin API); PRODUCTION.md gains "Issuer bindings and the
  admin API".
- **Console: Platform → Issuers** (`platform#can_manage_issuers`, held by
  platform admins and by the new dedicated `issuer_admin` platform role,
  grantable on the Admins tab, which opens nothing else): the
  fleet's issuer bindings — create, edit (the engine validates; a replace
  keeps `created_by`), pause (`enabled`), remove with confirmation, the
  history (keyset-paged by `seq`: `list_issuer_bindings_audit` gained
  `p_before_seq`, `count_issuer_bindings_audit` is new) with a refresh — and, with `PGAUTHZD_INTERNAL_URL` + `PGAUTHZD_SERVICE_TOKEN`
  (the writer's callback listener; set by the console overlays, compose and
  Helm), the set in force: every trusted issuer, binding source, applied
  revision, and per row applied / not applied / untrusted.
  `GET|PUT /api/platform/issuers`, `POST /api/platform/issuers/delete`,
  recorded in the console's action log and `authz.issuer_bindings_audit`;
  Go HTTP test and a Playwright spec (`issuers.spec.js`).
- **Browser tests for the Decisions tab** (`console/frontend/tests/ui/decisions.spec.js`):
  summary and newest-first list, keyset paging through the pager and page
  size, filters and the summary's click-to-narrow, a trace id finding its
  line with the detail and the tracing-UI link, and "Replay at that
  instant" into the Test tab — over a 30-line fixture
  `tests/test-console-ui.sh` loads into the console's database.
- **Review #19 (Codex, on a42cae2) fixes.** The postgres decision-log sink
  counts the accepted lines a failed batch could not keep when the queue
  was full (`pgauthzd_decision_log_dropped_lines_total`, an ERROR line) —
  before, they vanished silently; logged searches carry `trace_id` /
  `span_id` through a search span like decisions do; request spans are
  named after the matched route pattern (`POST /stores/{store}/pgauthz/v1/check`),
  never the raw path (bounded names, no identifiers); per-check
  `contextual_tuples` in `check-batch` are refused with `400` instead of
  being ignored.
- **OpenTelemetry in pgauthzd.** Off by default: `TRACING=auto` turns it on
  only when the `OTEL_*` environment configures an OTLP exporter (`on` /
  `off` force it; off is the untraced code path). On, W3C `traceparent` and
  B3 are honoured on every listener and forwarded to OPA, exporter or not; with
  `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_TRACES_EXPORTER=otlp`) spans leave
  over OTLP (`http/protobuf` or `grpc`): a server span per request, a
  `pgauthz.<endpoint>` span per decision carrying store, subject, action,
  resource and subject **types** (the ids only with `TRACING_IDENTIFIERS=true`;
  the decision log keeps them), decision, state, reason and client, a client span per engine
  query (`authz.<function>`, statement text and parameter count, never the
  arguments), a client span per OPA call, and `pgauthz.store` on the
  request's span;
  the standard `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` and
  `OTEL_TRACES_SAMPLER` apply. Every decision-log line carries `trace_id`
  and `span_id` (the postgres sink indexes `trace_id`), `X-Request-ID`
  defaults to the trace id, `pgauthzd doctor` reports the setup. The
  console's Decisions tab filters by trace id and client, shows the client
  column and "Denied: by client", and links a line into the tracing UI
  (`CONSOLE_TRACE_URL`, `{trace_id}` placeholder). `./start.sh --tracing`
  adds a Jaeger collector (`compose-tracing.yml`) and wires every instance,
  the console and — with `--opa` — the OPA sidecar to it (OPA's
  `distributed_tracing` over OTLP/gRPC, `OPA_TRACING_TYPE`/`_ADDRESS`; chart
  `otel.opaAddress`), so one trace shows gateway → OPA → callback → engine.
  OPA's sampling is parent-based and defaults to 0 %: it records only spans
  that join a trace pgauthzd started, never root spans of its own for health
  probes or policy listings; pgauthzd's readiness probes to OPA are untraced.
- **Decisions tab + the decision log's PostgreSQL sink (ADR 0015).**
  `DECISION_LOG=postgres` writes pgauthzd's decision lines into a sink
  database (`DECISION_LOG_DSN`): the daemon creates `decisionlog.decisions`
  (daily partitions, indexed by store, subject and resource, the whole line
  as `jsonb`), inserts in batches off the decision path (`COPY`, every
  second or 500 lines, `DECISION_LOG_QUEUE`), drops partitions older than
  `DECISION_LOG_RETENTION_DAYS` (default 30), marks itself down on a
  failed insert (`DECISION_LOG_REQUIRED` fails closed until the next batch
  succeeds; the probe line is the recovery attempt), and reports
  `pgauthzd_decision_log_batches_total{result}` /
  `_inserted_lines_total`; `pgauthzd doctor` pings the sink. Store →
  **Decisions** (`can_view_decisions`) reads the table from the console's
  own database: window and filters (subject, resource, action, outcome),
  the window's summary (outcomes; the reasons, actions and subjects behind
  the denials, the reasons behind the allows — click to narrow), the lines
  newest first with keyset paging and the full record, and two hand-overs
  into Test: explain the question now, replay it at that instant
  (`GET /api/stores/{store}/decisions[/summary]`). The console compose
  overlays point the decision instance at the console's database; the
  chart takes `decisionLog.dsn`. ADR 0013's "no database sink" clause is
  amended: this is a daemon-side, asynchronous sink in a separate database,
  not a table the engine writes on the check path.
- **`CONTEXTUAL_TUPLES` — who may inject what-if tuples (pgauthzd).** The
  native check accepted `contextual_tuples` from every authenticated caller
  of the public listener, the instance's DB role holding
  `authz_contextual_reader` for the OPA callback's sake. The new setting
  bounds it: `off` (nobody), `trusted-peps` (the default: callers that may
  assert a subject for the store — `pep_clients` / `ALLOW_SUBJECT_OVERRIDE`
  — the same trust boundary that lets a caller shape the question), `any`
  (every authenticated caller; refused under the production label, a
  startup warning elsewhere). Others get a `403`; the OPA callback listener
  always accepts them. The decision log counts a check's contextual tuples
  (`contextual_tuples`, never the tuples), `pgauthzd doctor` reports the
  mode, and the Helm chart (`contextualTuples`) and both compose files set
  it.
- **Contextual tuples in search and explain, and on the console's Test
  tab.** The engine gains `list_objects_with_contextual_tuples_jsonb`,
  `list_subjects_…`, `list_actions_…` and `explain_access_…` (gated by
  `authz_contextual_reader` like the contextual checks; one shared loader,
  `_load_contextual_tuples`): a contextual tuple takes part in the
  candidate enumeration like a stored one — it seeds a path, extends a
  userset or tuple-to-userset link, or names a concrete subject — and the
  explanation reports a `contextual_tuple` step; the plain functions never
  see the loaded tuples (the contextual branches are gated out of their
  plans). Store → Test: the single check, the matrix and every search
  direction take contextual tuples (one per line, `user:bob member
  team:eng`; the result badge counts them, Copy as SQL renders the
  contextual variant, an appended scenario case carries them); recorded
  with the question. Fixtures: `contextual_tuples` on the list cases too,
  and a check case with them can now be explained
  (`pgauthzadm.ContextualTuplesJSON`); the gdrive example shows a vacation
  substitute.
- **Saved test scenarios (console) and the fixture runner as a library.**
  The `tests.authz.yaml` runner moves from the pgauthzctl binary into
  `pgauthzadm` (`ParseFixture`, `Fixture.Validate`, `RunFixture`,
  `JUnit`, `ParseRef`), so the CLI and the console run the same fixtures
  the same way: `pgauthzctl model test` is a thin wrapper with identical
  output, and `RunOptions.Model` rebuilds a live store's model loss-free in
  the ephemeral store through `RenderSQL` (the OpenFGA JSON import cannot
  carry conditions, gates and grant rules). Store → Test gains
  **Scenarios**: the store's fixture in an editor, a single check or a
  search result appended as a case with its outcome, Run (an ephemeral
  store, this store's current model or `model: name@version`, the test
  policy applied: other subjects, enumeration, explain), Save for the team
  (`can_edit_model`, recorded), Export for pgauthzctl (the fixture with
  `model_file` filled in plus the model as DSL), and Seed from the store's
  data — an export, gated and recorded as one (`can_export`), capped at
  500 tuples (`GET/PUT /api/stores/{store}/scenarios`, `POST …/run`,
  `GET …/export`; the fixture lives in the console's own database,
  `InitSchema` adds the table). A fixture's model is one of `model_file`,
  `model` (registry) or the new **`store`**: a live store's current model,
  which `pgauthzctl model test --store <name>` fills in for a fixture
  without a model line — the console and the CLI run the same file the
  same way. Every example model ships a **`scenarios.authz.yaml`** (its
  story as named scenarios with assertions; gates hold back what the
  empty action log cannot prove), verified through the CLI; the CLI suite
  runs the loaded ones. Two views of the fixture: the **Test harness** (the
  parsed fixture as a form — the tuples as a table with an add row, every
  test as a collapsible block with its check, list_objects and explain
  cases, the last run's outcome on each assertion; add, rename and remove
  tests, add and remove assertions and tuples with the store's subjects,
  objects and relations suggested; every edit regenerates the YAML) and
  **Edit as YAML** (one YAML-highlighted, line-numbered editor; comments
  survive there). The draft is validated as you type through the runner's
  own parser (`POST …/scenarios/validate`, debounced, returning the parsed
  fixture), the offending line marked; runs are numbered and every result
  row points back at its scenario in either view; collapse all folds each
  test on its own, so any one opens again. The format gains free text for
  people: a `description` per test and per case, and `notes` per assertion
  (relation → text: the reasoning, a requirement, a ticket), carried
  through the runner into every result (`Result.Note`), printed by the
  CLI with a failure and shown in the console's result table; the harness
  edits all of them in place — a test's, a case's (the subject/object row),
  an assertion's (✎ on its chip) — and renders http(s) links in them
  clickable (bare URLs and markdown-style `[JIRA-99](https://…)`), so a
  user story, a ticket or a document can sit next to the check it
  motivated. Runs are the whole fixture or one test: ▶ on a test's block
  in the harness, ▶ in the YAML editor's gutter on every test's `- name:`
  line (coloured by the last outcome, scrolling with the text); the run posts `only`
  with the test's index and results keep their index in the full fixture.
  Runs of the session are kept client-side (the last 100), chosen from
  an execution list above the results (run, time, outcome, selection);
  the harness badges follow the chosen run; Clear hides the shown run,
  clear history drops them all. A result row copies itself as one line
  of text (outcome, assertion, detail, description), Copy results the
  whole run; **explain** on a check result shows the engine's resolution
  tree for that assertion decided inside the fixture's world — the server
  rebuilds the ephemeral store (`pgauthzadm.WithFixture`,
  `ExplainFixtureCheck`) and asks `explain_access` there, with the Single
  check view's options — "Only the deciding path", "Redact identifiers"
  (forced without `can_test_explain_full`) — as one shared control
  (`pgc-explain-options.js`) (`POST …/scenarios/explain`). The harness
  opens with every test collapsed; a test added there, or appended from
  a result, opens itself. The Test tab's mode and the scenarios' view are
  in the URL and the browser history —
  `stores/<store>/test/<single-check|matrix|search|as-me|scenarios>` and
  `…/test/scenarios/<harness|edit-as-yaml>` — so a deep link opens the
  right place, a reload stays there, and Back returns to the previous
  mode or view; switching within the tab keeps the scroll position. Every
  run carries its provenance — the store, its model (registry name and
  version, "drifted" when the live model differs, or unmanaged; or the
  fixture's registry ref) and the live model's checksum — shown under the
  run's title, kept per run in the session's history, and written into
  the text copy and, as a leading `#` comment line, into the CSV, so a
  result read later says what it tested. **Fixture runs are ephemeral
  stores without partitions.** A store's types normally get a dedicated
  tuples partition each, which is DDL on the shared parent — an ACCESS
  EXCLUSIVE lock on `authz.tuples` held until the transaction commits,
  during which every check in every store waits; a scenario run in one
  transaction held it for the whole run (found by probing: a check from
  another session blocked). New engine setting `authz.ephemeral_store`
  (transaction-local, `set_config(…, true)`): types registered while it
  is on get no partition, their rows live in `tuples_default` (same
  indexes), no DDL, no lock, no catalog churn; `delete_store` and
  `model_remove_type` already tolerate a type without a partition.
  `pgauthzadm.WithFixture` sets it, so the console's runs and explains
  and `pgauthzctl model test` (now one transaction per run, so the store
  never appears in the committed state unless `--keep-store`) are DML
  only. SQL suite: ephemeral registration creates no partition, the
  tuple lives in the default partition, the check decides from it, no
  exclusive lock is held, `delete_store` cleans up. A result carries what it asserted (kind,
  subject, relation, object — `Result.Kind/User/Relation/Object`), so a
  click in the YAML view lands on the assertion's own line; when that
  assertion is gone it lands on its case, when the case is gone on the
  test that defined it (found by name if tests were inserted or moved
  since the run), and when the test is gone it stays put. Found on the way and fixed: `RenderSQL` emitted a
  "but not" group's negated rule before its base rule when the export
  listed it first, which the engine's validation refuses — base rules now
  come first within a group. Go tests: the library's parser, validator
  and JUnit writer; the endpoints through the router (refused
  `model_file` and another store, a tester's 403, a hermetic run, a
  failing assertion as a result, no ephemeral store left, the export).
- **Console: Search gains "What may a subject do on an object?".** A third
  direction next to the two enumerations, asking `authz.list_actions` for
  everything a subject holds and may do on one object, shown as "may"
  (permissions) and "is" (relations) from the model's declared kinds,
  each with a "why" into the single check's tree, and "Add to scenarios"
  producing a `list_actions` case — the search the fixtures' `list_actions`
  assertions were missing on the tab (`POST /api/stores/{store}/actions`,
  test policy as for a check: another subject needs `can_test_others`;
  recorded as the person). The search direction is in the URL
  (`…/test/search/objects|subjects|actions`); only the two enumerating
  directions are locked without `can_test_search`, so a plain tester can
  still ask what a subject may do. Closes the Test-tab part of
  console-gaps item 4 except contextual tuples.
- **Fixtures: `list_subjects` and `list_actions` cases.** Next to `check`,
  `list_objects` and `explain`, a test can assert the reverse search
  (`list_subjects`: the subjects of a type that reach an object per
  relation, a wildcard grant listed as `type:*`) and the full action set
  (`list_actions`: exactly what a subject may do on an object — the
  relations it holds and the permissions they imply, as `authz.list_actions`
  answers). Runner, console harness (tables, descriptions), YAML emitter,
  the YAML view's jump-to-line, and "Add to scenarios" from a subjects
  search; `list_subjects` is gated like `list_objects`
  (`can_test_search`). The example fixtures show both.
- **Console: the share dialog.** Data → Share…: pick an object and whom
  to act as (yourself by default); `grant_options` renders, per relation
  with a grant rule, whether that actor may grant and revoke it and who may
  hold it, with today's holders; additions and removals queue up and are
  saved as one `apply_grants` transaction, each decided by the engine under
  the object's lock, recorded as the person (`GET`/`POST
  /api/stores/{store}/share`, console gate `can_grant` scoped to the object
  type's namespace). The holders listed are the live tuples of the offered
  relations only (a relation without a grant rule is not shown, an expired
  grant is not a holder; a grant with an expiry says when it runs out), at
  most 200 per relation with every relation's full count beside it, so a
  widely shared object never becomes a hundred-thousand-chip dialog. A
  response that arrives after the object or actor was retyped is dropped,
  and Save is bound to the object the options were loaded for, never to
  the form (review #18, P2). A save with only revokes (no `grants` key)
  works (it sent JSON `null` to the engine). The actor is a *chosen*
  subject, by contract — `can_grant` is a highly trusted console role,
  bounded by the engine's grant rules for that actor and recorded as the
  person with the actor named (console README). Go tests against the
  database: the engine calls (options for an owner and for a stranger, a
  refused and an accepted save) and the HTTP handlers through the router
  with a session cookie — 401, a viewer's 403, a namespace author's
  403 on another namespace's type, malformed payloads, the holders
  listing with its filters and cap, acting as a subject the rules refuse
  and as one they allow, the recorded event. Review #18, round 2: a
  committed save clears its queue and the shown holders before the
  refresh, so a refresh that fails cannot leave the saved changes queued
  behind a live Save (they would have been submitted twice); the result
  line then says the holders could not be reloaded. The holders query is
  per relation a LIMIT over the ordered object index plus one count,
  with the partitioned table pruned to the object type — measured at
  200K holders of one doc: 46 ms against 325 ms and a 14 MB sort for the
  window-function form it replaces; the count is the only part that
  grows with an object's popularity. **Browser tests** (Playwright,
  `frontend/tests/ui/`, `tests/test-console-ui.sh` against a running
  `./start.sh --console-local`): a late response for object A does not
  populate B, retyping the object retires the queue and never submits,
  a committed save with a failed refresh leaves nothing to replay, the
  expiry chip's relative text and absolute title. Round 3: the race tests
  synchronise on the intercepted response (no fixed waits), and CI
  enforces the suite in its own job, `console-ui-test`, which brings up
  the console-local stack and fails if the console is absent. This
  completes the Model tab's grant rules: declare them there, watch them
  decide here.
- **Console: batch import, export and offboarding on the Data tab.**
  Export the store's tuples as JSON (the native shape, round-trippable with
  conditions, context and expiry), CSV with the same columns, or the OpenFGA
  ReadTuples shape (`GET /api/stores/{store}/tuples/export?format=`).
  Import any of the three, pasted or from a file (the shape is detected):
  a preview says what was understood and on which object types, then one
  transaction as the person through `write_tuples_jsonb`, scoped like every
  Data-tab write by the namespaces of the object types touched, up to
  10000 tuples. Offboard a subject: count its tuples, confirm, then
  `delete_user_tuples` as the person. Go unit test for the three parsers.
  **Exports are sensitive:** the console model gains an `exporter` store
  role and `can_export` (exporter or owner); an export needs it, and every
  export is recorded in the console's action log with store, format and
  row count before the rows are read (Activity → Console actions). Existing
  console stores need the model delta once (console README).
  The stores home hides retired stores unless "show retired (n)" is ticked
  (remembered per browser); sorting it by model works again (it read a
  field the status never had). `frontend/src/types.js` documents the BFF's
  response shapes as JSDoc typedefs, used by `api.js` and the components'
  state, so editors resolve the fields.
- **Console: an Operations tab per store and for the fleet.** Store →
  Operations (reads `can_view_audit`, actions `can_manage_access`, as the
  person, recorded): gate readiness (`events_readiness`, every clause's
  window from `gate_windows`), the recorder allowlist
  (`grant_recorder_actions` / `revoke_recorder_actions`, with the
  database's login roles and the store's relations suggested), tuple
  maintenance (`cleanup_expired_tuples` with a grace, `find_redundant_tuples`
  then `cleanup_redundant_tuples` behind a confirmation), this store's
  action-log retention (`purge_events`; the engine's gate guard reaches the
  person as the error, force is a checkbox), the changefeed cursor and
  `watch_safe_until`, the derived-permissions status when
  `materialized_relations_status` is installed, and the partitions of both
  logs. Platform → Operations (`can_view_health` / `can_manage_access`):
  the monthly partitions with sizes and months of coverage ahead,
  `ensure_audit_partitions` + `ensure_event_partitions` ahead by N months,
  `drop_event_partitions_before` (gate-guarded, force optional), gate
  readiness per store, the fleet's longest gate window, store sizes with
  the storage their tuple partitions take (`pg_total_relation_size` per
  object-type partition, summed per store). The **Registry** page is one
  picker over models and stores: the models are the landing chips (few by
  design), typing searches models and stores by name, description and
  model, matches capped at 20 of each with a "more — keep typing" hint so
  a large fleet is never rendered as chips. A model (`registry/model/<name>`)
  shows its versions and its fleet (a (?) explains it: every store running
  the model, green current, grey older, amber drifted); a store
  (`registry/<store>`) shows the model and version it runs, the versions
  with the applied one marked, and the fleet.
  `roles.sql` grants `authz_console` SELECT on `recorder_actions`. Go test:
  the overview read as `authz_console`, the allowlist round trip, the purge
  guard refusing a cutoff inside a live gate window.
- **Console: the rest of the model, retiring a store, the model's history.**
  The Model tab now edits what it only showed before: **grant rules** (a
  section of their own: add, edit, remove, Details with the SQL call —
  `model_add_grant_rule` / `model_drop_grant_rule`), the **payload schema**
  of an action ("Payload…" on a relation, `model_set_payload_schema`; a
  `schema` badge marks relations that have one) and the **labels** of a type
  ("Labels…", `model_set_type_labels`; a Labels column). All three are
  namespace-scoped like the rest of the editor (a namespace author may set
  the labels and grant rules of their own types). The Admin tab gains
  **Retire store** (`authz.retire_store`, `POST /api/stores/{store}/retire`,
  typed-name confirmation, same gate as delete): the live data goes, the
  dictionary, the audit history and the console roles stay; a retired store
  is marked as such on the home table and the store page, keeps its
  Activity, Access and Admin tabs, and Delete purges it. The Activity tab
  gains **Model changes**: the union of `models_audit`, `conditions_audit`,
  `model_gates_audit` and `grant_rules_audit` with ids resolved to names,
  newest first — who added or removed which rule, condition, gate or grant
  rule, and what it said. The Structure card is now **one tab per
  section** (Types, Relations, Rules, Type restrictions, Conditions, Gates,
  Grant rules, with counts), the section in the URL
  (`stores/<store>/model/<section>`, remembered per browser), and each
  section's add button and edit form inside its own tab, so Edit on a gate
  or grant rule no longer jumps to the top of the page; the selection bar
  stays above the tabs since a selection spans sections. Each section's
  filter is labelled and sits beside the title; the tables sort by any
  column (click a head, click again to reverse) except the relations, whose
  order is the stored ui_order; the two relation groups share one column
  layout. **JSON fields**
  (gate clauses, payload schema, a condition's required context and its
  Try-it contexts, a tuple's condition context, the Test tab's request
  context) are one shared editor (`pgc-json`): highlighted as you type,
  parsed on every keystroke with the line and column of a syntax error, a
  Format button, and the browser's own form validation refusing the submit
  while the text is invalid. Form inputs carry no placeholder text any more;
  the example moved into the field's label or (?) text (search and filter
  boxes keep their hint). A JSON mistake is reported next to its field
  (focus and the browser's message, opening a collapsed section if need
  be), never in the page-top box; that box now says "Error:" first. The
  four Activity logs share one shape — When, Change, What, Details, By —
  so console actions, the relationship audit, the model changes and the
  action log read alike; long tokens in their Details column wrap instead
  of scrolling. The content column is 1600px wide (was 1180px), the body
  gutter still keeps it off the edges on narrower screens. New controls carry `data-testid` attributes
  (`<tab>-<thing>[-<key>]`, see the console README) for a future Playwright
  suite. `db/security/roles.sql` grants `authz_console` SELECT on
  `model_gates_audit` and `grant_rules_audit` (re-run it on an existing
  database). Go tests: the editor's new operations (`modelEditSQL`) and,
  against the database, retire keeping history and roles plus the history
  query — read as `authz_console` (`SET LOCAL ROLE`), so a missing table
  grant fails the test instead of the Activity tab.

- **Deployments: derived relations in the Helm chart, a Docker Compose
  deployment.** `derivedRelations.enabled` installs
  `db/replication/materialized_relations.sql` through the migration Job,
  declares the managed role `pgauthz_derived_worker` (inheriting the new
  least-privilege `authz_derived_worker`: worker, registration, status,
  namespace bypass) and runs one refresh worker pod
  (`db/replication/worker.sh`, a loop around
  `refresh_materialized_relations()` from the migrations image, registering
  `derivedRelations.stores` at start); `derivedRelations.publication.enabled`
  adds `wal_level=logical`, the managed `replicator` role and publication
  `authz_derived` for subscribers. `deploy/compose/` is a one-host deployment
  configured through `.env`: PostgreSQL behind a read-only and a writer
  `pgauthzd`, an idempotent `migrate` service (the migrations image, which now
  also sets the service-role passwords from `AUTHZEN_DIRECT_PASSWORD` /
  `PGAUTHZD_RW_PASSWORD` / `DERIVED_WORKER_PASSWORD` / `REPLICATOR_PASSWORD`
  when given), the `derived` and `opa` profiles and a `compose.logical.yml`
  override for subscribers; production profile by default.
  `tests/test-deploy-compose.sh` smoke-tests it (readiness, a decision with a
  demo token, the doctor, a write reaching the derived table, a console
  sign-in). The chart's description and notes now say what the front door is
  (pgauthzd; OPA is opt-in). **The management console** is in both: Helm
  `console.enabled` (managed roles `authz_console` + `console`, the sessions
  database as a CloudNativePG `Database`, the console store created once by
  the migration Job, Ingress path `/console`, NetworkPolicies), compose
  `--profile console` (`migrate` creates the sessions database and the store).
- **Console: local admin sign-in.** `CONSOLE_LOCAL_ADMIN_USER` +
  `CONSOLE_LOCAL_ADMIN_PASSWORD` offer a username/password sign-in that needs
  no OpenID Provider (`ISSUER` becomes optional): the person is
  `user:<name>` with the memberships in `CONSOLE_LOCAL_ADMIN_TEAMS` (default
  `role_console_admin`), so the console store still decides everything. Unset
  the variables and restart to deactivate — the form disappears and every
  local session is rejected at once. Constant-time comparison, a 500 ms delay
  on a wrong guess, 404 while not configured; refused under
  `DEPLOYMENT_ENVIRONMENT=production` unless
  `CONSOLE_LOCAL_ADMIN_ALLOW_IN_PRODUCTION=true`. Helm `console.localAdmin.*`,
  compose `CONSOLE_LOCAL_ADMIN_*`.
- **Console: the local admin owns every store.** `CONSOLE_LOCAL_ADMIN_STORE_ROLE`
  (default `owner`, `none` to switch off) is held contextually on every store
  the account is asked about, so it can test, edit, publish and share
  everywhere instead of only seeing stores as platform admin. Helm
  `console.localAdmin.storeRole`, compose `CONSOLE_LOCAL_ADMIN_STORE_ROLE`.
- **Dev stack: `./start.sh --console-local`.** The management console without
  Keycloak (`compose-console-local.yml`): the local admin sign-in on
  `http://localhost:8095/console/`, no proxy, no OPA; `env.sh` keeps the
  overlay across `init.sh`/`test.sh` like the others.
- **pgauthzd: successful health probes log at `debug`.** `/livez`, `/readyz`
  and `/healthz` answered 2xx no longer produce an `info` line per poll; a
  failing probe still does.

- **`./start-replication.sh` / `./stop-replication.sh`.** Bring the
  logical-replication demo up next to the main stack — host ports moved by
  `compose-replication-ports.yml`, its own compose project and volumes —
  initialise it, and print the connection strings for the primary, the full
  replica, the derived-permissions subscriber and the namespace-scoped one;
  `--clean` recreates, `--no-init` only starts, `--default-ports` for a
  machine without the main stack. The demo's volumes lost their fixed
  global names so a second project cannot share or remove them.

- **Derived permissions for one application's namespace.** Rows of
  `authz.materialized_relations` and `authz.materialized_objects` carry the
  object type's namespace (in the primary key, so a publication row filter may
  name it); an application subscribes to its own object types through a
  row-filtered publication — `authz_derived_<ns>` with `WHERE (store = …
  AND namespace = …)` on the two tables, the subject set and the freshness
  row whole. The derivation stays store-wide. Replication demo: a third
  subscriber `accounting-app-dms-db` on namespace `dms` (document, folder);
  `tests/test-replication.sh` asserts it holds exactly the primary's `dms`
  rows after the snapshot and after every random batch. Existing derived
  tables are upgraded in place (column + key); run `refresh_all` per store
  afterwards. The worker's login role needs `authz_namespace_bypass` or
  namespace read grants for the `list_subjects` expansion once types carry
  namespaces (the demo grants it). Rows also carry `is_permission`, the
  relation's declared kind: the table holds permissions (`can_read`) and
  structural relations (`member`, `parent`, `owner`) alike, and an
  application that only asks "may X do Y?" reads `WHERE is_permission` — or
  filters its publication on it, which is why the flag is in the key (a
  boolean rather than an enum: row filters cannot reference user-defined
  types). **Renamed** for the same reason: `authz.materialized_permissions`
  → `authz.materialized_relations` (partitions too), `permissions_refresh_queue`
  → `materialized_refresh_queue`, `refresh_materialized_permissions` /
  `refresh_all_materialized_permissions` / `materialized_permissions_status`
  → `…_relations…`, the name column `permission` → `relation`, and the script
  `db/replication/materialized_relations.sql`.
  Existing installs are renamed in place by the script; the subscriber
  helpers (`check_permission`, `permissions_as_of`, `permissions_fresh`) keep
  their question-shaped names.

- **Management console (proof of concept, `console/`).** A Lit + Go BFF web
  UI for the people who run pgauthz: per store, the live model in three
  read views (OpenFGA-style DSL, canonical JSON, the SQL calls that rebuild
  it) and a structured editor over the `model_*` API; check/explain for any
  subject; tuples with grant/revoke; registry publish, plan and apply with
  drift and fleet views; the audit trail and action logs; and who may do
  what with the store. Access to the console is decided by pgauthz itself:
  a `console` store (`examples/models/console`, with SQL tests) answers
  "may alice edit the model of store:demo?" before every screen and action,
  with the token's realm roles, groups and organizations injected as
  contextual `team#member` tuples; explicit roles (owner, author, publisher,
  sharer, tester, auditor, viewer) are tuples the Access tab writes, a
  platform admin reaches every store, and a store never loses its last
  owner. Actions run as the person (`authz.performed_by`) and are recorded
  in the console store's action log. New `authz_console` role,
  `compose-console.yml` / `./start.sh --console`, Keycloak client
  `console-bff` + realm role `console_admin`. See `console/README.md`.
  The Test tab asks four ways: a single check with the resolution tree, a
  matrix (subjects × actions × resources in one `check_access_batch`), a
  reverse search (`list_objects` / `list_subjects`), and "as me via
  pgauthzd" (the person's own token with `X-PGAuthz-Detail`, showing
  whether OPA and which hooks took part). Removal of model parts, tuples
  and role assignments goes through selection and an inline confirmation,
  one transaction for all selected items. The UI is internationalized
  (English, German) with help icons on columns and sections.
- **Decision log names the policy hooks.** An OPA-fronted decision line now
  carries `hooks` (the hook packages consulted) and `hook_denials` (tier,
  store, hook, code, message of each veto), copied from OPA's detail — so
  the log says not only that OPA took part (`via`, `policy`) but which
  custom policies did, and which one denied. The `X-PGAuthz-Detail`
  response context now carries `via` (`engine` | `opa`) as well, so a
  caller sees who decided without reading the log.
- **Relation kinds: what a subject IS versus what it CAN DO.** Every
  relation carries a `metadata` document (migration 0019); its `kind` is
  `relation` (assignable by a tuple — viewer, owner, member; the default) or
  `permission` (what it can do — can_read, can_share, or a directly granted
  capability such as `run: [agent]`). The kind is a declaration; whether a
  relation takes tuples is decided by its rules: a permission without a
  direct rule on the object type refuses tuples (it is derived), one with a
  direct rule takes them. `infer_relation_kinds` calls a derived-only
  relation a permission, otherwise keeps what is declared, and never
  overrides a declaration; the example models declare their permissions.
  `model_register_relation` takes
  `p_metadata`, `model_set_relation_metadata` merges keys (`ui_order` is a
  number tools sort by, display only; label, docs_url are yours), `infer_relation_kinds` derives kinds from the rules (used by
  the example models and the OpenFGA importer). `describe_model` marks
  permissions, `export_model` carries the metadata, the registry applies it
  and the plan reports metadata changes as relation updates. The console's
  Test tab groups actions by kind and explains a "no" on a relation.
- **Explain reports time-bound grants.** Every granting tuple step in
  `explain_access` carries `expires_at` (the matched tuple's expiry, null
  for never), so a caller can tell an allow that ends from one that does
  not; the console shows it as a ⏱ badge on the decision and on the tree.
- **`tuple_stats(store)`.** Live totals, expiry (with expiry, expiring
  within 24 h, expired-but-not-yet-cleaned via a count-only bypass helper),
  wildcards, conditional tuples, usersets, distinct subjects and objects,
  rows per object type — the console's Data tab shows them.
- **Console personas.** Keycloak demo users named for their role —
  `platform-admin`, `auditor`, `iam-dev`, `app-dev`, `app-secarch`,
  `support` — each with one `console_*` realm role the console seed grants
  per team; alice/bob/carol/eva stay the application users. New store role
  `supporter` (tests anyone's access with full trees, never edits).
- **Playground deprecated**: the management console replaces it; the
  playground stays until the console draws the resolution graph and has the
  "act as the PEP" event bar (tracked in `console/README.md`).
- **Rollout tab tightened**: the registry model picker, the version list
  of an unmanaged store and the Plan dry run need `can_rollout`; viewers,
  testers, supporters and auditors see only the versions of the store's
  own model, without Plan.
- **Code views with line numbers** (console): DSL, SQL, JSON and Rego views
  number their lines with a CSS counter (copies stay clean); the DSL editor
  has a scroll-synced gutter.
- **Policies tab** (console): when OPA fronts the deployment, the Rego that
  applies to a store — its hooks, the global hooks, shared libraries and
  platform policy with sources — plus OPA's version and bundle revisions,
  read from the sidecar (`CONSOLE_OPA_URL`, `CONSOLE_OPA_TOKEN`). Read-only.
  Design note for executing hooks in process (Wasm via wazero) in
  `scratch/notes/in-process-policy-hooks.md`.
- **Version diff on Rollout.** Planning a registry version also shows what
  that version changes compared to the version the store runs (or the live
  model when unmanaged): `pgauthzadm.DiffModels` compares two definitions
  section by section (types, relations, rules, type restrictions,
  conditions, gates, grant rules).
- **Test page placeholders come from the store** (its types, a subject and
  an object that exist, its relations); the completion lists sample up to
  100 subjects and objects per type instead of the first 500 overall.
- **Test runs no longer reset the console store**: the console fixture
  takes its store name from the psql variable `cs` and `tests/test.sh` loads
  it as `console_test`; `./start.sh --console` creates the live `console`
  store once when missing.
- **Console performance on large stores.** The stores home computes a
  person's capabilities with one engine call
  (`check_access_batch_with_contextual_tuples_jsonb`: many checks, the
  contextual tuples loaded once; capped by the GUC `authz.max_batch_checks`,
  default 5000) and asks only for the capabilities it shows;
  `tuple_stats` counts distinct subjects and objects with hash aggregates
  (60k tuples: 263 → 60 ms). The Data tab pages server-side (offset,
  total, sort order applied to the whole store, not the visible rows).
- **`KEEP=1 ./bench/run.sh <suite>`** leaves the suite's store and data in
  place after the run, as a large dataset for the console or psql.
- **Condition expressions are stored trimmed** (`create_condition`; migration
  0022 trims existing rows).
- **Try a condition** from its Details row: a request context and a
  mocked stored context, evaluated by the new `authz.evaluate_condition`
  without a tuple (needs `can_run_tests`, recorded like any test). The
  placeholder `__now__` (with offsets such as `__now__-30m`, `__now__+1d`)
  becomes the current instant before the JSON is parsed; both contexts are
  validated live. Server-time conditions take `current_time` from the
  engine's clock exactly as a check does.
- **Model tab filters**: every section (types, relations, rules, type
  restrictions, conditions, gates) has a filter box that also matches the
  rendered forms (`team#member`, `user:*`, `viewer from parent`); rules and
  type restrictions show their engine id and `#id` in a filter addresses
  exactly that one; the definition card starts collapsed.
- **`model_set_type_namespace`**: move a type into or out of a namespace
  (create, rename and dissolve namespaces by moving types); the console's
  Model tab edits a type's namespace and renames a namespace, moving its
  role assignments along.
- **`authz_namespace_bypass`** role: skips the per-application namespace
  gate (`_check_namespace_access`); granted to `authz_console`, whose console
  store decides namespace access per person instead.
- **Namespace roles in the console.** `namespace:<store>/<name>` objects
  with `author` / `viewer`; the BFF checks each model or data change against
  the namespace of the type it touches (store roles allow everything,
  store-wide changes need them). Types get a namespace on creation; the
  Access tab grants namespace roles. Table columns are resizable (drag a
  header's right edge, double-click to reset); the conditions list shows
  the expression and required context in its Details row only.
- **Console test policy.** `can_run_tests` opens the Test tab; four further
  console-store permissions say what a tester may ask beyond their own
  access — `can_test_others` (other subjects), `can_test_explain_full`
  (unredacted trees; otherwise `p_redact` is forced), `can_test_search`
  (enumeration), `can_test_history` (point-in-time checks). A plain
  `tester` has none of them; authors, publishers and owners have all,
  auditors history. The BFF enforces the policy server-side and records
  every test (the question, never the answer) in the console's action log.
- **`stores.created_at`** (migration 0020, backfilled from the earliest
  audit entry); the console lists stores as a table with created and
  last-change times and lets owners delete a store (Admin tab, typed confirmation,
  audit history kept unless purged); platform admins can delete unclaimed
  stores.
- **Condition descriptions and times** (migration 0021): `create_condition`
  takes `p_description` (NULL keeps, `''` clears; a description-only change
  is an audit version), `conditions.created_at` / `updated_at`, export and
  the registry carry the description. The console lists them, edits
  conditions and temporal gates in place (add / replace / remove, mode
  enforce|shadow|off, clause templates), and shows each one's SQL
  definition and JSON.
- **Console translations are JSON** (`frontend/src/i18n/<lang>.json`) and
  an operator can override entries or add a language with `<lang>.json`
  files in `CONSOLE_I18N_DIR` (served at `api/i18n/<lang>`; `@language`
  names a new one).
- **Store documentation link.** `authz.stores.docs_url` (migration 0018) and
  `authz.update_store(store, description, docs_url)` (admin tier): where the
  owners keep the longer description of a model; the console shows it on
  the store card and header, owners edit it there.
- **Console: define a model as DSL.** The Model tab's "Edit as DSL" takes
  the OpenFGA-style DSL the DSL view shows (an empty store starts from a
  small template) and applies it through the OpenFGA importer: types and
  relations added, rules and type restrictions replaced, relation kinds
  inferred. The parser moved from pgauthzctl into `pgauthzadm.ParseDSL`,
  which also accepts `describe_model` output (store line, `# permission`
  markers). "+ relation" defines a relation on its object types with its
  type restrictions (or a permission with what it derives from) in one
  step; editor forms carry titles and open with a cleared selection.
- **`pgauthzadm` — the embeddable admin library.** The registry and export
  code of `pgauthzctl` (status, versions, plan, publish, apply, rollout,
  export, DSL) moved into a Go module the console uses in-process;
  `pgauthzctl` is now a thin shell over it. New `pgauthzctl model export
  --sql` renders a model as the engine calls that rebuild it (complete,
  unlike `--dsl`).

### Security

- **`model_remove_type` with `p_force => NULL` no longer skips the tuple
  guard.** The check was `v_tuples > 0 AND NOT p_force`; with a NULL flag
  that is NULL and the `IF` fell through, deleting a referenced type and
  its tuples without consent. It is now `p_force IS NOT TRUE`. The guard
  also counts **expired** tuples (hidden from ordinary counts by RLS but
  deleted by the purge) through a new RLS-bypass helper,
  `_rls_count_type_tuples`, and names them in the error;
  `plan_model_apply` reports the same count as a blocker. Tests rt_10/rt_11.
- **Type and relation removal are serialized against tuple writes.**
  `model_remove_type` counted a type's references, then purged; a tuple
  written in between was deleted without `p_force` or left orphaned. The
  count (and `apply_model`'s stale-relation guard) now runs under a
  `SHARE ROW EXCLUSIVE` lock on `authz.tuples` (self-exclusive, so two
  removals serialize instead of deadlocking on their later deletes):
  in-flight writers commit first and are counted, later writers wait the
  milliseconds a removal takes, reads never wait, and no write path can opt
  out because the lock manager enforces it, not a convention. Writers take
  their `ROW EXCLUSIVE` lock on the parent as their first statement, before
  resolving names to ids, closing the window in which a writer inserts
  against an id the removal just deleted; the remover (and `apply_model`)
  likewise lock before resolving, so a second removal of the same type
  fails cleanly instead of dropping a re-registered type's partition by
  name. Removals require `READ COMMITTED`
  and raise otherwise (a repeatable-read snapshot would predate the lock).
  Documented: detaching the type's partition holds `ACCESS EXCLUSIVE` until
  commit, so checks pause briefly per removed type. The stale-relation
  guard also counts **expired** tuples
  (new `_rls_count_relation_tuples`), as the type guard does, and
  `plan_model_apply` reports the same count. New two-session suite
  `tests/test-concurrency.sh` (in `test-all.sh`) shows the remover waiting
  for a writer, a writer waiting for a remover and then failing cleanly
  once it committed, two removals serializing (also of the same type), the
  removal lock conflicting with itself, two partial-precondition writers
  serializing, and two object-scoped writers staying concurrent. The second
  session starts only once `pg_stat_activity` shows the first inside its
  hold, not after a fixed delay, so slow runners cannot make it flaky.
- **Checked writes: partial preconditions take the store lock.** A
  `write_tuples_checked` precondition without `object_id` ("alice owns no
  document") expresses a cross-object invariant that the per-object locks
  could not protect: two such writers on different objects could both see
  it hold and both commit. The lock protocol is now store first, then
  objects: object-scoped requests, `grant`, `revoke` and `apply_grants`
  hold the store lock shared, a partial precondition holds it exclusively.
  A precondition missing *either* `object_type` or `object_id` is partial
  (an `object_id` alone matches every type and used to lock nothing).
  `allowed`/`denied` keep the target-object lock; their graph dependency is
  documented as the same window a human share has. DEVELOPMENT.md; tests
  pc_13/pc_14 check the held modes.
- **Documented the sharing trust boundary.** `authz.grant` / `revoke` take
  the actor as a parameter; `authz_sharer` must stay with a backend that
  authenticates its users (pgauthzd derives the actor from the token).
  API.md note + PRODUCTION.md checklist item.
- **Console: changes are re-authorized inside their transaction, under a
  per-object lock.** Every console write (role grants and removals, model and
  data changes, store creation/adoption/deletion, recorded tests) now takes a
  transaction-scoped advisory lock on the console object it concerns
  (`store:X`, `platform:default`) and asks the console store again whether
  the person may still do it, in the same transaction — so a role revoked
  between the screen's check and the click is honoured, and two owners
  removing each other at the same time leave one owner, never zero (the
  last-owner count runs under the same lock). Store capabilities can be
  inherited from the platform, so a store change also holds the platform
  lock in shared mode and a platform-admin grant or revocation takes it
  exclusively: a revocation waits for the store changes that admin already
  started and is seen by every one that starts after it. Renaming a
  namespace re-checks both capabilities it needs (`can_edit_model` and
  `can_manage_access`). Go regression tests (`console/backend`,
  `PGAUTHZ_TEST_DATABASE_URL`) race two owner removals, a platform
  revocation against a store change, and the rename gate;
  `tests/test-console-go.sh` (part of `test-all.sh`, so CI) runs them
  against a fixture store and fails if they skip. Lock keys are 64-bit
  (`hashtextextended`).
- **Console: an expired session is no session.** The BFF refreshed the
  access token only when a refresh token existed; without one it kept
  serving the stale memberships until the 8-hour cookie ran out. A session
  whose token has expired and cannot be renewed is now deleted and answered
  with 401. Membership changes in the IdP therefore reach the console within
  the access-token lifetime.
- **Console test policy: "your own access" binds the subject type.** The
  self-subject check compared ids only, so a tester without
  `can_test_others` could ask about `agent:alice` or `service_account:alice`.
  The subject must now be the person's id under the console subject type or
  one of `CONSOLE_SELF_SUBJECT_TYPES` (the types that denote people in the
  managed stores; the demo stack lists `user,internal_user`).

### Fixed

- **Derived permissions: a physically deleted store kept its rows.** The
  worker found its stores by joining the registry to `authz.stores` by name,
  so after `delete_store` the store was never visited again and its derived
  rows stayed — and a store recreated under the same name would have exposed
  its predecessor's permissions until rebuilt. Deletion now invalidates
  synchronously: a trigger on `authz.stores` drops the store's rows and
  registration in the deleting transaction (they replicate atomically); the
  registration records the store's id, the subscriber's `check_permission()`
  requires a registration row (a stale row of an unregistered incarnation
  answers false), and registration, cleanup and the trigger serialize per
  store name on an advisory lock with an incarnation check, so a concurrent
  re-registration is never undone. Regression tests: delete → immediate
  emptiness on primary and replica → recreate → false until registered;
  cleanup of a dead incarnation racing refresh_all under a held lock.
  Deletion and snapshot also order themselves on the engine's store-wide
  lock (the one checked writes hold shared): `delete_store` and
  `retire_store` now take it exclusively as their first statement — before
  resolving the name, before the partition DDL — so they wait for checked
  writes and a running snapshot; `refresh_all_materialized_relations` takes
  it shared and resolves the name only afterwards, so it can no longer
  register the id of a store whose deletion is in flight; the worker
  try-locks and skips rather than waits, so a deletion's DDL and the
  worker's reads never form a cycle (the two try-locks and the check that
  the store is still registered run in one subtransaction, so a failed step
  releases what was taken), and re-reads
  each registration under its locks, so a deletion or re-registration
  committed after it listed its stores is seen, not acted on from stale
  state — tested deterministically by parking the worker on a held row
  while the next store is deleted, recreated and registered anew. Tests: each pairing with a held-open
  transaction, and twelve seconds of deletion/recreation, snapshot and
  worker on one store with no deadlock, no orphan row and engine agreement;
  the live-upgrade test now covers `materialized_objects` too.

- **Derived permissions: upgrading an existing subscriber.** The in-place
  rename on the publisher had no counterpart for subscribers, which logical
  replication matches by name. `db/replication/upgrade-derived-tables.sql` plus
  the documented procedure (disable; upgrade both sides; truncate the
  subscriber's derived tables; enable; refresh publication; verify) brings a
  first-shape subscriber to the current shape; the publisher script also
  repoints an existing `authz_derived` publication at the four current
  tables. The rows are re-copied rather than kept: the first publication
  listed leaf partitions, the current one publishes the root, which the
  subscription meets as a new table and copies in full — into a subscriber
  still holding the old rows that copy collides on the key and never
  finishes (the first draft of the procedure did exactly that). Tested
  through a LIVE subscription from the first shape
  (`tests/sql/derived_subscriber_v1.sql`): disable, upgrade both sides,
  truncate, enable and refresh, whole-row parity, then an insert and a
  delete after resumption. The replication test compares
  subscribers to the primary by a whole-row digest (`row_to_json`), not by
  row counts.
  `check_permission()` is documented to answer for any relation, like
  `check_access()`; `is_permission` classifies, it does not restrict.

- **Namespace access check failed on installs without roles.sql.**
  `_check_namespace_access` asked `pg_has_role` about `authz_namespace_bypass`
  unconditionally, which raises "role does not exist" where roles.sql has not
  run (a bare engine load, the replication demo): the first namespaced type
  made every read of that type's permissions fail. The role lookup is guarded
  now; `tests_namespace.sql` 25/25.

- **Derived permissions: the refresh entry points require READ COMMITTED.**
  Third review round: the cutoff is read from `pg_stat_activity`, which is
  not MVCC, while the feed is read through the transaction's snapshot. Under
  `REPEATABLE READ` or `SERIALIZABLE` a transaction that committed between
  the snapshot and the cutoff capture is invisible yet no longer open, so
  its rows would be skipped for good. `refresh_materialized_relations` and
  `refresh_all_materialized_relations` now raise `invalid_transaction_state`
  in any isolation level other than `READ COMMITTED`, where every query
  inside these `VOLATILE` functions takes a fresh snapshot after the capture.
  Regression tests for both entry points.

- **AuthZEN conformance job: MongoDB could not start on current GitHub
  runners.** The suite's MongoDB (`mongo:9.0.2-noble`) exits at startup on
  Linux kernels 6.19 up to 7.0.13 (SERVER-121912) and, before 9.0.4, misreads
  Ubuntu's 7.0 kernels as 7.0.0 (SERVER-131779); the runner image of
  2026-10-18 ships such a kernel, so every plan failed with "could not start
  MongoDB for the conformance suite". `conformance/settings.go` now pins
  `mongo:9.0.4` by digest (the same pin as easyssf/easyssf#54).

- **Derived permissions: the cursor cutoff is absolute, exclusive, and
  includes the worker's own transaction.** Second review round: the gate was
  an interval re-applied against a moving clock inside the feed query, so
  the effective cutoff drifted forward while a run worked through earlier
  stores, and it excluded the worker's own session, so a worker invoked
  inside an explicit transaction could advance past rows that transaction
  wrote afterwards. `watch_changes` gains `p_until` (absolute, exclusive;
  replaces `p_lag` when set) and the engine gains `watch_safe_until(lag)`:
  now minus the lag, capped at the start of the oldest transaction open on
  the database, the caller's own included. The worker captures it once per
  run; `refresh_materialized_relations` / `refresh_all_…` accept `p_until`
  as an explicit override for tests and controlled replays. Regression
  tests: a cutoff in the past returns nothing a lag would, and a worker run
  inside a transaction that keeps writing leaves the cursor at that
  transaction's start. Documented operational limit: a long-open
  transaction, read-only ones included, holds every revocation back —
  `permissions_fresh(store, max_staleness)` on the subscriber lets a
  consumer refuse a stale copy. The `watch.sql` header no longer claims that
  `statement_timeout` bounds a transaction. `roles.sql` grants the new
  signature and `watch_safe_until` to `authz_auditor`.

- **Derived permissions: review follow-ups (incremental refresh).** Four
  correctness and privilege findings from an external review of the
  changefeed-driven worker, each with a deterministic regression test in
  `tests/test-replication.sh`: (1) a subject or object that *became* known
  under a wildcard lost the `*` rows it had inherited without gaining
  concrete ones — the worker now derives the newcomer against every object
  (subject) carrying a `*` row of its type; (2) the cursor could skip a
  write made in a transaction that committed after a later one — the gate
  is now max(stability lag, age of the oldest open transaction), read from
  `pg_stat_activity`, so an open transaction stalls the cursor instead of
  being lost (`last_run_gate` / `oldest_open_txn_age` in the status);
  (3) the three public `SECURITY DEFINER` entry points kept PostgreSQL's
  default `EXECUTE` for `PUBLIC` — revoked, granted to `authz_admin`, and
  every function pins `search_path = pg_catalog, pg_temp`; (4) a forced
  type removal left the store's rows stale while the feed reported itself
  drained — `TYPE_REMOVED` (or unresolvable tuple deltas) now rebuilds the
  store in the same run, `STORE_RETIRED` drops it. Also: the store-wide
  known-subject set is built only for deltas that need it, so a principal's
  grant never scans the subjects; `last_run_pairs` / `last_run_rows_written`
  are per store; the random-mutation harness fails on psql errors, requires
  a minimum of applied draws and distinguishes model rejections from
  unexpected SQL errors.

- **Derived permissions under-authorized on wildcards.** On the derived
  replica a subject-wildcard grant (`employee:*`) produced only a literal
  `*` row, so an unknown employee was denied although the live engine
  allows; an object-wildcard grant (`document:*`) was expanded only to
  objects that already had tuples, so a document the engine had never seen
  was denied. Both are fixed by the wildcard contract (see Changed). Also
  fixed: on a `roles.sql` install the queue trigger failed with
  `permission denied for table materialized_refresh_queue` (tuple writes run
  as the BYPASSRLS helper's owner), and calling the refresh and the public
  `check_access` in one session failed with `permission denied for table
  _check_memo_v2` (two roles creating the engine's memo table).

- **Tests, example models and bench suites declared dictionary ids as
  `smallint`.** The engine's `types` / `relations` / `models` ids are
  `integer` (serial) and have been all along; test-local variables and a
  few `::smallint` casts were not, and a long-lived development database
  whose `models` sequence had passed 32,767 made `tests/test.sh` abort with
  `smallint out of range` at the first affected block. All widened to
  `integer`; ARCHITECTURE.md no longer calls the ids `smallint`.

### Changed

- **Go 1.27.3** across every module (`pgauthzd`, `pgauthzadm`, `pgauthzctl`,
  `console/backend`, `conformance`, `playground/backend` — the last three
  were still on 1.26) and the three `golang:1.27.3-alpine` builder images;
  CI reads the version from `pgauthzd/go.mod`. `go mod tidy` on pgauthzd
  swapped one indirect module (`rogpeppe/go-internal` in,
  `go.yaml.in/yaml/v2` out).
- **Derived permissions: userset and object-reference deltas expand through
  the engine; the snapshot is the blast radius of every tuple.** Characterizing
  the worker on the 50 k-user `drive` store (BENCHMARKS.md addendum
  2026-10-20) found the scale limit of "every known subject" as the fallback
  for a userset share or a folder move: 50,018 pairs and 2.2 minutes for one
  share, and a snapshot of objects × subjects that could not finish. The
  worker now asks `list_subjects` (gates off, once per distinct reference)
  who holds the userset's relation or any relation on the referenced object,
  and `refresh_all_materialized_relations` takes the blast radius of every
  tuple instead of the cross product: the share is 50 pairs in ~200 ms, its
  revocation the same, a folder move 4 pairs, the snapshot 110 k pairs in
  ~200 s; principal deltas stay at one pair in tens of milliseconds. Every
  known subject is re-derived only for subject-wildcard grants (by the
  contract: ~100 s per public document at that scale), a wildcard reported by
  `list_subjects`, or a manual whole-object entry. The closure also walks the
  batch's own deleted edges — the random differential found a member whose
  membership and whose team's reference vanished in one batch was otherwise
  reached by neither path; that case is a deterministic regression test now.

- **Derived permissions table documented as a feature.** The flat
  `authz.materialized_relations` table (`db/replication/`) — pgauthz's
  equivalent of a hosted *permissions index* for search, analytics and
  application databases that join on precomputed answers — now has a use
  case, a README feature line, a comparison row and an explicit statement
  of its limits (context-free answers, no gates, brute-force refresh,
  two-level reverse propagation) in `DESIGN.md`.

- **Derived permissions: the wildcard contract.** Wildcard grants are
  stored as literal `*` rows, which are correct only for a subject or
  object the engine does not know. Two side tables,
  `authz.materialized_subjects` and `authz.materialized_objects`, now
  travel with the permissions table (publication `authz_derived`), and the
  subscriber helper `authz.check_permission()` (`schema-derived.sql`)
  applies the rule — a known entity's concrete rows are authoritative, a
  `*` row covers unknown ones — as one inlinable SQL expression. A write of
  an object-wildcard tuple re-derives every object of its type; subjects
  that lose their last tuple are delisted (wildcard-covered). The refresh
  goes through `authz._decide` with an empty gate list (graph only), and
  the refresh functions and queue trigger are `SECURITY DEFINER`, handed to
  `authz_owner` when `roles.sql` has run. `tests/test-replication.sh` now
  loads the aia-acme fixture next to the demo and asserts, differentially,
  that the subscriber's `check_permission()` equals the primary's live
  `check_access()` for every subject × relation × object plus unknown
  probes (~9 000 checks), and that a primary write reaches the derived
  replica through the refresh queue. The narrated
  `demo-replication.sh` gains a section walking through the contract (the
  `*` rows, a naive lookup getting an unseen document wrong, the helper
  getting it right, a wildcard grant re-deriving the type), and DESIGN.md an
  example to match. `init-replication.sh`, the demo and the test accept
  `REPLICATION_COMPOSE_FILES` (override files, e.g. other host ports) so the
  demo can run next to the main stack.

- **Derived permissions: incremental, changefeed-driven refresh.** The
  worker `authz.refresh_materialized_relations()` replaces the tuple
  trigger and `process_materialized_refresh_queue()`: it follows
  `authz.watch_changes` from a per-store cursor (registered by
  `refresh_all_materialized_relations`, which takes the snapshot from
  just before the cursor), computes each delta's blast radius — the
  objects that reach the changed object through tuples at full depth, the
  delta's own subject when its type can never be an edge (no relation on
  it in the model), every known subject for usersets, object references
  and subject wildcards — decides
  those pairs and diffs them against the stored rows, so the table only
  ever receives real inserts and deletes. A grant or revoke re-derives one
  pair in tens of milliseconds instead of every subject of the object; the
  two-level reverse-traversal limit is gone. Expiring tuples file a
  deferred delta due at their expiry, so the rows they granted are
  withdrawn on time. `authz.materialized_refresh_state` (replicated) carries
  cursor and `as_of`; `materialized_relations_status()` on the primary and
  `permissions_as_of(store)` on the subscriber say how stale the copy may
  be. Requires the audit profile. `tests/test-replication.sh` now also
  runs three batches of random mutations
  (`tests/sql/derived_permissions_mutate.sql`: grants to known, fresh and
  `*` subjects, expiring grants, revokes, usersets, object wildcards) and
  re-runs the differential after each. Two things that loop caught before
  release: an object and a subject vanishing in the same change left the
  subject listed as known (objects were pruned before subjects were
  resolved), and a tuple expiring in the milliseconds between the worker's
  statement start and its expiry-filing step was derived but never filed
  (`clock_timestamp()` vs the RLS policy's `statement_timestamp()`); and
  deciding "is this subject type a principal?" from the current tuples
  turned a type into a principal in the very batch that deleted its last
  edge, so the deleted edge's delta re-derived one pseudo-subject instead
  of everyone above the cut — it is decided from the model now. A
  set-based blast radius was tried first and rejected: with the keys coming
  from a CTE the planner joined the whole tuples table per delta (4 s next
  to large benchmark stores); the procedural version probes indexes with
  constant keys.

- `publish_model` and `apply_model` attribute `created_by` / `applied_by`
  to the `authz.performed_by` session setting when it is set (the same
  convention as the tuple audit trail), else to the connection's role.

- **Per-client, per-store subject assertion (ADR 0014).** `ALLOW_SUBJECT_OVERRIDE`
  was process-wide: every token could assert any subject, or none could.
  Each `JWT_ISSUERS` entry now takes `pep_clients` — client id (the token's
  `azp`, else `client_id`) → anchored store patterns — so that *this* service
  may speak for users in *these* stores and nowhere else, while every other
  token stays self-subject. One predicate decides for the decision path, the
  batch and the native checks AND for `performed_by` / `recorded_by` on
  writes; a refused assertion is a `403` naming client and store; a pattern
  that reaches beyond the issuer's `stores` binding is a startup error; the
  coarse switch next to a map is a warning and is refused in production;
  `pgauthzd doctor` reports the assertion matrix. The decision log gains
  `client` (the token's `azp`) on every line, so a PEP's service credential
  is attributed even without a user subject. Deny by default — no behaviour
  change for existing deployments. The conformance harness's api_key carries
  `azp: conformance-suite`.
- **Embedded Swagger UI (`SWAGGER_UI_ENABLED`, default off)** at
  `GET /pgauthz/v1/docs`: renders the instance's OpenAPI document same-origin,
  so "Try it out" needs no CORS — Authorize with a bearer JWT. The assets
  (swagger-ui-dist 5.33.1, Apache-2.0) are vendored into the binary by
  `scripts/vendor-swagger-ui.sh`, which pins the tarball's sha256; nothing is
  loaded from a CDN and the page's CSP allows scripts from this origin only.
  Needs `OPENAPI_ENABLED`; the demo stack turns it on via env.sh. With
  **`SWAGGER_UI_OIDC_ISSUER` + `SWAGGER_UI_OIDC_CLIENT_ID`** the Authorize
  dialog logs the user in at an OpenID Provider (authorization code + PKCE,
  public client, the vendored `oauth2-redirect.html` on the UI's origin)
  instead of taking a pasted token: the served document gains an `oidc`
  security scheme on every authenticated operation (with
  `SWAGGER_UI_OIDC_AUTHORIZATION_URL`/`_TOKEN_URL` the one `authorizationCode`
  flow, else the issuer's discovery document), and the page's CSP admits the
  issuer. The Keycloak overlay provisions the `swagger-ui` public client
  (`keycloak/terraform/client.swagger-ui.tf`, PKCE S256, the `authz-api`
  audience, `subject_type`) and configures the instances that trust Keycloak;
  verified end to end: login as alice, token exchanged by the UI, decision
  returned.
- **OpenAPI for external tools, discovery documented.** The served document
  now carries a `servers` entry stamped with the instance's public base URL
  (the `BASE_URL` / `TRUST_FORWARDED_HEADERS` rules of discovery), so a
  Swagger UI or Postman loading `/pgauthz/v1/openapi.json` calls pgauthzd
  rather than itself; the entity schemas carry demo-store examples so a
  "Try it out" body is meaningful as generated; the public endpoints — discovery, health, the document,
  the UI — answer any browser origin (CORS), and a new
  **`CORS_ALLOWED_ORIGINS`** (default empty) opens the authenticated API to
  listed origins (`*` = any) for browser PEPs or an external UI's "Try it
  out". The three `/.well-known/authzen-configuration` operations
  (instance-wide, the §9.2 tenant form `/.well-known/authzen-configuration/stores/{store}`,
  the path-appended convenience form) and the metadata schema now describe
  what they return, with a store-scoped example; the daemon README shows the
  Swagger UI one-liner.
- **AuthZEN `properties` reach the engine's conditions.** `subject.properties`,
  `resource.properties` and `action.properties` on `/access/v1` requests
  (evaluation, evaluations, the three searches) are put into the request
  context under the entity's own key in the request's shape —
  `context.action.properties.soft`, `context.resource.properties.status` —
  so a SQL or CEL condition reads the wire request; an entity without
  properties adds nothing, a caller context key named like an entity is
  replaced. Batch items are now evaluated with their OWN context: the shared
  `context` overridden per key by the item's (§7.1 context inheritance, which
  was dropped before), then the item's properties — `authz.check_access_batch`
  takes an optional per-check `"context"` key for it, and the OPA path
  forwards it. The `authzen-cert` fixture gained the Properties level of the
  certification profile (rules 5–8: bob's admin role and record-2's archived
  status as tuples, soft-vs-hard delete as one conditional wildcard tuple
  reading `action.properties.soft`), the conformance harness runs the plans
  with `authzen_support=properties` by default (`CTS_SUPPORT=core` for the
  core level), and MODEL_DESIGN §8 gained "AuthZEN request properties"
  (attributes are data, properties are claims).
- **`TRUST_FORWARDED_HEADERS`** (pgauthzd, default `false`): build the
  discovery document's base from `X-Forwarded-Proto` / `X-Forwarded-Host`,
  for an instance behind a TLS-terminating proxy that sets them — AuthZEN
  1.0 §9.2.3 wants the advertised `policy_decision_point` identical to the
  URL the metadata was fetched from, which a proxied instance cannot know
  from its own request. Off by default (a client could otherwise choose the
  advertised identifier); `BASE_URL` still wins when set. The demo stack opts
  in (env.sh) and the conformance harness carries the `discovery` variant
  of the five certification plans (`TestDiscoveryPlans`); it stays skipped
  until the suite can run discovery with an api_key at all (the fetched
  metadata currently replaces the configured key — a second suite defect,
  [conformance-suite#2041](https://gitlab.com/openid/conformance-suite/-/work_items/2041),
  documented in `conformance/README.md`).
- **AuthZEN certification fixture** (`examples/models/authzen-cert/`): the
  PDP data the OpenID Foundation's conformance suite expects
  ([openid/authzen #433](https://github.com/openid/authzen/issues/433)) —
  users alice/bob, records record-1/record-2, actions read/write/delete — as
  a pgauthz store (`authzen_cert`), so the `authzen-pdp-*-test-plan`s can run
  against `/stores/authzen_cert/access/v1`. `tests.sql` pins the Core-level
  decisions and searches the suite validates; `test.sh` loads it as a
  fixture.
- **Conformance harness** (`conformance/`, `tests/test-conformance.sh`): a
  Go module that starts the OpenID conformance suite with Testcontainers
  (release-v5.3.2, pinned by digest — the bootstrap of easyssf-go's
  conformance module), puts an https front in front of pgauthzd (the suite
  refuses plain http), mints the subject-less `api_key` JWT the suite
  authenticates with, and runs every module of the five AuthZEN PDP plans
  (evaluation, evaluations, subject/resource/action search) plus the
  short-circuit comprehensive plan as Go subtests, failing with the suite's
  log and link. Variant `api_key` / `static` / `core`; `discovery` and
  `properties` are documented as not covered yet. CI runs it on every push
  (`conformance-test` job) against the stack's `pgauthzd-decision`.

- **Agentic authorization demos.** Alongside the `agents` model
  (`examples/models/agents/`, the *Authorization in Action* ch. 18 scenario),
  the repository now carries runnable demos of a human delegating to an
  agent: `examples/agentic/delegation-demo.sh` (Keycloak token-exchange
  delegation → a task-bounded agent, subagent reach, task completion, time
  travel — details in the next entry) and its out-of-band **step-up consent**
  via Keycloak CIBA, both scripted end to end against the `--keycloak` stack;
  plus a capability-teaser slide deck, *pgauthz: Can your AuthZ do that?*
  (`docs/slides/`), linked from the README.
- **Delegated actors (`ACTOR_CLAIM` / `ACTOR_SUBJECT_TYPE`)** on pgauthzd and
  OPA: a token carrying an RFC 8693 `act` claim (OAuth token-exchange
  delegation — Keycloak 26.8's `token-exchange-delegation`) is checked **as the
  actor** (`agent:<act.client_id>`) with the actor's own authority, never as
  the user it acts for; the user is carried as `on_behalf_of` in the decision
  log (new field) and on the OPA hook actor (`input.actor.on_behalf_of`,
  additive to the ADR 0011 ABI). Off by default. New runnable example
  **`examples/agentic/`**: alice consents to the `acme_assist` agent acting
  for her, the agent exchanges her token for a delegated one, and the PEP
  opens a task-bounded authority for it in the `agents` store (expiring task
  bundle under a precondition on alice's own access, subagent reach) and
  closes it when the task is completed — the still-valid delegated token then
  denies everywhere; time travel replays the window. **Step-up consent out of
  band (CIBA):** when the agent needs more than its task gives, the rich
  decision's reason is the cue to ask — the PEP sends a backchannel
  authentication request (`…/ext/ciba/auth`, same delegation scope, a
  `binding_message` plus what/why as extra parameters), Keycloak delivers it
  to the authentication entity (alice's device, played by the script on
  `:18555`), a decline ends in `access_denied` and nothing changes, an
  approval yields a fresh `may_act` token and only then does the PEP widen the
  task bundle (one more `write-checked`); `--browser` lets you answer the
  prompt yourself. Keycloak overlay: the two preview features are enabled,
  the CIBA HTTP authentication channel points at the docker host
  (`CIBA_AUTH_CHANNEL_URI`), `keycloak/terraform/client.agentic.tf` adds the
  clients (acme-app with the CIBA grant) and the FGAP v2 `delegate`
  permission, `realm.tf` spells out the CIBA policy, and the overlay now
  carries the two-issuer `JWT_ISSUERS` set itself (previously only the
  playground overlay did), so `./start.sh --keycloak` alone serves Keycloak
  tokens through pgauthzd.
- **Sharing as a first-class API: `authz.grant` / `authz.revoke` + grant
  rules** (migration 0017). A grant rule (`model_add_grant_rule(store, type,
  relation, requires, p_requires_revoke)`) declares which relation an actor
  must be allowed on the *same object* to hand a relation out; `authz.grant
  (store, actor_type, actor_id, user_type, user_id, relation, object_type,
  object_id, …)` looks it up, runs the actor's full check under the
  per-object lock `write_tuples_checked` uses, and writes the tuple with
  `performed_by` = the actor (`revoke` likewise). Fail-closed by
  construction: no rule → refused, a rule may not require the relation
  itself, object wildcards are refused; refusals name the missing right and
  any missing request context. Rendered by `describe_model` (`# grant
  requires …`), exported/applied by the registry (checksum-neutral when
  absent), audited (`grant_rules_audit`), removed with their type by
  `model_remove_type`. New DB role **`authz_sharer`** (these two functions
  only; `authz_writer` inherits it). pgauthzd: `POST /pgauthz/v1/grant` and
  `/revoke` — the actor is the token subject, no `WRITER_ROLE` needed, 403
  with the engine's reason when refused; OPA ops `grant` / `revoke`. New
  suite `tests/sql/tests_grant.sql`. (`grant`/`revoke` are SQL reserved
  words: call them schema-qualified, as every authz function is.)
  **For share dialogs:** `grant_options(store, actor, object)` renders per
  relation whether the actor may grant / revoke it, the required relations
  and who may hold it (`grantee_types`); `can_grant` / `can_revoke` as
  booleans (false, never an error, without a rule); `grant_options_batch` for
  many (actor, object) pairs in one call (a list view's "Share" buttons);
  `list_grant_rules`; and
  `apply_grants(store, actor, p_grants, p_revokes)` saves a dialog's changes
  as one transaction, all-or-nothing, naming a refused entry. pgauthzd:
  `POST /pgauthz/v1/grant-options` (a read) and `/apply-grants`. The gdrive
  example gains grant rules (`viewer` requires `can_share`; revoking a doc's
  viewer requires `owner`), a share-dialog demo section and tests.
- **`authz.model_remove_type(store, type, p_force, p_performed_by)`** — the
  missing counterpart of `model_register_type`. Removes a type with its rules,
  the restrictions that name it on either side and its tuple partition; fails
  closed on gates and recorded events (always) and on tuples naming the type
  as object or subject (unless `p_force`, which deletes them, expired rows
  included, through the audited path with a `TYPE_REMOVED` marker that
  `watch_changes` delivers to every watcher). Before, nothing removed a type
  and a manual `DELETE` orphaned its tuples. `apply_model` now removes types a
  new version no longer declares when nothing references them; a referenced
  one blocks the apply and `plan_model_apply` reports it as a
  `type_referenced` blocker (replaces the unconditional `extra_type` blocker).
  New suite `tests/sql/tests_model_remove_type.sql`.

### Changed

- **Docs: the two ways to call pgauthzd.** `pgauthzd/README.md` gains "Two
  ways to call pgauthzd" — forward the user's token (self-subject, the
  default) versus ask as a PEP with a service credential
  (`ALLOW_SUBJECT_OVERRIDE=true`): who names the subject, what may be
  omitted, how writes and the decision log attribute, how to scope a PEP's
  credential — and `docs/USE-CASES.md` indexes it.
- **BREAKING (AuthZEN search responses): `results` now holds the entity
  objects themselves.** AuthZEN 1.0 §8.4.2/§8.5.2/§8.6.2 define the search
  results as arrays of subject objects `{type, id}`, resource objects
  `{type, id}` and action objects `{name}`; pgauthzd returned the pre-1.0
  draft's wrapped items (`{"subject": {…}}`, `{"resource": {…}}`,
  `{"action": {…}}`), which failed every result-bearing module of the
  conformance suite's three search plans. Clients that read
  `.results[].subject.id`, `.results[].resource.id` or `.results[].action.name`
  change to `.results[].id` / `.results[].name` (the repository's own scripts,
  demos and docs are updated; the native `/pgauthz/v1/list-*` endpoints are
  unchanged).
- **PostgreSQL 18.6.** Every image pin moves from 18.4 to 18.6 (compose
  stack, replication/scaling demos, Keycloak and playground databases, the
  pg_cel build, the migrations runner image, the Helm CNPG tag, CI,
  `gen-schema.sh`). A minor release: data directories upgrade in place, no
  engine or migration change. Benchmark figures and the planner notes in
  `access.sql` still say 18.4 — that is the version they were measured on.
- **OPA 1.21.2** (was 1.20.2) everywhere the sidecar is pinned: compose
  overlays, Helm, CI, the hook validator and the pre-release script. Carries
  the Go 1.27.2 security rebuild, the 1.21.2 fix that makes the basic
  authorizer (`--authorization=basic`, our `system_authz.rego`) and the Data
  API resolve `%2F`-encoded slashes to the same document, the 1.21 rule-indexer
  improvements, `rule_labels` on Data API responses, and the 1.20 `and`/`or`
  keywords for hook authors. Behaviour changes checked against every Rego
  suite and the hook validator: stricter `:=` safety (1.19), empty literals
  typed as empty (1.21), YAML 1.2 parsing (1.21; we load JSON data only).
- **Keycloak 26.8.1** in the demo issuer overlay (was 26.7.5):
  `compose-keycloak.yml`, `keycloak/README.md`, `keycloak.conf`. 26.8 is the
  release that ships token-exchange delegation and parameterized scopes as
  preview features, which the agentic example turns on (`KC_FEATURES`); CIBA
  is a supported feature, on by default.
- **Documentation split: one owner per topic.** `README.md` shrinks from
  ~2,000 to ~330 lines — pitch, features, setup, the complete example and a
  **documentation map** — and every topic now has exactly one home:
  `docs/API.md` (new; the SQL function reference and recipes), `docs/AUDIT.md`
  (new; audit trail, time travel and the changefeed, which moves out of
  DEVELOPMENT), `docs/COMPARISON.md` (new; the OpenFGA comparison),
  `examples/models/README.md` (new; the example index), `examples/filtering/`
  (authorization as a JOIN, prose included), `docs/MODEL_DESIGN.md` (gains
  multi-store, namespaces, the condition-language and missing-context sections
  and the CIDR note; its stale `required_context` description is corrected),
  `docs/ARCHITECTURE.md` (gains the resolution walkthrough, the OPA / AuthZEN /
  read-replica deployment sections and the access-control roles),
  `docs/DESIGN.md` (the long "Why PostgreSQL"), `docs/DEVELOPMENT.md`
  (repository layout), `playground/README.md` (overview). README sections that
  merely paralleled an existing owner (wildcards, object wildcards, rule
  groups, temporal gates, deployment topologies) were dropped in favour of
  that owner. Old README anchors are rewritten repo-wide; `llms.txt` at the
  root and AGENTS.md "Where to read" point agents at the owner instead of the
  README. New `scripts/check-links.sh` (relative links + anchors, GitHub slug
  rules) runs in CI and pre-release; it also caught four links that had been
  dangling for a while.

### Added

- **`docs/USE-CASES.md`** — an index of use cases from simple (roles,
  hierarchies, public access, expiring grants) through common (folder
  inheritance, conditions, fail-closed device checks, rule groups, object
  wildcards, sharing administration through checked writes, lifecycle
  markers (archived, legal hold, draft), suspension / offboarding /
  break-glass, one user in several tenants, service principals and acting
  on behalf of a user, data filtering, time travel, changefeed, policy hooks,
  namespaces, the registry, OpenFGA and Cedar imports) to advanced (rate
  limits, prior approval, separation of duties, lockout, quotas, exact caps,
  shadow rollout, agent task scope, sequencing, delegation, the control
  plane, RAG), each with a short sketch of how to express it and a link to
  the owning doc or example. Listed in the documentation map, `llms.txt`
  and AGENTS.md.
- **Conditions declare their clock, and the server's is the default**
  (migration 0016). `create_condition*` gain `p_time_source => 'server' |
  'caller'`. A `server` condition — the default for every condition created
  from now on — has `current_time` set by the engine before evaluation
  (statement time on live paths; on time-travel paths `current_time` is
  `p_at` for every condition, as before) and ignores any caller value, so
  business hours and grant windows cannot be forgotten or backdated by the
  enforcement point, and never report `current_time` as missing context.
  `caller` is the explicit choice when the request legitimately asserts a
  time (tests and demos that pin the clock, "as of T" asked live); the
  shipped examples and suites say so where they do. **Upgrade note:**
  conditions that exist when the migration runs are stamped `caller`, so no
  existing decision changes; `describe_model` renders every condition's
  clock (`# condition x (sql, caller time)`) for review. The choice is
  policy: versioned in `conditions_audit`, exported by the registry only when
  `server` (definitions published earlier keep meaning `caller`; existing
  checksums do not move), rendered by `describe_model`, and named on a denied
  step in `explain_access`. Signature note: the three `create_condition*`
  functions gained a trailing parameter (roles.sql updated; old overloads
  dropped on reload).
- **`examples/models/fourquestions/`** — the pitch sentence as one runnable
  store: *share this folder with the marketing team, except Bob; external
  reviewers read-only until next Friday, but only once they accepted the NDA; three
  downloads a day; payments over 10k need two distinct approvers.* A userset
  grant, an exclusion group, an expiring tuple and three temporal gates
  (`formerly_within` pinned to a trusted recorder, a calendar-day
  `count_within`, `count_distinct_within` keyed on `payload.input.approver`
  plus a separation-of-duties clause over the same events matching the
  approver against `$request.self`), with a payload schema on the approval
  action. Its README records the two modelling decisions the
  sentence forces: the NDA gate hangs on `review` (the question the portal
  asks, so it never touches the team), and the amount tier is a distinct
  action because gates are AND-only vetoes. 37 assertions, loaded by
  `tests/test.sh`.
- **Resolver regression shapes suite** (`tests/sql/tests_resolver_shapes.sql`,
  in `tests/test.sh`): the graph structures that broke OpenFGA's v2 check
  resolver during 2026 (#3244 two recursive TTUs sharing a tupleset relation,
  #3239 multi-branch recursion on one relation with a cycle and a diamond,
  #3195 independently-recursive relations under a union, #3224 deep nesting
  — resolves to the depth limit and fails closed with an error past it,
  #3145 contextual tuples mixed with stored ones inside a userset and an
  intersection in any order, #3284 wide union/intersection operand sets)
  pinned as fixed-answer fixtures, each asserted with the memo on, with the
  memo off, and against `list_objects` / `list_subjects` membership.

### Fixed

- **Unknown type or action on a decision is a 400, not a 500.** A check,
  batch or explain naming a subject/resource type or an action the store's
  model does not declare made the engine RAISE (`Unknown type: …`), which
  pgauthzd surfaced as an opaque `500 internal server error`. It is the
  caller's error and now answers `400` with the engine's message (found by
  Swagger UI's placeholder body, `"type": "string"`). Searches already
  answered an unknown entity with empty results (§8.3) and still do.
- **AuthZEN 1.0 conformance of the HTTP surface** — read against the OpenID
  conformance suite's PDP test plans, pgauthzd deviated in five places, all
  fixed with unit tests (`internal/api/authzen_conformance_test.go`):
  a batch request **without an `evaluations` array** (absent or empty) is now
  answered like the single Access Evaluation API, `{"decision": …}` (§7.1),
  instead of a 400; a batch item that **cannot be resolved** after the shared
  defaults are merged (no subject/action/resource, e.g. `{}`) is now a
  `{"decision": false}` entry with the batch answered 200 (§7.1.1,
  certification profile 3.4.1) instead of failing the whole request — a
  rejected subject override stays a 403; the evaluations semantic is read
  from **`options.evaluations_semantic`** (§7.1.2; the pre-1.0 top-level
  `semantic` still works) so an unknown value is a 400 rather than ignored,
  and a short-circuit is now visible on the wire — the response array ends
  with the decision that stopped processing (§7.1.2.1) instead of padding
  the rest with `false`; a request declaring a **non-JSON `Content-Type`**
  is refused with 415 on every `/access/v1` route (§10.1; `charset`
  parameters and `+json` suffixes accepted, a missing header still read as
  JSON); and a search naming an **unknown subject/resource type or action**
  returns an empty `results` array (§8.3) instead of a 500 from the engine's
  `Unknown type` RAISE (the check path keeps raising). Also: `page.limit` is
  accepted as the page size (§8.2; `size` still read), a 401 carries a
  `WWW-Authenticate: Bearer` challenge (§11.3), and search responses put
  `page` before `results` (§8.3 RECOMMENDED). Found by the first suite run: in
  trusted-PEP mode (`ALLOW_SUBJECT_OVERRIDE=true`) a **partial body subject**
  — `{"id": "alice"}` without a type, or a type without an id — was completed
  from the token's subject, so the engine was asked about a principal nobody
  named (`Unknown type: internal_user` → 500); it is now a 400. The token's
  subject still stands in for a body that names no subject at all.

- **pgauthzd no longer crash-loops on a fresh database.** The startup profile
  assertions (`decision-only` → read-only role, `full` → writer role) ran
  before the engine existed and died on `role "authz_writer" does not exist`,
  so after `./stop.sh --clean` a `./start.sh` (compose `--wait`) never
  returned and `init.sh` could not follow. pgauthzd now recognises "engine not
  installed yet" (missing role / table / schema) and waits, re-checking every
  2 s with one warning, then completes startup the moment `init.sh` or the
  migration job lands. Any other assertion failure — a writable role on a
  decision-only instance, a non-writer on a full one — is still fatal.
- **Hook example tests vs the actor ABI.** `examples/opa-hooks-filtering`'s
  Rego tests still asserted the pre-delegation actor shape; since the actor
  carries `on_behalf_of` (`{}` for a plain token) OPA's type checker refused
  the comparison and the OPA integration CI job was red. Expectations updated.
- **`init.sh` / `init-readonly.sh` / `tests/test.sh` refuse a pg_cel-created
  volume on a stock image.** Starting the stack without `--cel` on a data
  volume the pg_cel image created leaves the extension registered in
  `pg_extension` while the image has no `pg_cel.so`: the catalog says CEL is
  present, every evaluation fails with "could not access file pg_cel", and the
  CEL tests die mid-run. A shared preflight in `env.sh`
  (`check_pg_cel_consistency`) now fails fast with the two remedies (start
  with `--cel` again, or drop the volume). `tests/test.sh` likewise refuses a
  database without the engine (`role "authz_reader" does not exist` mid-run
  before) and points at `init.sh` / `bootstrap.sh`.
- **`pgauthzd doctor` agrees with the runtime on `ALLOW_OPEN_DIAGNOSTICS`.**
  Open diagnostics in production under the override warned on one check
  but failed on another, so a release the daemon starts and the chart
  renders could still fail `helm test`; preflight now warns (fatal under
  `--strict`), as the runtime does. `helm test` gains a second doctor pod
  wired like the OPA gateway when `authzen.opa.enabled` (`OPA_URL`, no
  database), so OPA's health is actually probed; the Helm `target` comment
  no longer claims there are no consistency tokens (freshness tokens exist).
  (External review.)
- **`list_objects` scanned every tuple partition of every store again**
  (re-found by the benchmark, 2026-09-29). The July fix constrained the
  three subject-rooted scans of the reachability walk with a tautology
  `object_type IN (SELECT id FROM authz.types WHERE store_id = …)` so the
  executor could prune down to the store's own partitions; on PostgreSQL 18.4
  the planner turned that subselect into a merge join over a Merge Append of
  all 130 partitions (40k buffers per call) and pruned nothing — rules-suite
  intersection `list_objects` 12 → 94 ms, drive grant-sparse 4.6 → 14 ms.
  The store's type ids are now materialised once into an array parameter
  (`object_type = ANY(…)`), which prunes at executor start: rules
  intersection 96.8 → 3.8 ms, drive grant-sparse 15.7 → 2.5 ms, github
  org-admin repos 269 → 121 ms, gates 19.1 → 13.0 ms (full rerun, same
  machine state). Checks and `list_subjects` (object-rooted) were never
  affected. See the BENCHMARKS addendum.

### Added

- **Condition-bound type restrictions** (migration 0015; OpenFGA
  `[user, user:* with cond]`). A restriction facet may now require a
  condition: `model_add_type_restriction(..., p_condition => 'cond')`. At
  write time a tuple of that shape must carry *that* condition (`requires a
  condition (one of: …)` / `does not allow condition "…"`); a facet without
  one stays open and accepts unconditioned tuples and any condition, so
  existing models behave exactly as before — to require a condition for a
  shape, define only conditioned facets for it. `describe_model` renders
  `with cond`, `type_restrictions_view` gains `condition`, `export_model`
  emits `condition` on bound facets only (checksum-neutral for existing
  registry versions), `apply_model` upserts conditions before facets and
  diffs the binding, and `delete_condition` refuses while a facet still
  requires the condition. **The OpenFGA import no longer drops `with
  <cond>` silently:** the facet is bound, and a condition the store lacks is
  created as a deny-all placeholder (`false`) and reported in `warnings` /
  `placeholder_conditions` until defined natively (found while comparing
  against OpenFGA 1.18.2's facet-binding fix, #3218). Signature note:
  `model_add_type_restriction` gained a trailing `p_condition text` parameter
  (roles.sql updated); the old overload is dropped on reload.

### Security

- **A verified token without a subject claim could assert any subject.** In
  self-subject mode (`ALLOW_SUBJECT_OVERRIDE=false`) the rule "no token
  subject, so the body is the only source" was meant for deployments without
  tokens, but it also applied to an authenticated service credential that
  carries no `sub`/`preferred_username` — the one credential that could then
  name anyone. Such a token now gets the same `403` as any other mismatch
  unless its client may assert (ADR 0014); the body-only fallback applies
  only when no token was verified at all. Found by probing ADR 0014's grant
  against the live engine.
- **The production profile refuses the audience override.** With
  `DEPLOYMENT_ENVIRONMENT=production`/`prod`, `ALLOW_MISSING_AUDIENCE=true`
  fails startup outright — even when every issuer currently pins an audience,
  so the override cannot lie dormant until an issuer entry loses its
  `audience` — and an audience-less issuer fails naming the issuer, with no
  override hint. `pgauthzd doctor --profile production` reports it as a fatal
  config finding; the Helm chart refuses to render `opa.allowMissingAudience`
  under `deploymentEnvironment=production`. The same rule applies to
  `ALLOW_UNBOUND_MULTI_ISSUER`: forbidden under the production label, and an
  unbound issuer among several fails with no override hint; `doctor --profile
  production` additionally warns about a single unbound issuer (legal, but a
  choice to make explicit with `REQUIRE_STORE_BINDING`). Open diagnostics keep
  their `ALLOW_OPEN_DIAGNOSTICS` override (a trusted internal network is a
  legitimate reason) and `ALLOW_SUBJECT_OVERRIDE` stays a warning (AuthZEN
  PDP deployments legitimately decide for arbitrary subjects); an unverified
  audience or an unbound issuer has no such reason. (External review.)
- **`docs/PRODUCTION.md` gains an adoption path**: the minimal first
  deployment (one domain, the default stack, the production profile from day
  one, a DB-role review) and a table mapping the adversarial cases external
  reviewers ask for to the suites that already cover them, with the gaps
  named. `docs/SECURITY-AUDIT.md` now states up front that the callback and
  Rego surfaces belong to the opt-in OPA overlay. (External reviews.)
- **pgauthzd requires an audience for every trusted issuer**
  `JWT_AUDIENCE` was optional and an empty value skipped the `aud` check, so a
  token the IdP minted for *any other API* — same keys, same subject and role
  claims — was accepted by pgauthzd (confused deputy). Startup now fails when
  the legacy single issuer or any `JWT_ISSUERS` entry has no `audience`,
  naming the issuer and the fix; `ALLOW_MISSING_AUDIENCE=true` is the
  deliberately alarming override (WARNING on every start); the Helm chart
  refuses to render an empty `opa.jwtAudience` unless
  `opa.allowMissingAudience` is set. **Upgrade note:** every shipped
  compose/Helm deployment already pins `authz-api`; the playground's Keycloak
  issuer entries now carry it too (the realm's audience mapper mints it). If
  you run an issuer without an audience, add one before upgrading.

### Changed

- **Docs: CIDR conditions and IPv4-mapped IPv6 addresses.** PostgreSQL keeps
  `::ffff:10.0.0.1` as an IPv6 value, so a plain `<<=` against an IPv4 CIDR is
  false for clients a dual-stack listener reports in mapped form. The README
  `ip_in_range` example and the demo model's `ip_allowlist` condition now
  normalise with `regexp_replace(host(ip), '^::ffff:', '')::inet`, and a note
  explains why (the OpenFGA `in_cidr` fix in 1.18.2 is the same issue).

## [0.17.0] - 2026-09-29

### Security

- **Exclusion terms failed open on missing condition context**
  (SECURITY-AUDIT F20, found while comparing against OpenFGA advisory
  GHSA-5278-rrxc-mgf7). `can_view = viewer BUT NOT banned` with a `banned`
  tuple whose condition needed a request key the caller did not supply
  evaluated the ban as *false* — "not banned" — and **allowed**, on every
  path (`check_access`, `check_access_detailed` reported `allow` while
  listing the missing key, `list_objects`/`list_subjects`, `explain_access`,
  `audit_check_access`). A missing key on a *granting* term was already
  fail-closed. **Fixed:** the missing-context assumption
  (`authz._assume_missing_ctx`) is now flipped for every negated term of an
  exclusion group — and again at each nesting level — so an unevaluable ban
  counts as a ban: `check_access` denies, `explain_access` shows a
  `condition_assumed` step (with `condition_name` / `condition_missing_keys`),
  `check_access_detailed` reports `conditional` with the keys that would
  settle it (its optimistic second pass inherits the flip), and the
  time-travel evaluator snapshots each condition's `required_context` so it
  applies the same rule as of `p_at`. Both per-check memos are keyed by the
  assumption polarity (`_check_memo_v2`). Regression tests cover the plain,
  wildcard-base, nested (`(base BUT NOT a) BUT NOT b`, the shape of OpenFGA
  GHSA-h7w8-xr72-cv4r) and time-travel cases.
## [0.16.0] - 2026-09-29

### Added

- **The action log** ([ADR 0012](docs/adr/0012-action-log.md), temporal gates
  phase 1): `authz.events` — a store-scoped, append-only record of what a
  principal *actually did*, reported by the application/PEP after the action
  ran (never by the check path; a PDP "allow" is not an action). SQL:
  `authz.record_event` / `record_events_jsonb` (atomic batches, `event_id`
  idempotency — re-deliveries are reported as duplicates, never inserted),
  `authz.list_events` (auditor inspection, `(occurred_at, seq)` keyset
  cursor), `ensure_event_partitions` / `drop_event_partitions_before`
  (monthly partitions + retention, sharing a generalized month-partition
  worker with the audit log). A new `authz_recorder` role (EXECUTE on the two
  record functions only; granted to `authz_writer`) lets an app feed the log
  without tuple-write rights. Actions must be **declared relations** of the
  store (the model is the action vocabulary — unknown actions fail loud);
  subjects are concrete principals; recording *about* a namespaced object type
  needs the namespace's `can_write` grant. `occurred_at` is caller-asserted
  but bounded (`authz.event_max_future_skew`, default 5s;
  `authz.event_max_backdate`, default 24h — set it to the queue's worst-case
  lag), `recorded_at`/`recorded_by` are server-set. Append-only by trigger;
  `delete_store` purges a store's events. pgauthzd: `POST /pgauthz/v1/events`
  (full profile; public listener gated by the new `RECORDER_ROLE` claim,
  default `authz_recorder` — `WRITER_ROLE` passes too; `recorded_by` follows
  `performed_by`'s attribution rules; engine content rejections map to 400,
  namespace refusals to 403), OpenAPI-documented, metric
  `pgauthzd_events_recorded_total{result}`. Phase 2 (model gates:
  `count_within`, `sum_within`, `formerly_within`, `count_distinct_within`
  evaluated after the graph) and phase 3 (`reserve_event` strict tier) are
  designed in the ADR; phase 2 ships below, phase 3 is not built.
- **Temporal gates** ([ADR 0012](docs/adr/0012-action-log.md) phase 2,
  [MODEL_DESIGN §17](docs/MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules)):
  history-dependent rules in the model, evaluated by engine code after the
  graph allows — `authz.add_gate` / `drop_gate` attach an `all_of` of
  `count_within` / `count_distinct_within` / `sum_within` / `formerly_within`
  clauses (sliding or calendar windows, containment `match` with
  `$request.*` references, `recorded_by` allowlists, inclusive `max`/`min`)
  to an `(object_type, relation)`; the spec is validated and normalized at
  write time (unknown keys rejected; a derived `required_context`). Gates
  apply on every decision path through one new seam, `authz._decide`
  (lint-enforced: entry points may no longer call `_check_access` directly),
  and only to the question asked — never to userset sub-resolution.
  Enumeration agrees with check (`list_objects` empty page on a gate deny,
  `list_subjects` / `list_actions` filter); `explain_access` emits
  `temporal_gate` steps (gate, clause, window, observed, threshold — never
  payloads) and `decision.reason = gate_denied`; `check_access_detailed`
  reports a missing `$request` key as `conditional` through the existing
  compositional pass; time-travel evaluates gate definitions as of `p_at`
  (`model_gates_audit` + snapshot) over events recorded by then;
  `export_model` gains `gates` (checksum ignores an empty array, so existing
  registry versions show no drift), `apply_model` / `plan_model_apply`
  propagate and diff them; `describe_model` renders gates as `#` comment
  lines. Migration 0011; engine files `gates.sql` (read) / `gates_admin.sql`
  (write); `delete_store` purges a store's gates.
- **The strict tier: `reserve_event`** ([ADR 0012](docs/adr/0012-action-log.md)
  phase 3): a gate bounds *recorded* actions, so two concurrent checks can
  both pass a cap; PEPs that need an exact bound call
  `authz.reserve_event` / `POST /pgauthz/v1/events/reserve` because they are
  about to act. Under an advisory lock per `(store, subject)` the engine takes
  the full decision (graph + gates) and records the `request` event in the
  same transaction; a refusal records a `denied` event (`p_record_denied`
  opts out). Returns `{allowed, seq, kind, reason: allowed|gate_denied|
  graph_denied, gates: [per-clause outcomes]}`. Proven by parallel-session
  tests in both the SQL suite (8 sessions, cap 3 → exactly 3) and the e2e
  suite (6 parallel HTTP reserves, cap 2 → exactly 2). Two fixes surfaced by
  those tests: gate windows and recorded timestamps now use
  `clock_timestamp()` (a statement's start time predates the lock wait and
  hid events recorded meanwhile), and `count_within` /
  `count_distinct_within` gained `plus` (like `sum_within`) so `max: 5,
  plus: 1` means at most 5 actions *including* the one being decided.
- **gdrive example: temporal gates on `doc.download`** — a new `download`
  relation (computed from `can_read`) with a daily quota and a per-document
  limit (object scope) over the action log; `demo.sql` §11 walks through
  recording, the `gate_denied` explain, enumeration and `reserve_event`;
  `tests.sql` covers the permission matrix and both gates and runs in
  `tests/test.sh`.
- **Gate readiness** (review #11): `authz.events_readiness(store)` — one row
  per store with gate counts by mode, the longest window, `history_since`
  (earliest retained partition or oldest event), `history_covers_gates` and
  `history_deficit`, events and worst occurred→recorded delay in the last
  hour, recorder identities in the last 24 h. Reader-callable. pgauthzd samples
  it into six per-store gauges (`pgauthzd_gates_total`,
  `pgauthzd_gate_history_covers`, `pgauthzd_gate_history_deficit_seconds`,
  `pgauthzd_events_last_recorded_age_seconds`,
  `pgauthzd_events_recording_delay_max_seconds`,
  `pgauthzd_events_recorders_24h`) and `pgauthzd doctor` warns for every
  gated store whose retained history does not yet cover its longest window.
- **Adversarial hook-URL regression tests** (review #11): the `hookurl`
  canonicaliser now has 20 reject cases (userinfo dressed as `host:port`,
  percent-encoded dots, control characters, broken ports and brackets,
  opaque/backslash and scheme-less forms, uppercase and Unicode/Cyrillic
  hosts) and 13 decoy-host cases asserting the host reported for the
  `allow_net` comparison is never a fragment/query/path/suffix decoy;
  `tests/hooks-invalid/` gains `bad_suffix`, `bad_percent`,
  `bad_portuserinfo`, `bad_redirect` (`enable_redirect: true`) and
  `bad_computed` (non-literal url) fixtures, all asserted rejected by
  `tests/test-hook-validator.sh` (CI).
- **Decision log: evidence mode and search lines** (review #11).
  `DECISION_LOG_REQUIRED=true` fails closed after a failed log write —
  `/readyz` 503 and every decision endpoint 503 until the sink accepts a line
  again (`pgauthzd_authz_denied_total{reason="decision_log_required"}`).
  `DECISION_LOG_SEARCHES=true` writes one line per AuthZEN search / native
  list call with the query dimensions and `result_count`, never the ids.
  Both need a sink and are off by default. Helm `decisionLog.required` /
  `decisionLog.searches`; compose passthrough.
- **`pgauthzd doctor`**: a preflight subcommand that loads the
  configuration as the daemon does and checks demo secrets, diagnostic gates,
  issuer store bindings, JWKS reachability, subject override, the cursor seal
  key, database connectivity and role capability for the profile, the
  callback listener and mTLS, OPA health, the decision-log sink and the
  metrics listener. `--profile production` evaluates the production profile
  regardless of `DEPLOYMENT_ENVIRONMENT`; `--json`; `--strict` exits 2 on
  warnings. The Helm chart runs it as `helm test` (`doctor.strict`).
- **Decision log in pgauthzd** ([ADR 0013](docs/adr/0013-decision-log.md)):
  `DECISION_LOG=off|stdout|stderr|file:<path>` writes one JSON line per
  decision — `evaluation(s)`, `check(-batch)`, `explain`, `events/reserve`,
  both listeners — with the resolved request, `decision`/`state`/`reason`,
  `missing_context`, gate outcomes (reserve), context **key names** (never
  values), caller (`actor`, `issuer`), `request_id` and latency.
  `DECISION_LOG_SAMPLE` samples allows only; `DECISION_LOG_DETAIL` runs the
  detailed evaluation for the log without changing responses.
  `pgauthzd_decision_log_lines_total{result}` counts logged / sampled-out /
  failed lines. Helm `decisionLog.*`; compose passes `DECISION_LOG*` through.
  Lines carry **provenance** (review #11): `pgauthzd_version`, the store's
  `model` (registry name/version + live checksum via `model_status`, cached
  per store for 30 s) and, for OPA-fronted decisions, `policy` (OPA version +
  bundle revisions, requested with `?provenance=true` only while the log is
  on).
- **`docs/AGENTIC-AUTHORIZATION.md`** — the guide to authorizing AI agents
  with pgauthz: the policy-aware loop over AuthZEN with detailed decisions as
  planner feedback, constraint-aware planning via the search API, task scope
  as stored or contextual tuples, sequencing and budgets as temporal gates
  (recorder = PEP, `reserve` for exact caps), delegation as data with
  evaluation-time attenuation and issuance preconditions, the control plane
  protected by absence, RAG authorize-before-retrieval (filter-then-search or
  search-then-batch-check), what to log and replay, and what ReBAC does not do.
- **Access-check preconditions for conditional writes.** `write_tuples_checked`
  (and `POST /pgauthz/v1/write-checked`, OPA `write_checked`) accept
  `{"match": "allowed" | "denied", user_type, user_id, relation, object_type,
  object_id, context?}` next to the stored-tuple `exists`/`absent` filters. The
  precondition is decided exactly as `check_access_with_context` would — graph,
  conditions with the given context, temporal gates — inside the same
  transaction and advisory locks, so "grant only if the granter may" (share on
  behalf, approvals, delegation that must not exceed the delegator) is one
  race-free call. A failed check is the usual `Write precondition failed`
  (`check_violation`, 400 over HTTP); malformed shapes are 22023.
- **`examples/models/agents/`** — authorization for AI agents (*Authorization
  in Action* ch. 18 / appendix C) on pgauthz: the policy-aware loop (every
  tool call a check, denial with a reason), task scope as an expiring or
  contextual tuple, constraint-aware planning with `list_actions` /
  `list_objects` in place of policy residuals (guidance ≡ enforcement is a
  test), sequencing and partner reputation as temporal gates over the action
  log, a control plane with no agent path (the grant cannot even be written),
  delegation as data with attenuation at evaluation time: grants go to an
  agent's `reach` userset (`[agent] or reach from delegate`, enforced by the
  type restriction), so a delegate reads only what its delegator still holds
  and what it was explicitly given, revoking the delegator revokes the
  subtree, chains cut at any link, plus an issuance precondition. 41 checks,
  loaded by `test.sh`; the README lists what ReBAC cannot express (per-type
  gates, multi-party approval as events, subject-side traversal).
- **Gate cross-check accepts nested `match` objects.** `match: {"output":
  {"promise_kept": false}}` is containment-equivalent to the dotted form and
  is now validated against the payload schema by its leaf paths instead of
  being rejected as an undeclared top-level key.
- **`examples/models/aia-acme/`** — the ACME "Customer Collaboration" example from
  the book *Authorization in Action* (Cedar, chapter 9 + appendix A) as a
  pgauthz model with the book's entities as seed data and its four
  `is-authorized` evaluations plus the chapter-9 patterns as 36 checks. Shows
  the Cedar → ReBAC translation: attributes become relations (`owner`,
  `manager`, readers teams), `classification == "Legal"` becomes a reified
  `classification` object with one `reviewer` tuple, `delegatable` and the
  §9.7.2 overrides become flag tuples in intersection/exclusion groups, and
  the global unmanaged-device `forbid` becomes a conditional object-wildcard
  tuple that every employee path must intersect — fail-closed on missing
  context, where Cedar would skip the erroring policy; the book's "stricter
  outside business hours" is a second such tuple (`business_hours`) that only
  non-owner edits must satisfy. Loaded by `test.sh`.
- **Playground: AuthZEN console is store-scoped and says who you are.** Calls
  follow the store selected in the header via the AuthZEN §9.2 tenant path form
  (`?store=` on the BFF proxy → `/stores/<store>/access/v1/…`); the request
  template defaults the subject to the token's (`subject_type` + username) and
  a hint above the request explains that pgauthzd-opa evaluates as you, warns
  before a 403 when the fields name another subject, and flags stores that lack
  the token's subject type (gdrive).
- **Playground: act as the PEP.** The Access Explorer gains an action bar:
  **Record response** and **Reserve** send the current query to pgauthzd-full's
  native `/pgauthz/v1/events` and `/events/reserve` with the user's Keycloak
  token (the real PEP path, `RECORDER_ROLE`-gated there; `recorded_by` is the
  token subject), then re-run explain so the gate nodes show the moved
  counters — download a gdrive doc three times, watch the fourth turn into
  `gate_denied`. **Reset events…** purges an allowlisted demo store's action
  log (`authz.purge_events` with `p_force`) behind a two-step confirmation, a
  Keycloak role (`playground_admin`) and a dedicated connection role that may
  execute nothing but `purge_events` (`authz_playground_reset`,
  `db/security/roles.sql`). Keycloak terraform grants the demo users
  `authz_recorder` (documented as a demo concession — it is a PEP credential)
  and alice `playground_admin`; `compose-playground.yml` adds the Keycloak
  issuer to pgauthzd-full. New BFF env: `EVENTS_URL`,
  `PLAYGROUND_RECORDER_ROLE`, `PLAYGROUND_WRITER_ROLE`, `ENGINE_RESET_DSN`,
  `PLAYGROUND_RESET_ROLE`, `PLAYGROUND_RESET_STORES`.
- **Playground: temporal gates in the Access Explorer.** Gate clauses
  (`rule_type: temporal_gate`) render as their own teal nodes hanging off the
  requested access — gate, clause, observed vs threshold in the window — instead
  of masquerading as granting tuples or failed lookups; a gate-vetoed DENY shows
  the vetoing clause; shadow clauses are neutral (○) in the graph and the text
  tree; the Result header shows `decision.reason` (e.g. `gate_denied`); the
  model view styles the engine's `# gate` / `# payload schema` lines as
  comments; legends and README updated. `compose-playground.yml` sets
  `EXPLAIN_REQUIRED_ROLE` on pgauthzd-opa so the overlay stays valid under
  `DEPLOYMENT_ENVIRONMENT=production`.
- **Per-action payload schemas** (migration 0014, external review): a relation
  may declare the payload shape its events must have —
  `authz.model_set_payload_schema(store, relation, schema)` with `required` /
  `optional` dotted paths and JSON types, per-kind additions (`kinds.response`
  …) and an optional closed shape (`additional: false`). `record_event`
  enforces it (400 over HTTP, batches atomic), `add_gate` refuses clauses that
  read undeclared paths or sum a non-number, the registry exports and
  propagates it (emitted only when set, so existing checksums do not move),
  `describe_model` renders it. Relations without a schema are unchanged.
- **Action-log metrics in pgauthzd** (ADR 0010): `pgauthzd_events_rejected_total{reason}`
  (invalid_request | forbidden | error), `pgauthzd_event_lag_seconds{kind}`
  (record time − `occurred_at` per accepted event), `pgauthzd_reserve_decisions_total{result}`,
  and `pgauthzd_gate_clauses_total{path,reason,shadow}` — temporal-gate clause
  outcomes observed on the explain and reserve paths, including what a
  shadow-mode gate would have denied.
- **`examples/events/` — action-log ingestion reference** (external review):
  a compose overlay with Redis Streams, a consumer (consumer group,
  at-least-once, batches, dead-letter stream for content rejections with the
  engine's reason, backoff for transport errors, pending-entry reclaim,
  Prometheus metrics incl. ingestion lag) with SQL and HTTP sinks, a demo
  producer, and a README stating the message contract and the outbox rule. A
  dedicated `authz_recorder_svc` login role (inherits only `authz_recorder`)
  is the consumer's least-privilege identity.
- **Shadow mode for temporal gates** — a gate spec may set `"mode": "shadow"`:
  it is evaluated exactly as enforcement would (same windows, same cost) but
  a failing clause never denies. The outcome is reported instead: the
  `explain_access` step keeps its real reason/observed/threshold and carries
  `"shadow": true` (summary icon `○`), `decision.reason` stays the graph's,
  `check_access_detailed` excludes shadow gates from `missing_context`,
  `reserve_event` allows and returns the shadowed clause outcome, and every
  would-be denial writes a structured `gate_shadow …` line to the PostgreSQL
  server log (replica-safe). The `authz.gates_mode` GUC (`enforce` default |
  `shadow` | `off`) shadows or switches off every gate database-wide;
  `describe_model` renders `(shadow)` / `(off)`. `"mode": "off"` keeps a gate
  defined and versioned but skips it entirely. Introduce a gate on a live
  relation, watch, then drop the key to enforce.
- **Retention guard for temporal gates** (external review): `drop_event_partitions_before`
  and `purge_events` now refuse a cutoff that falls inside a live gate window
  (`check_violation`, naming the gate; `p_force => true` overrides), because a
  dropped or purged range under-counts and can only relax a cap. New
  reader-callable `authz.gate_windows(store)` / `authz.max_gate_window(store)`
  report each clause's effective window (calendar buckets rounded up: day
  25 h, week 7 d 1 h, month 31 d, year 366 d) for readiness runbooks.
- **Per-store event retention** — `authz.purge_events(store, before)` deletes
  one store's events older than a timestamp (row-wise, under the sanctioned
  maintenance window, admin-only, returns the count) — the per-tenant tool
  next to the fleet-wide `drop_event_partitions_before` partition drop.
- **Per-recorder action allowlists** (migration 0013): `authz.recorder_actions`
  maps a DB role to the actions it may record in a store, managed with
  `grant_recorder_actions` / `revoke_recorder_actions` (admin). Namespace
  precedent: a role with no rows is unrestricted; once rows exist for a role
  the caller is a member of, only the listed actions may be recorded
  (`Permission denied` → 403; batches fail atomically). Enforced in
  `record_event`, so `reserve_event` and the HTTP endpoints inherit it;
  excluded from `export_model`; purged by `delete_store`.
- **Object-scoped gate clauses** — a clause may set `"scope": "object"` to
  count only the principal's events on the object being checked ("3 edits
  of *this* document per hour"; separation of duties: `count_within{action:
  submit, scope: object, max: 0}` on `approve` denies whoever submitted
  *that* object). Subject scope stays the default. `list_objects` keeps its
  once-per-subject fast path for subject-only gate lists and evaluates per
  candidate when any clause is object-scoped; explain steps and
  `reserve_event` outcomes carry `scope`.
- **`bench/suites/gates.sql`** — a benchmark suite for the action log and
  temporal gates (gated vs ungated checks over 0 / 100 / 10k events in the
  window, containment matching, traced and two-pass paths, gated enumeration,
  recording, `reserve_event`, `list_events`); results and the `_decide` seam
  A/B against the previous engine in [BENCHMARKS.md](docs/BENCHMARKS.md).

### Security

- **Production profile for the diagnostic surfaces** (external review,
  SECURITY-AUDIT F19). `DEPLOYMENT_ENVIRONMENT=production` (or `prod`) now
  makes pgauthzd refuse to start unless `SEARCH_REQUIRED_ROLE` and
  `EXPLAIN_REQUIRED_ROLE` are set and `WATCH_REQUIRED_ROLE` is not `"*"`
  (reverse search enumerates the graph, explain reveals model structure and
  traces, watch streams every change); `ALLOW_OPEN_DIAGNOSTICS=true` is the
  deliberately alarming override. The Helm chart gains `deploymentEnvironment`
  and a `diagnostics` block (`searchRequiredRole` / `explainRequiredRole` /
  `watchRequiredRole` / `allowOpenInProduction`) applied to every pgauthzd
  instance, refuses to render an open production profile, and ships
  `values-production.yaml`. Runtime defaults outside the production label are
  unchanged.

### Security (documentation)

- **Temporal gates positioning** (external review): the ADR, MODEL_DESIGN §17
  and README now state that gates are centrally managed, history-dependent
  veto rules over trusted recorded actions — not a workflow engine, not a
  substitute for reliable PEP recording, Dogwood-inspired but not
  Dogwood-compatible — and every shipped gate carries the
  permission-not-outcome rule of thumb.
- **`authz_recorder` / `RECORDER_ROLE` is documented as a PEP-only
  credential** (external review): recorded events drive temporal gates, so a
  recorder can move a gate; the ADR 0012 trust model, PRODUCTION checklist and
  role table, SECURITY-AUDIT hardening checklist, README, DEVELOPMENT,
  pgauthzd README and `roles.sql` now state it explicitly, with containment
  (action allowlists, `recorded_by` pins, `purge_events`, `list_events` by
  `recorded_by`).

### Fixed

- **Playground overlay kept the demo issuer's roles on the writer.** The
  `pgauthzd-full` override in `compose-playground.yml` set `JWT_ROLES_CLAIM`
  to the Keycloak paths only, so demo-issuer tokens (`tests/test-authzen.sh`)
  lost their writer/recorder roles (403 on writes and events) when the
  playground overlay was up; `roles` is now listed first.
- **Search evidence is complete under required mode** (review #13): with
  `DECISION_LOG_REQUIRED` and `DECISION_LOG_SEARCHES` both set, searches are
  refused (503) while the sink is down, like decisions — no answer without the
  line that was asked for. With search lines off, searches are counted only
  and never refused. No third switch.
- **`DECISION_LOG_REQUIRED` could latch unhealthy until a restart** (review
  #12): decisions were refused before they reached the logger, so nothing
  ever retried a failed sink. The guard and `/readyz` now probe the sink with
  a marker line (`endpoint: decision_log_probe`, `state: sink_recovered`) at
  most once per second and resume when it accepts. Required mode now rejects
  `DECISION_LOG_SAMPLE < 1` (sampled evidence is not complete evidence), and
  the model-provenance read on a cache miss runs under the request context
  with a 100 ms budget instead of an unbounded background context.
- **OPA `explain` now forwards `input.context`** (new `pgauthz.explain_access_with_context`).
  Explaining through OPA — the playground's "As me" mode — evaluated conditions
  and temporal-gate clauses that read `$request.*` without the request context,
  so they always reported missing context while the `allow` decision (which
  forwards it) did not. Covered in `tests/test-opa.sh`.

- **Hook validator: `http.send` destinations are canonicalised with OPA's own
  parser** (external review, SECURITY-AUDIT F17). `validate-hooks.sh`
  extracted the destination host with `sed` before comparing it to
  `allow_net`; it now calls `pgauthzd/cmd/hookurl` (Go `net/url`, the parser
  OPA applies `allow_net` with) and additionally requires https (loopback
  excepted; `--allow-plain-http` / `HOOK_ALLOW_PLAIN_HTTP=1` opts a trusted
  private network in), rejects userinfo, opaque URLs and non-canonical hosts.
  `--allow-http` validation now needs the Go toolchain.
- **Hook validator: IPv6-literal destinations skipped the allowlist check**
  (SECURITY-AUDIT F18, found while fixing the above). Under the script's
  `nullglob`, an unquoted URL loop treated `https://[2001:db8::1]/…` as a
  glob matching nothing and never checked it; URLs are now iterated by line.
  `tests/test-hook-validator.sh` pins both fixes with negative fixtures.
- **`list_events` scanned the whole log for a subject page** (23 ms / 191k
  buffers on a 220k-row log for 100 rows): the `(param IS NULL OR …)` filter
  shape could not become an index condition under a generic plan, and no
  index ordered a subject's events by time. `list_events` now builds its
  predicates from the filters supplied, and migration 0012 adds
  `idx_events_subject_list`; a subject page is 0.26 ms. `p_subject_id` now
  requires `p_subject_type` (the indexed pair).

## [0.15.0] - 2026-07-07

### Security (review #10 — pre-production batch)
- **Watch/changefeed is role-gated and DENY BY DEFAULT on the public
  listener** (`WATCH_REQUIRED_ROLE`; the feed exposes authorization topology
  and the daemon's DB role holds `authz_auditor` to serve it — HTTP now
  decides who may ask; `"*"` opens explicitly; the trusted callback listener
  is unaffected). Native explain gains the analogous `EXPLAIN_REQUIRED_ROLE`
  (empty = open, back-compat). The dev/test stack sets
  `WATCH_REQUIRED_ROLE=authz_auditor`; the e2e suite proves ordinary 403 /
  auditor 200.
- **Multi-issuer is fail-closed**: with more than one trusted issuer, an
  issuer without stores (or, with role derivation, db_roles) bindings now
  FAILS STARTUP instead of warning past a cross-tenant hole;
  `ALLOW_UNBOUND_MULTI_ISSUER=true` is the deliberately alarming override.
  Single-issuer behavior unchanged.
- **Malformed configuration is fatal**: invalid ints/durations/booleans in
  env vars fail startup with a message naming every offender —
  `REQUIRE_STORE_BINDING=treu` can no longer silently mean `false`. Absent
  still means the documented default.
- **Sealed-cursor hardening**: AAD fields are length-prefix encoded
  (delimiter characters in ids can no longer alias field boundaries; property
  test included), the caller-context digest is the full SHA-256, and a
  cursor-sealing failure now surfaces as a 5xx instead of silently ending
  pagination as if complete.
- **OPA responses are bounded** (`OPA_MAX_RESPONSE_BYTES`, default 10 MiB):
  oversized bodies → `policy_evaluation_failed`; error-body text is truncated
  before logging.
- **CI: a required OPA integration job** (`opa-test`) runs the full stack
  with `PGAUTHZ_OPA=1`; `tests/test-opa.sh` fails (instead of skipping) when
  OPA is absent under `PGAUTHZ_CI=1`, and all four hook example suites +
  validator tiers run in CI.


## [0.14.0] - 2026-07-07

### Added

- **OPA policy hooks** ([ADR 0011](docs/adr/0011-opa-policy-hooks.md)):
  user-supplied **veto rules** riding along the standard decision pipeline —
  no allowlist entries, no pgauthzd config, no platform-file edits. Mount
  `.rego` files declaring packages under `authz.hooks.v1.<name>` (compose: one
  volume line onto the shipped `/policies/hooks` mountpoint; Helm:
  `authzen.opa.extraPoliciesConfigMap`); a hook may define
  `deny contains msg` (vetoes `allow`/`allow_detailed`/`evaluations` — a veto
  denies the whole batch, so `/evaluations` is not a bypass) and
  `deny_write contains msg` (vetoes every write operation,
  `error: denied_by_policy_hook`). Hooks can only **narrow** — the ReBAC graph
  answer still has to pass — and are fully attributed: denials carry the hook's
  package name, and `allow_detailed` reports `hooks_consulted` +
  `hook_denials`, which pgauthzd returns in the AuthZEN response context under
  `X-PGAuthz-Detail` (discarded otherwise). A deployment with no mounts is
  bit-identical to before. Reference hooks + the contract test suite live in
  `examples/opa-hooks/` (`opa test` against the real platform policies, wired
  into `test-opa.sh`); validated live against a real OPA with hooks mounted. Hooks are evaluated against a versioned, normalized input ABI
  (`pgauthz.hooks/v1` — tokens/transport invisible), declared under
  `authz.hooks.v1.<name>`, and gated by `scripts/validate-hooks.sh`
  (namespace/duplicate/platform-package/`http.send` checks — veto-only is a
  contract, not a sandbox); denials are structured `{hook, code, message}`,
  `evaluations` returns a `403 denied_by_policy_hook` on veto (not a fake
  all-false batch), and `permitted_actions` is filtered per action. **Store-scoped hooks:** the namespace
  is two-tier — `authz.hooks.v1.global.<name>` (every store) and
  `authz.hooks.v1.stores.<store>.<name>` (only that store, keyed by the
  request's store so tenants are isolated); Helm gains
  `opa.storePoliciesConfigMaps`. `/evaluations` now evaluates hooks **per item**
  (a veto rejects the batch with `evaluation_index`, not a fake all-false); a
  runtime hook error **fails the request closed** (`strict-builtin-errors` →
  `policy_evaluation_failed`, 5xx, never a phantom decision); hooks read a
  **server-derived `evaluated_at`** (time/env gates can't trust caller context);
  and `scripts/validate-hooks.sh` (`--global` / `--store <s>`) is a required
  release gate (wired into `pre-release.sh`). Fourth review round:
  **tenant isolation is now validator-ENFORCED** (a hook may reference only
  `input`, pure builtins, and its own package — no cross-package/dynamic
  `data[…]`), a server-derived **`deployment.environment`** joins the ABI for
  environment gates, hook-veto **`denials` are disclosed only under
  `X-PGAuthz-Detail`** (batch 403 + write veto), denials are ordered
  `(tier,store,hook,code,message)` with `denials_truncated`/`denial_count`, the
  Helm chart runs a deploy-time `opa check` initContainer over mounted hooks
  (store volume names sanitized), and OPA's isolated Rego eval time is recorded
  as `pgauthzd_opa_rego_eval_duration_seconds` (`OPA_EVAL_METRICS`, default on). Fifth review round:
  hook builtin **purity is pinned by a capability allowlist**
  (`opa/hooks-v1-capabilities.json`, reproducible ABI) enforced by the
  validator AND a Helm `opa check --capabilities` **initContainer**; the ADR
  now names two trust tiers (global = platform, store = delegated tenant) and
  requires **signed immutable bundles** for delegated store hooks (a mutable
  ConfigMap under `--watch` is not an isolation boundary); a **per-hook denial
  cap** (16) bounds a misbehaving hook; `strict-builtin-errors` fail-closed is
  documented + tested on every query path; and `DEPLOYMENT_ENVIRONMENT` is
  format-validated. Sixth review round:
  `http.send` is **forbidden for store hooks** (a global-only, platform-governed
  option); the validator now also rejects `data`/`input` **imports** (an
  `import data.other as x` alias would evade the body-only isolation check) —
  all checks operate on the parsed AST; the signed-bundle topology is pinned to
  a **single platform-controlled, platform-signed bundle** (a tenant can't sign
  an artifact production OPA accepts); `denial_count` is defined as the total
  **after** per-hook caps, with `denials_dropped` + `hook_output_truncated` for
  honesty; and the readiness signals are documented as non-overlapping
  (deploy-time validation ≠ deep readiness ≠ activation revision ≠ runtime
  metrics). Seventh review round:
  **enumeration refusal ships in v1, secure by default** — with any hook
  loaded, `accessible_objects`/`accessible_subjects` are refused
  (`403 enumeration_refused_with_hooks`) because hooks don’t filter
  graph-derived supersets; `ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true`
  (OPA env / `opa.allowUnfilteredEnumerationWithHooks` in Helm) opts into
  superset semantics; an unset `DEPLOYMENT_ENVIRONMENT` now forwards the
  sentinel **`unknown`** (an empty string fails *open* on equality gates —
  env gates must be allowlist-style); bundle signing pinned to exact validated
  bytes with unsigned/unknown-key/local-fallback rejection; per-hook denial
  cap documented as an output bound, not a compute bound. Eighth review round:
  enumeration refusal is **applicable-hook-scoped** (global + requested store —
  tenant B's hooks never disable tenant A's enumeration; now regression-tested);
  Rego **reserved words are blacklisted as store names** (migration 0009 —
  keyword package segments parse inconsistently across Rego tooling); Helm
  store-hook volume names get a **hash suffix**
  (`store-hooks-<40-char sanitized>-<8-char sha256>`) fixing case-collisions
  and the 63-char limit; bundle signing described correctly (signature covers
  the file set + per-file hashes, not tarball bytes) with explicit `.manifest`
  roots required; and the `"unknown"` environment sentinel is now **enforced**:
  a platform guard denial (`deployment_environment_unknown`) fires on decisions
  and writes when hooks are loaded without `DEPLOYMENT_ENVIRONMENT`
  (`ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true` opts out). Ninth review round
  (reviewer: final-quality): bundle **root narrowed to `authz/hooks/v1/stores`**
  (the wider root would erase separately mounted global hooks on activation),
  full `.manifest` example with `revision` + ABI metadata; **http.send
  destinations capability-enforced** via `opa/hooks-v1-http-capabilities.json`
  (pure set + `http.send` + deny-all `allow_net` template; runtime-enforced by
  OPA's capabilities file, `HOOK_HTTP_CAPABILITIES` for the validator); hook
  `<name>` segments follow the store-name rules (reserved words + ≤63,
  validator-enforced); the amendment history moved to an ADR appendix; and the
  hooks README gained a "see exactly what your hook receives" dev section
  (query `_decision_hook_input`/`_write_hook_input` directly). Tenth review round
  (final): the `allow_net` claim corrected — OPA capabilities are
  **build/check-time** validation (`opa run` takes no capabilities file), so
  the http.send model is three independent controls: build-time capabilities +
  AST validation (the validator now also **rejects non-static http.send
  destinations** — literal object + literal string `url` required), the signed
  immutable bundle, and independent runtime egress enforcement
  (NetworkPolicy/egress proxy; a blocked call fails closed via
  `strict-builtin-errors`). Eleventh review round (merge verdict): the
  config-injection mechanism is explicit (flags reach Rego only via the
  platform config module — `opa.runtime().env`, excluded from hook
  capabilities; data-injected where process env doesn't exist), and the
  validator now **statically enforces the `allow_net` host allowlist** on the
  forced-literal `http.send` destinations and **rejects
  `enable_redirect: true`** (OPA redirects verified off by default). Twelfth
  review round (merge): the `http.send` static contract is complete —
  `raise_error` must stay `true` (`false` bypasses `strict-builtin-errors`
  fail-closed via a `status_code: 0` response), `tls_insecure_skip_verify`
  must stay `false`, `timeout` must be a static non-zero bound; computed
  values rejected. Thirteenth review round (merge): global `http.send` hooks
  must ship via the signed immutable artifact path in production (mutable
  ConfigMap/`--watch` = dev or network-free globals only); platform config
  flags documented + regression-tested as fail-closed parses (exact `"true"`
  enables, anything else disables). Fourteenth review round: the nonexistent
  `max_response_bytes` field removed from the ADR (OPA verifiably rejects it;
  response size must be bounded by the endpoint or an egress proxy), and the
  `http.send` contract tightened to **read-only lookup** — literal `GET`/`HEAD`
  only, no `body`/`raw_body`, `max_retry_attempts` 0/absent, no `Host` header
  (all validator-enforced, mutation-tested). Fifteenth review round: HTTP
  4xx/5xx responses identified as a **fail-open gap** (they are successful
  `http.send` executions — `strict-builtin-errors` never fires), so network
  hooks must deny outside a declared success-status set;
  `examples/opa-hooks-http/` ships the reference hook + 10 contract tests
  (404/429/500/503, malformed/missing bodies, aggregator veto), wired into
  `pre-release.sh`; signed global-hook topology pinned (combined
  `authz/hooks/v1` bundle XOR separate `authz/hooks/v1/global` bundle). Sixteenth review round (ADR frozen): the HTTP status/schema contract is
  explicitly a **governance** requirement for platform-trusted network hooks
  (review + contract tests; not statically checkable), with the
  platform-HTTP-helper model documented as deferred v2 hardening;
  `platform_policy_compatibility` enforcement named (publish pipeline +
  activation monitor).
- **Hook-filtered enumeration + verified actor roles (ADR 0011 follow-up).**
  `HOOK_FILTERED_ENUMERATION=true` (Helm: `opa.hookFilteredEnumeration`)
  evaluates the applicable decision hooks per enumeration candidate and drops
  denied ids — listings then match per-object checks, replacing the blanket
  refusal. Guardrails: `HOOK_FILTER_MAX_CANDIDATES` (1000) refuses over-cap
  queries outright (`enumeration_refused_too_many_candidates`, typed 403);
  refused while the environment guard is active; paginated results switch to
  a raw-keyset protocol (`{hook_filtered, ids, has_more, cursor}`) so pages
  that filter below the limit never end pagination early (short/empty pages
  with a next_token are normal). And the hook ABI now carries the verified
  caller as `actor{id, roles}` on decisions AND writes (roles =
  `JWT_ROLES_CLAIM` aggregation, e.g. Keycloak realm + client roles) —
  role-based exemptions (`not "auditor" in input.actor.roles`) are
  expressible and stay veto-only. `examples/opa-hooks-filtering/` ships the
  reference hook + 14 contract tests, wired into `pre-release.sh`. Review
  hardening: strict cap parsing (digits-only, 1..100000; malformed ⇒ refusal,
  never a silent default), **sealed filtered-page cursors** (AES-GCM via
  `CURSOR_SEAL_KEY` — the raw-keyset cursor may name a hook-hidden id; failed
  unseal = 400), the per-page consistency claim qualified, `http.send` request
  fields moved to an explicit allowlist (cross-query cache controls
  forbidden), and the flat role namespace documented (use globally unambiguous
  exemption role names). Precedence pinned: with BOTH mode flags set, filtering
  wins, and a configured-but-inoperable filtering state (env guard, malformed
  cap) refuses — never degrades to the superset. `CURSOR_SEAL_KEY` is a
  comma-separated keyring (first mints, all accept) so key rotation keeps
  in-flight paginations alive. Sealed cursors are additionally **bound to
  their query context** (AEAD AAD over operation/store/subject/action/
  resource — cross-context replay rejected); the per-process fallback is
  declared dev-only (startup warning without a shared key on OPA-fronted
  instances); the cap tri-state pinned (missing → 1000, valid → value,
  malformed → refusal); cache-field prohibition promoted into the normative
  ADR `http.send` contract; `actor{id,roles}` additivity clarified (actor was
  always an object). Cursor binding completed: the AAD includes `actor.id` and a
  canonical caller-context hash (actor A's cursor is rejected for actor B);
  the Helm chart refuses to render `opa.hookFilteredEnumeration` without
  `authzen.opa.cursorSealKey`; the cap documented as per-request scope. Crypto
  invariants (freeze round): fresh random nonces per cursor, strict
  `CURSOR_SEAL_KEY` parsing (empty segments = startup error), an explicit
  envelope format version (unknown = fail closed), and 32-byte plaintext
  padding (token length reveals only a coarse bucket). Role provenance,
  two mechanisms: the hook `actor` carries **verbatim claim copies** under
  `actor.claims.<name>` (`HOOK_ACTOR_CLAIMS`, default
  `realm_access,resource_access` — client_ids stay map keys, so URI-shaped
  SAML entity IDs need no separator convention; the recommended way to write
  client-scoped hook logic; the actor top level stays reserved for derived
  identity), and
  `JWT_ROLES_SOURCE_PREFIX=true` (opt-in) emits provenance-prefixed FLAT
  roles — `realm::<role>` / `<client_id>::<role>` — for consumers of the flat
  set like the writer gate (update `WRITER_ROLE` to the prefixed form when
  enabling); flat aggregation remains the default. Custom selections
  (`HOOK_ACTOR_CLAIMS=...`, Helm: `opa.hookActorClaims`) replace the default —
  top-level claim names taken whole (URI-named OIDC claims work), missing
  claims absent. **Platform hook library** `authz.hooks.lib.v1`: shared,
  versioned helper functions — the single validator-allowlisted namespace
  hooks may import (platform-owned, functions-only, ships with the platform
  policy; a call to a nonexistent function fails validation). First module:
  `keycloak.has_realm_role` / `keycloak.has_client_role` +
  `realm_roles`/`client_roles` accessors, all fail-closed on absent claims;
  the `claims_guard` example uses it. Operators add their OWN shared helpers
  under the reserved `authz.hooks.lib.v1.ext.<name>` subtree
  (`validate-hooks.sh --lib`: functions-only, always pure — no `http.send`
  escape, since a shared lib would hand network access to network-free store
  hooks; Helm: `opa.extraLibsConfigMap`; validator: `HOOK_EXTRA_LIBS=<dir>`
  when validating hooks that call them; `examples/opa-hooks-lib/`). Onboarding pass: the dev compose stack now sets
  `DEPLOYMENT_ENVIRONMENT=dev` (mounting a first hook no longer trips the
  fail-closed environment guard; production still must set its own value —
  Helm: `authzen.opa.deploymentEnvironment`), `scripts/new-hook.sh` scaffolds
  a correctly-packaged hook skeleton, and the hooks README leads with a
  5-minute quickstart (surprising secure defaults called out up front)), plus
  `scripts/make-token.sh` (demo ES256 JWT minting, extracted from
  test-opa.sh) so the quickstart is runnable end-to-end — which also fixed
  the quickstart to target the OPA-fronted instance (8091, where hooks run)
  instead of the direct reader (8090, which never consults hooks). Dev flag: OPA
  console decision logging is now switchable — `OPA_DECISION_LOGS_CONSOLE=true`
  (compose) / `opa.decisionLogsConsole=true` (Helm), OFF by default (the log
  includes full inputs, i.e. forwarded bearer JWTs — dev only). Post-review hardening: **store
  names are restricted** to a Rego-safe identifier (`^[a-zA-Z_][a-zA-Z0-9_]*$`,
  ≤63 chars — migration 0008 + `create_store`), so a store is its hook package
  segment directly (no scope-key hashing); `evaluated_at` is **captured once
  by pgauthzd** and forwarded (every batch item/hook sees one timestamp); the
  write ABI names the authenticated **`actor`** distinct from the tuple's
  subject; and denial `code`/count are bounded.

- **HTTP availability hardening** (review #9). Go's zero timeouts are
  *unlimited*, so a black-holed dependency or a slow client could previously
  hang requests, probes, or startup:
  - `OPA_REQUEST_TIMEOUT` (default `10s`) bounds every OPA HTTP call; the
    startup health probe runs under its own deadline.
  - Every listener now sets `ReadHeaderTimeout` (`HTTP_READ_HEADER_TIMEOUT`,
    default `5s`, slowloris hardening) and `IdleTimeout` (`HTTP_IDLE_TIMEOUT`,
    default `60s`) — deliberately **no** `WriteTimeout`, so long-running
    search/explain/watch responses are never killed mid-write.
  - `HTTP_MAX_BODY_BYTES` (default 10 MiB, `0` disables) caps request bodies
    via `http.MaxBytesReader` on both the public and callback listeners.
  - `/readyz`'s backend ping is bounded server-side (5s), so a black-holed
    database fails the probe promptly instead of hanging it.
- **Strict deep-readiness mode** (review #9). `OPA_DEEP_READINESS_REQUIRED`
  (default `false`): when set, a policy set without the `callback_healthy`
  rule **fails** readiness instead of silently degrading to the shallow
  OPA-`/health`-only check. Either way the active mode is now observable as
  `pgauthzd_opa_readiness_mode{mode="deep|shallow"}`.

### Fixed

- **Whitespace-only audit actors rejected** (review #9). `performed_by` is
  trimmed before the non-empty check (`"   "` no longer passes) and capped at
  256 characters, so the immutable audit trail can't carry blank or junk
  attribution.

## [0.13.0] - 2026-07-07

### Security

- **`/readyz` no longer echoes backend errors** (review #8). The probe
  endpoints are unauthenticated, and a failing backend's error text can carry
  internal hostnames or DSN fragments; callers now get a generic
  `{"status":503,"message":"unhealthy"}` while the cause goes to the
  structured server log. Test pins that DSN/hostname strings never reach the
  body.
- **No empty audit attribution on the callback listener** (review #8,
  F16 follow-up). The service-token callback listener has no JWT subject to
  fall back to, so an omitted `performed_by` would have stored an *empty*
  actor in the immutable audit trail; it is now rejected (`400`). The
  sanctioned caller is unaffected — the OPA policy always asserts
  `authn.subject_id`.

### Added

- **OPA-mode readiness is end-to-end** (review #8). An OPA-fronted instance's
  `/readyz` previously proved only that OPA's own `/health` answered — not
  that a decision could succeed. The pgauthz client policy now exposes
  `data.authz.pgauthz.callback_healthy` (allowlisted in `system_authz.rego`,
  a bare boolean; reuses the callback mTLS options, 2s timeout, never
  cached), and `opabackend.Healthz` queries it after OPA `/health` — so
  "ready" means **OPA policy eval → native callback → PostgreSQL** is usable.
  A policy set without the rule (custom Rego) degrades to the shallow check.
  Validated against a real OPA (rule true with the callback up, false with it
  down) and asserted in `tests/test-opa.sh`.

### Changed

- **Store names are restricted to `^[a-zA-Z_][a-zA-Z0-9_]*$` (≤63 chars)**
  (migration 0008). Enforced by a table `CHECK` and `create_store`. Required so
  a store name can be the Rego package segment for store-scoped OPA policy
  hooks (ADR 0011); every existing store name already complies.

- **GitHub Actions bumped off the deprecated Node 20 runtime**: `checkout@v7`,
  `setup-go@v6`, `cache@v6`, `docker/setup-buildx-action@v4`,
  `docker/build-push-action@v7`.

## [0.12.0] - 2026-07-07

### Security

- **Audit actor spoofing closed on the public listener** (audit finding F16,
  found by external review #7). The native write bodies' `performed_by` field
  previously overrode the authenticated JWT subject on **both** listeners, so
  any authorized writer could stamp another user into the immutable audit
  trail. Now the trust contexts are split: on the **public** listener the JWT
  subject is authoritative — a differing body value is rejected (`403`) unless
  `ALLOW_SUBJECT_OVERRIDE` is enabled (the existing trusted-PEP switch, now
  governing both the decision-path subject and audit attribution); the
  internal callback listener is unchanged (the body value is the trusted OPA
  upstream's assertion of the subject it authenticated — the field's purpose).

### Added

- **`/livez` and `/readyz` probes** (review #7). `/livez` is process liveness
  with **no dependency checks**; `/readyz` pings the backend (the old
  `/healthz` behavior, which remains as a deprecated alias). The Helm chart
  now points `livenessProbe` at `/livez` and `readinessProbe` at `/readyz`,
  so a PostgreSQL outage takes instances out of rotation instead of making
  Kubernetes restart healthy pgauthzd processes in a loop.

### Changed

- **OpenAPI wording: the served document is *topology-accurate*, not
  capability-pruned.** It lists exactly the routes the instance registers — a
  `decision-only` instance keeps the write operations (they respond with a
  documented `403`; pruning them would claim a route doesn't exist while it
  demonstrably answers). The `serviceToken` security scheme now states
  explicitly that it is rejected (`401`) on the public listener.

## [0.11.0] - 2026-07-07

### Changed

- **`wrong_epoch` recovery guidance is now reconcile-first** (review #6). The
  structured freshness 409 (and ADR 0009 / README) previously advised
  "re-mint via a new write" — misleading after a **lossy** promotion, where the
  original write may be gone and an unrelated write's token proves nothing
  about it. The guidance is now: re-read and reconcile the intended
  authorization state on the current primary, reapply the change idempotently
  if missing, then use that write's token (matters most for
  revokes/offboarding, as the promotion integration test demonstrates).
- **Token ordering documented as timeline-local.** "A later token covers all
  earlier writes" holds only within one WAL timeline; a failover
  (`wrong_epoch`) voids the ordering contract until the client reconciles
  (PRODUCTION.md PEP guidance + ADR 0009).
- **The served OpenAPI document is instance-accurate.** An OPA-fronted
  instance (whose public listener does not register the native routes) now
  serves a copy with the native paths omitted; the source file keeps the full
  contract, and native operations carry a machine-readable
  `x-pgauthz-availability` extension (`listeners`, `public_listener:
  not-when-opa-fronted`, `profile: full` on writes). New `OPENAPI_ENABLED`
  (default `true`) disables the endpoints entirely.

### Fixed

- **Mint-status tri-state edge:** freshness keys configured but a write
  backend that cannot mint now reports `X-PGAuthz-Revision-Status:
  unavailable` (enabled-but-broken, counted + logged) instead of `disabled`
  (feature off). Defensive-only — a `full` instance's direct pgx backend
  always mints.

## [0.10.0] - 2026-07-07

### Added

- **Verdict-specific freshness errors** ([ADR 0009](docs/adr/0009-freshness-tokens.md)).
  An unsatisfiable `at_least_as_fresh` read now returns a structured `409` —
  `{error: "freshness_constraint_unsatisfied", verdict, primary_consulted,
  message}` (plus the existing `X-PGAuthz-Stale` header) — with per-verdict
  guidance: `stale`/`unknown` → retry the primary; `wrong_epoch` → **not
  retryable** (a failover happened; re-mint via a new write or drop the
  constraint). `primary_consulted: true` says the transparent fallback already
  re-checked the primary, so "retry the primary" is no longer offered as advice.
- **Mint failures are surfaced, not silent.** A write that commits but cannot
  mint its freshness token now reports `X-PGAuthz-Revision-Status: unavailable`
  (vs `issued` / `disabled`), increments
  `pgauthzd_freshness_mint_failures_total`, and logs the error;
  `pgauthzd_freshness_tokens_minted_total` counts successes.
- **Duplicate derived key ids are a startup error.** Two `FRESHNESS_TOKEN_KEYS`
  secrets deriving the same kid (a ~2⁻³¹-per-pair sha256-prefix accident) would
  silently shadow one key at verification; `config.Load` now rejects the keyring
  deterministically at startup.
- **Real promotion integration tests** (`tests/test-scaling.sh`). The scaling
  suite now ends with an actual `pg_promote` of the streaming standby, proving
  the ADR 0009 timeline guard against a live failover: a **lossy** promotion
  (the standby is network-disconnected before a write, then promoted and its
  new timeline advanced past the token's LSN — the exact scenario where a naive
  LSN-only check false-allows, F12) and a **clean** promotion (caught-up token)
  both yield `wrong_epoch`, asserted before any `CHECKPOINT` so a lagging
  control-file timeline source would fail the test; a token re-minted on the
  promoted node carries the new epoch and is immediately `fresh`. Also asserts
  the primary-side F12 behavior directly (cross-timeline token → `wrong_epoch`
  on a primary).

### Removed

- **`gateway/` (the nginx "OPA edge proxy" template).** It existed for the
  legacy topology that exposed OPA's decision API directly to clients — a
  topology gone since the pgauthzd consolidation ([ADR 0008](docs/adr/0008-opa-is-opt-in.md)):
  OPA is now internal-only (pgauthzd is its sole caller), edge TLS belongs on
  any ordinary proxy/ingress in front of pgauthzd, the internal callback hop
  has built-in mTLS (`INTERNAL_TLS_*`), and OPA's management surface is gated
  by `system_authz.rego` + network isolation. Keeping the template suggested
  OPA was meant to be externally exposed — exactly the mistake the current
  architecture removes. PRODUCTION.md's "Edge TLS / mTLS" section now
  documents the per-hop guidance; the template remains in git history.

### Added

- **OpenAPI description for pgauthzd, contract-tested against the code.** The
  full HTTP surface — native `/pgauthz/v1` and AuthZEN `/access/v1` (incl. the
  store-scoped variants), every `X-PGAuthz-*` request/response header, the
  error envelopes (standard + the structured freshness `409`), and both
  security schemes (public-listener JWT vs the internal callback's service
  token) — lives in `pgauthzd/internal/api/openapi.yaml`, is embedded into the
  binary, and is served unauthenticated at `GET /pgauthz/v1/openapi.json`
  (and `.yaml`) with `info.version` stamped to the build version. AuthZEN
  shapes cross-checked against the official openid/authzen JSON schemas
  (`properties` bags accepted; the detail `context` documented as a vendor
  extension). Drift is impossible to ship: `openapi_test.go` enforces
  bidirectional route coverage (documented ⊆ registered ⊆ documented) and
  validates real handler responses against the schemas — wired into `go test`,
  CI, and `scripts/pre-release.sh` (which now also runs the pgauthzd unit
  tests).

### Added (docs / examples)

- **README "A complete example first"** — the full lifecycle in one
  copy-pasteable psql session at the top of the API section (store → model →
  `describe_model` → `write_tuple` → `check_access` → `explain_access` →
  `list_objects`/`list_subjects` → revoke), with real outputs; validated live.
  The same example ships as loadable files under
  **`examples/models/helloworld/`** (`model.sql`, `seed.sql`, `demo.sql`) —
  the smallest useful model, now the first row of the Example Models table.

### Changed

- **Bad-token 400s are opaque by design.** The freshness guard returns one fixed
  message for every bad-token cause (malformed / unknown-or-retired kid /
  signature mismatch) so a probe can't distinguish "key rotated away" from
  "forged"; the specific reason is now logged server-side instead.
- Documented the **cooperative-consistency contract** (ADR 0009 + PRODUCTION.md):
  freshness tokens upgrade only the reads that present them — deployment-level
  revocation visibility remains `remote_apply`'s job, and a PEP fronting end
  users must own consistency selection (retain the newest token, never let
  clients weaken the mode, cache-bypass after revokes).

## [0.9.0] - 2026-07-06

### Added

- **Freshness-token key rotation** ([ADR 0009](docs/adr/0009-freshness-tokens.md)).
  The signing config is now an ordered keyring, `FRESHNESS_TOKEN_KEYS`
  (comma-separated): the **first** key mints, **every** key verifies, enabling a
  zero-downtime three-phase rotation (`"old,new"` → `"new,old"` → `"new"`;
  runbook in [PRODUCTION.md](docs/PRODUCTION.md)). Tokens embed a key id derived
  from the secret (`base64url(sha256(secret)[:4])`, MAC-covered), so verification
  picks the right key during the overlap; an unknown/retired kid fails with the
  same opaque error as a forgery (fail closed). New per-kid drain metric
  `pgauthzd_freshness_key_verifications_total{kid}` shows when the old key is
  safe to drop. `FRESHNESS_TOKEN_KEY` remains as a single-key alias (setting
  both is a startup error). **Breaking:** the token wire format now carries the
  kid — tokens minted by v0.8.0 fail with `400` after the upgrade (clients
  re-mint on their next write); closes audit finding F13.

### Fixed

- **Freshness tokens: a promoted primary no longer accepts stale tokens**
  ([ADR 0009](docs/adr/0009-freshness-tokens.md)). `assert_fresh` previously
  returned `fresh` unconditionally on any primary, so after a **lossy failover** a
  promoted primary (new timeline) would confirm a token minted on the old
  timeline whose write it never received — a stale-allow. It now derives its own
  timeline + WAL position (`pg_walfile_name(pg_current_wal_insert_lsn())`) and
  applies the same `wrong_epoch`/`stale` checks as a standby, so a cross-timeline
  token is rejected everywhere. **Breaking:** a primary can now return
  `wrong_epoch`/`stale` for a token instead of always `fresh`.
- **Transparent primary fallback re-validates on the primary.** It previously
  marked the request for primary routing without re-checking; it now re-runs
  `assert_fresh` against the primary pool and only serves from it on a `fresh`
  verdict (else `409`), closing the same lossy-failover hole on the fallback path.
- **`at_least_as_fresh` without a token is now `400`** (was a silent downgrade to
  a low-latency read — a fail-open on client misconfiguration).

## [0.8.0] - 2026-07-06

### Added

- **Prometheus metrics** ([ADR 0010](docs/adr/0010-metrics-observability.md), Slice 1)
  on an opt-in, non-public listener (`METRICS_LISTEN_ADDR`): HTTP RED
  (`pgauthzd_http_requests_total` / `_duration_seconds` by templated route),
  freshness verdict/fallback counters (`pgauthzd_freshness_verdicts_total{verdict}`,
  `pgauthzd_freshness_fallback_total` — lagging-replica + failover signals),
  `pgauthzd_build_info`, and pgx pool stats (`pgauthzd_db_pool_connections{pool,state}`),
  plus the default Go/process collectors. Demo wiring: `./start.sh --metrics`
  brings up a Prometheus + Grafana that scrape it (compose-metrics.yml, UIs on
  :9095/:9096); Helm exposes it via `metrics.enabled` + a `ServiceMonitor`
  (`metrics.serviceMonitor.enabled`). **Slice 2** adds per-store decisions
  (`pgauthzd_check_decisions_total{store,decision,api}`), search
  (`pgauthzd_search_requests_total` / `_result_size`), auth signals
  (`pgauthzd_jwt_validation_failures_total`, `pgauthzd_authz_denied_total`), and
  backend latency (`pgauthzd_db_query_duration_seconds{op,pool}`,
  `pgauthzd_opa_request_duration_seconds`). **Slice 3** adds periodically-sampled
  engine/tenant gauges — `pgauthzd_store_tuples{store}` (top-N, capped by
  `METRICS_MAX_STORES`) + `pgauthzd_stores_total` (`METRICS_SAMPLE_INTERVAL_SECONDS`).
- **Freshness tokens for read-your-writes across replicas** ([ADR 0009](docs/adr/0009-freshness-tokens.md)).
  An opt-in, HMAC-signed LSN-watermark token (`{epoch=timeline, lsn}`): a write
  mints one (`X-PGAuthz-Revision` header + `"revision"` body), and a read can
  present it with `X-PGAuthz-Consistency: at_least_as_fresh` to demand
  read-your-writes. A replica that hasn't caught up answers `409` +
  `X-PGAuthz-Stale` so the caller retries against the primary; the epoch guards
  against a lossy-failover false-allow (the timeline is read from the WAL
  position, never the lagging control file). Engine primitives
  `authz.freshness_token()` / `authz.assert_fresh()`; enabled by
  `FRESHNESS_TOKEN_KEY` (same value on writer + readers; empty = off, fail
  closed). No PostgreSQL 19 dependency. Paginated searches bind the freshness
  floor into the `next_token` cursor, so a scan can't mix pre/post-revoke states
  across pages. Optional **transparent primary fallback** (`FRESHNESS_PRIMARY_URL`
  on a decision-only reader): a not-fresh-enough read is re-run on the primary
  (marked `X-PGAuthz-Served-By: primary`) instead of returning 409.
- **Proprietary HTTP headers are namespaced `X-PGAuthz-*`** (was the generic,
  collision-prone `X-Authz-*`): `X-PGAuthz-Role` / `-Detail` / `-Consistency` /
  `-Revision` / `-Stale` / `-Store` (the last also fixes a casing slip).

### The pgauthzd front door — PostgREST removed, OPA now opt-in

A large architectural consolidation: **pgauthzd** (one Go daemon) is now the
external front door for reads *and* writes, PostgREST is gone entirely, and OPA
is demoted to an **opt-in** internal policy sidecar — the default stack is
OPA-free, answering directly from PostgreSQL.

### Changed

- **pgauthzd is the external front door.** Clients speak AuthZEN 1.0
  (`/access/v1/*`) or the native `/pgauthz/v1/*` API to pgauthzd, which validates
  the JWT (multi-issuer via `JWT_ISSUERS`; the `iss` claim selects the validator).
  OPA is an internal sidecar — the *only* caller of OPA is pgauthzd, which
  forwards the verified token; OPA's Rego calls **back** into pgauthzd's native
  `/pgauthz/v1` callback for graph data (service-token authenticated, optional
  mTLS). The old "OPA is the single front door" topology is gone.
- **pgauthzd fronts and authorizes writes.** The `full`/writer instance exposes
  `POST /pgauthz/v1/{write,delete,delete-user,write-checked}` and gates them on a
  `WRITER_ROLE` claim (default `authz_writer`; `JWT_ROLES_CLAIM` defaults to
  `roles`) — it authorizes writes itself instead of relying on an OPA-fronted
  writer. Writes apply natively via pgx under a fixed writer DB role.
- **Profiles are DB capability only: `decision-only` | `full`.** The former
  `compat-opa` profile is replaced by an orthogonal **`OPA_URL`** flag: set it and
  pgauthzd consults OPA for the AuthZEN surface; the native surface stays direct
  pgx and is exposed on the public listener only when *not* fronting OPA (so the
  raw API can't sidestep OPA policy). A DB-less instance with `OPA_URL` set is a
  pure OPA-AuthZEN gateway.
- **One daemon, one image.** The separate `authzen-direct` / `authzen-opa`
  services are collapsed into pgauthzd profiles; reader/writer separation is a
  deployment topology (a `decision-only` reader instance + a `full` writer
  instance), not a per-process split.
- **OPA is opt-in; the default stack is OPA-free**
  ([ADR 0008](docs/adr/0008-opa-is-opt-in.md)). pgauthzd answers
  `/access/v1` and `/pgauthz/v1` directly from PostgreSQL (with conditions for
  ABAC); OPA + the OPA-fronted pgauthzd gateway are an opt-in overlay:
  `./start.sh --opa` (or `PGAUTHZ_OPA=1`) for compose, `authzen.opa.enabled`
  (default `false`) for Helm. The `--keycloak` / `--playground` overlays imply it.
  Fronting OPA stays the orthogonal `OPA_URL` flag; this only flips the DEFAULT
  from on to off. One fewer moving part, one JWT validation, lower latency by
  default; policy-as-code Rego remains a first-class opt-in.
- Helm: the ingress front door routes to pgauthzd (not OPA); OPA's NetworkPolicy
  is tightened to gateway-only. The `examples/keycloak` demo now routes through
  pgauthzd (AuthZEN) via the gateway instead of hitting OPA's data API directly.
- Docs: the inline ADRs in `docs/ARCHITECTURE.md` §9 are consolidated into the
  `docs/adr/` log (ADRs 0002–0008); §9 is now an index into that log.

### Removed

- **PostgREST — removed from the project entirely.** Every read and write path,
  and every deployment (compose, scaling, Helm), uses the native pgauthzd
  callback. There is no PostgREST fallback.
- **PostgREST role/hook residue:** the `authz_authenticator` LOGIN role, the
  `api_anon` role (folded into `authz_reader` — there is no anonymous tier; every
  request is JWT-validated), and the `authz._pre_request` / `_pre_request_reader`
  db-pre-request hooks. pgauthzd now validates the per-app DB role (member of
  `authz_reader`/`authz_writer`, not admin) and applies `SET LOCAL ROLE` +
  the consistency mode itself in Go.

### Added

- **Native `/pgauthz/v1` API:** `check`, `check-batch`, `list-objects`,
  `list-subjects`, `list-actions`, `explain`, `watch`, and the write endpoints —
  plus their `/stores/{store}/…` tenant variants.
- **OPA callback listener** (service-token auth, optional mTLS `RequireAndVerify`
  client cert) — the native surface an OPA sidecar calls back into, kept off the
  public listener.
- **Multi-issuer JWT validation** (`JWT_ISSUERS` JSON array) with per-issuer
  store and DB-role bindings.
- `authz_watcher` — a dedicated read-only login role (granted `authz_auditor`)
  for the `examples/watch` changefeed consumer, replacing the bootstrap superuser.

### Fixed

- **Per-write consistency now fails closed.** An unknown/misspelled consistency
  mode is rejected (400) instead of being silently ignored (which downgraded the
  durability guarantee) — restoring the behavior the removed SQL hook enforced.
- `pgauthzd-opa` now carries `restart: unless-stopped`, so on a fresh database it
  crash-loops until roles are ready (like the reader/writer) instead of exiting
  and breaking `up --wait`.

## [0.7.3] - 2026-07-05

### Fixed

- **`check_access_detailed` `conditional` is now compositional** (review #4
  P0). Previously `state` aggregated missing condition-context keys across the
  whole trace, so an intersection/exclusion with a structural deny the context
  could not repair (e.g. `A AND B` with A conditional-on-missing and B a hard
  deny) was mis-reported as `conditional`. It now confirms `conditional` with
  a second **optimistic** evaluation (conditions failing solely for missing
  context treated as passing): a decision is `conditional` only when supplying
  the missing context could actually flip DENY→ALLOW, else `deny`. `allow`
  still fires only on the real boolean, so no authorization was ever wrong.
  8 truth-table tests across OR/AND/EXCLUSION.

## [0.7.2] - 2026-07-05

### Fixed

- **Live expiry now judged per statement, not per transaction** (migration
  0007; review 2026-07-05). The expiry RLS policy compared `expires_at`
  against `now()`, which in PostgreSQL is transaction-start time — so a
  long-lived direct-SQL transaction could keep seeing a tuple after its
  wall-clock expiry (the request-per-transaction front door was unaffected).
  It now uses `statement_timestamp()`, so every check/search re-evaluates
  expiry at its own start, matching the documented "stops granting the moment
  expiry passes". Regression-tested.

### Documentation

- **Re-granting a tuple without `expires_at` clears its expiry** (makes it
  permanent) — documented as a footgun for generic sync/upsert code, which
  should pass `expires_at` explicitly or read-modify-write.

## [0.7.1] - 2026-07-05

### Security

- **Fixed a fail-open in tuple expiry (SECURITY-AUDIT F11), migration 0006.**
  The v0.7 expiry enforcement hid expired tuples with a row-level-security
  policy whose write-side escape was a **caller-settable GUC**
  (`authz.tuples_include_expired`). Because expiry is read inside the
  `SECURITY DEFINER` functions app roles invoke, a **direct `authz_reader`
  SQL connection could set that GUC and make expired grants grant again**
  (not reachable through the OPA/PostgREST front door, which exposes RPC
  only — a direct-SQL trust-tier hole). The escape is now a dedicated
  `BYPASSRLS` role (`authz_rls_bypass`) that owns the `SECURITY DEFINER`
  helper functions performing the two operations that must see expired rows
  (reactivating upsert, cleanup); the SELECT policy has no GUC escape and is
  unbypassable by any caller value. `EXECUTE` on the helpers is granted only
  to `authz_owner` and no LOGIN role can reach the bypass role. Found and
  fixed in the v0.7 security-audit delta; verified closed (the reproduction
  now denies).

### Added

- **Signed release tags (SSH).** `release.sh` now creates signed tags
  (`git tag -s`) and refuses to tag unsigned, printing the one-time SSH
  signing setup if missing; `RELEASING.md` documents the flow, the GitHub
  "Signing Key" upload for the Verified badge, and local `git tag -v`
  verification via an allowed-signers file. `.github/CODEOWNERS` marks the
  security-sensitive paths (engine roles/migrations, OPA policies + Helm
  copy, AuthZEN token/issuer code, CI/release machinery) as review-gated —
  the supply-chain hardening "first slice".

## [0.7.0] - 2026-07-05

### Fixed

- **`list_objects` scanned every tuple partition of every store** — a
  partition-count scaling defect present since the beginning, uncovered by
  the expiry benchmark A/B. The reachability expansion's subject-rooted
  scans left the partition key (`object_type`) unconstrained, so each
  recursion iteration touched all tuple partitions in the database (168
  from just 3 stores in the dev DB; linear in tenant count for
  store-per-tenant deployments). The scans now carry a tautological
  `object_type IN (this store's types)` predicate that the executor turns
  into startup-time partition pruning: sparse `list_objects` 133.9 → 4.6
  ms/op (raw expansion 94.6 → 0.8 ms) on the 168-partition database.
  Check paths are object-rooted and were never affected.

### Added

- **Native relationship expiration: `tuples.expires_at`** (migration `0005`; review #3 priority 4). Grants can carry a server-time expiry:
  the moment it passes, the tuple stops granting on **every** check and
  search path. Enforcement is structural — row-level security on
  `authz.tuples` (FORCEd onto the engine's definer functions) hides expired
  rows from every read, so a missed filter in any of the ~37 tuple-scan
  sites is unrepresentable; caller-supplied context has no influence.
  Write paths: `write_tuple(p_expires_at)` and `"expires_at"` in the jsonb
  batch/`write_tuples_checked` tuples (flows through the OPA write API);
  re-granting an expired tuple reactivates it; a batch re-grant makes it
  permanent; granting an already-expired tuple is rejected up front.
  `cleanup_expired_tuples(store, grace)` garbage-collects (audited);
  offboarding removes expired grants too. Time-travel judges expiry **as of
  the asked time** — a grant that expired at T still shows allowed for
  p_at < T, even after cleanup deleted the row. Conditions remain the tool
  for complex time windows; this is the simple case without CEL/SQL.
  Measured overhead of the RLS enforcement: ~+10% on checks, up to ~+50% on
  large `list_*` scans (see BENCHMARKS.md addendum). 16 SQL tests.

- **Rich decision results (opt-in): which KIND of "no"** (review #3
  priority 3). New engine function `authz.check_access_detailed` classifies
  a decision — `state: allow | deny | conditional` — plus the missing
  condition-context keys (namespaced `request.*`/`stored.*`), the conditions
  that lacked input, the explain reason, and the registry model version for
  managed stores. `conditional` distinguishes "denied because required
  context was not supplied" (recoverable: supply it / step up and re-check)
  from a genuine deny; the boolean APIs keep collapsing it to deny (fail
  closed, unchanged). Exposed as the OPA rule `authz/allow_detailed`
  (allowlisted in system_authz; uncached by design) and on both AuthZEN
  services via the `X-PGAuthz-Detail` request header, which populates the
  AuthZEN response `context` field. Runs the explain machinery — a
  per-decision opt-in, not a hot-path default. 10 SQL tests + e2e on OPA and
  both AuthZEN services; demo walkthrough section 9g.

- **`pgauthzctl` — model-as-code toolchain** (new top-level Go CLI; review #3's
  top item). Author models as **verbatim OpenFGA DSL** (`.fga`) in git,
  parsed with the official `openfga/language` transformer — no new DSL —
  and piped into the existing `import_openfga_model`. Verbs:
  `model import | publish | plan | diff | apply | export | status |
  versions | rollout | test`. `publish` turns a git file into the next
  immutable registry version; `plan` exits non-zero on blockers
  (CI-gateable); `apply --plan-first` refuses blocked rollouts;
  `model test` runs YAML fixtures (a **superset of OpenFGA's store-test
  format** — existing OpenFGA tests port directly) against a hermetic
  ephemeral store, with pgauthz extensions (condition `context`,
  `contextual_tuples`, golden `explain` reason paths) and `--junit` output.
  DSL `condition` blocks are parsed but not imported (OpenFGA CEL and
  pgauthz CEL vocabularies differ) — pgauthzctl prints a
  `create_condition_cel` scaffold per condition instead. Own Go module
  (keeps the ANTLR dependency tree out of the services); integration suite
  `tests/test-pgauthzctl.sh` wired into `test-all.sh`, CI, and
  `pre-release.sh`.

- **`plan_model_apply`: dry-run for model rollouts** (review #2 priority 2).
  Read-only report of what `apply_model` would do to a store: per-section
  changes (types add/update, relations add/remove, rules, type restrictions,
  conditions add/update/remove), the exact blockers that would make the apply
  raise (`extra_type`, `relation_referenced_by_tuples` with the tuple count,
  `cel_evaluator_missing`), `no_op`/`can_apply` verdicts, the store's current
  managed state, and **rollback feasibility** — whether the currently
  recorded version could be re-applied afterwards (a version that adds types
  cannot be rolled back, since types are never removed automatically). Diffs
  the same canonical name-based exports the checksums hash, so the plan
  agrees with `model_status` by construction; reader-callable so pipelines
  can gate rollouts without admin credentials. 7 new SQL tests; usage +
  example in MODEL_DESIGN §16.

- **Per-request decision-cache bypass.** Read requests may set
  `"no_cache": true` on the OPA input to force a 0-second cache TTL for that
  decision — the escape hatch for revocation-sensitive checks that must see a
  just-committed change inside the normal TTL window. AuthZEN callers request
  the same with the standard **`Cache-Control: no-cache`** header, which
  `authzen-opa` maps to `input.no_cache` (headers cannot reach OPA policy
  input, so the body field is the mechanism at the OPA hop; `authzen-direct`
  has no decision cache and is fresh by construction). Applies to every
  cached read call (check, batch, list, explain); e2e-tested on both hops (a
  revoke is visible through the bypass immediately after a cached allow).
  Not a DoS vector: unauthenticated callers never reach PostgreSQL, and
  cache-busting by varying the object id was already free. PRODUCTION.md now
  states the end-to-end staleness bound explicitly: replication staleness
  (zero on the synchronous set with `remote_apply`) + the decision-cache TTL.

### Documentation

- **Model rollout guidance** (MODEL_DESIGN §16 + `apply_model` fleet-variant
  comment): the fleet apply is one atomic transaction — right for small
  fleets, wrong for hundreds of stores (use an external orchestrator with
  bounded batches, a pinned version, and `model_rollout_status` as the
  progress/retry view); and "rolling back is a forward operation" — immutable
  versions re-apply under the same guard rails, so plan model evolution as
  expand → migrate → contract.

## [0.6.0] - 2026-07-05

### Added

- **Per-app namespace isolation on READS over OPA (slice B).** The OPA read
  path now gets the same database-enforced per-application isolation the
  write path has had: OPA forwards the caller's per-app DB role as
  `X-PGAuthz-Role` on every PostgREST read call, and the reader's new
  `PGRST_DB_PRE_REQUEST` hook (`authz._pre_request_reader`) validates it —
  member of `authz_reader`, **not** admin-capable, fail closed — and
  `SET LOCAL ROLE`s to it, so the engine's read-side namespace checks key on
  the calling application instead of the fixed `api_anon`. Role source
  mirrors subject trust: verified token claim (`authn.db_role`) in token
  mode, `input.db_role` only in trusted-PEP mode
  (`REQUIRE_TOKEN_FOR_READS=false`). `authzen-opa` derives the role like
  `authzen-direct` (claim → issuer map → global map, validated against the
  issuer's `db_roles` binding) and forwards it as `input.db_role` — both
  AuthZEN services now provide equivalent read-side isolation. The role
  header is part of OPA's `http.send` cache key, so cached read decisions
  are partitioned per role. No role configured → reads stay `api_anon`
  (unchanged). E2E-tested in test-opa.sh (namespaced type: denied without
  role / allowed with grant / admin rejected) + 7 SQL hook tests.

- **Model registry: named, versioned models shared across stores** (migration
  `0004` + `db/engine/model_registry.sql`). Multi-tenant pattern: one store
  per tenant (tuples isolated by construction), one common model rolled out
  per store. `authz.export_model` renders a store's live model as a
  canonical, name-based JSONB definition (types incl. namespace/labels,
  relations, rules, type restrictions, conditions — not tuples, not
  namespace role grants); `authz.publish_model` snapshots it into the
  registry as the next immutable version of a named model (republishing an
  unchanged model is a no-op); `authz.apply_model` makes a target store's
  live model match a registry version — exact diff via the existing model
  API (validation + `models_audit` time-travel stay engaged), self-verified
  by checksum after apply, with strict guards: types are never removed
  automatically, and a stale relation still referenced by tuples aborts the
  apply instead of silently orphaning them. A fleet variant applies one
  resolved version to a list of stores. Drift detection: `authz.model_status`
  (per store) and `authz.model_rollout_status` (per model) compare the live
  model's checksum against the applied registry version — hash-partition
  layout (`hash_modulus`) is excluded from checksums, so per-tenant partition
  sizing does not read as drift. `authz.list_model_versions` lists the
  registry.

- **AuthZEN: issuer binding enforcement flags.** `REQUIRE_STORE_BINDING=true`
  refuses startup unless every trusted issuer carries a `stores` binding;
  `REQUIRE_DB_ROLE_BINDING=true` does the same for `db_roles`/`client_db_roles`
  when per-app role derivation is configured — an unbound issuer means
  unrestricted store/role access, so multi-tenant deployments should set both.
  With the flags off (default, legacy-compatible), the services now log a
  startup **warning** per unbound issuer whenever several issuers are trusted.

### Changed

- **`WRITER_DB_ROLE_CLAIM` renamed to `DB_ROLE_CLAIM`** (OPA service env,
  Helm value `opa.dbRoleClaim`): the same claim now drives the role switch
  on both the write and the read path.
- **AuthZEN (direct): per-app DB role validation results are now cached with a
  TTL** (`DB_ROLE_CACHE_TTL_SECONDS`, default 60; `0` = re-validate every
  request) instead of indefinitely — dropping a role or revoking its
  `authz_reader` membership takes effect within the window, not at the next
  service restart.
- `scripts/pre-release.sh` now fails if the Helm chart's OPA policy copy
  (`deploy/helm/pgauthz/files/opa/policies`) drifts from `opa/policies`
  (it had drifted silently); the copy is re-synced in this change.

### Documentation

- **Security self-audit refreshed** (`docs/SECURITY-AUDIT.md`) for the v0.6
  surface: AuthZEN multi-issuer routing + store/role bindings, the two new
  role-switch hooks (writer + reader), token forwarding and the trusted-PEP
  `input.db_role` path, per-role OPA cache partitioning, and the model registry
  as a cross-store propagation path; playground reviewed as a dev-only tool.
  No High/Critical code findings; four new Info/Low findings (F7–F10) accepted
  with operational controls, plus expanded operational-risk and hardening
  checklists.
- **AuthZEN isolation parity documented** (authzen/README.md + PRODUCTION.md
  checklist): the interim callout that `authzen-opa` lacked database-enforced
  per-application namespace isolation was superseded *within this release* by
  slice B (see Added) — the docs now describe the symmetric setup: both
  services enforce read-side isolation, with `DB_ROLE_CLAIM` configured on the
  OPA service for the token-mode role source.

## [0.5.0] - 2026-07-04

### Added

- **AuthZEN: store selection via URL path.** Every `access/v1` endpoint (and
  the discovery document) is also served store-scoped under
  `/stores/{store}/…` (OpenFGA-style), so each pgauthz store presents as its
  own AuthZEN PDP. Resolution order: path → `X-PGAuthz-Store` header →
  `DEFAULT_STORE`.
- **AuthZEN: per-app namespace enforcement (authzen-direct).** The direct
  backend can derive a per-app DB role from the verified token —
  `DB_ROLE_CLAIM` (dot-path, mirrors the writer's `WRITER_DB_ROLE_CLAIM`) or
  the `CLIENT_DB_ROLES` map keyed by client id (`azp`) — and assume it per
  request (`SET LOCAL ROLE` in a transaction, validated: member of
  `authz_reader`, not admin-capable, fail closed). pgauthz namespace
  restrictions then apply per calling application on the read path.
  authzen-opa (OPA→PostgREST reads) is documented follow-up work.
  **Per-issuer role binding:** `JWT_ISSUERS` entries gain `db_roles`
  (anchored regex patterns) restricting which roles that issuer's tokens may
  yield — without it, any trusted issuer could claim another tenant's role;
  violations are rejected (403), never downgraded. Plus issuer-scoped
  `client_db_roles` maps (azp is only unique within an issuer, so the global
  `CLIENT_DB_ROLES` map is unsafe across tenants).
- **AuthZEN: per-issuer store binding.** `JWT_ISSUERS` entries gain a `stores`
  list of **anchored regex patterns** (plain names match exactly,
  `tenant-a-.*` covers families): tokens from that issuer may only access
  matching stores (403 otherwise) — multi-tenant isolation where each
  tenant's IdP is bound to its stores. Issuers without a list stay
  unrestricted.

- **Multi-AZ reference configuration.** PRODUCTION.md gains a concrete
  single-region/3-AZ Helm setup (all-serving synchronous standbys — the
  serving ⊆ sync-set invariant holds by construction, lagging replicas
  block visibly instead of serving stale allows — zone anti-affinity,
  per-write modes, failure drill); the chart gains a `database.affinity`
  passthrough (CNPG `.spec.affinity`) for zone spreading. Plus a
  **two-node datacenter variant** with an operator-driven promotion
  runbook (fence-first, clear the sync requirement, rejoin via
  pg_rewind/basebackup) and the monitoring signals that map to it.
- **Strict revocation: the write path commits with `remote_apply`.** The
  OPA-fronted writer's connection now sets `synchronous_commit = remote_apply`
  (compose + Helm `postgrestWriter.synchronousCommit`): with synchronous
  standbys configured, a grant/revoke is only acknowledged once every
  synchronous replica has **applied** it — after the ack no replica in the
  set can serve a stale allow (the "new-enemy" window). A no-op without
  synchronous standbys, so all existing deployments are unaffected. The
  serving(-ro) ⊆ synchronous-set invariant, blocking semantics, and the
  client-cancel caveat are documented in PRODUCTION.md → Strict revocation;
  regression-tested in the scaling suite (revoke ack → immediate replica
  check must deny, 10× cycles). **Per-write consistency modes:** the write
  API accepts `consistency: applied | durable | eventual` (forwarded as
  `X-PGAuthz-Consistency`; the writer's `_pre_request()` maps it to a
  transaction-local `synchronous_commit`, failing closed on unknown values) —
  the connection default is the policy, individual writes opt up or down;
  direct-SQL callers use `SET LOCAL synchronous_commit` in their own
  transaction.

### Changed

- **PostgREST v14.13 → v14.14.** Maintenance release (admin server now logs
  the cause of failures); no breaking changes. Verified against the full OPA
  (52) and AuthZEN (42) integration suites.
- **OPA 1.17.1 → 1.18.2.** The only 1.18 breaking change (outbound
  `User-Agent` header format, RFC 9110) doesn't affect this stack; no changes
  to `http.send` caching, the data API, or Rego evaluation we rely on.
  Policies parse clean under 1.18.2 (`opa check`); verified against the full
  OPA (52) and AuthZEN (42) integration suites.

## [0.4.0] - 2026-07-02

### Added

- **`explain_access` now reports the exact granting tuple.** Each granting-tuple
  step gains a `matched_tuple` field — the stored tuple that satisfied it, as
  `subject → relation → object` with `*` wildcards resolved (so an object-wildcard
  grant shows `user:* → can_read_user → user:*`, not the queried ids). Redacted in
  safety mode. The playground's resolution tree renders it. No API break (additive).
- **`todo` example model (AuthZEN interop).** A pgauthz port of the OpenFGA
  [authzen-interop todo model](https://github.com/openfga/authzen-interop/tree/main/todo):
  list/item roles, ownership, TTU, wildcards (incl. a pgauthz **object wildcard**
  making every profile world-readable in one tuple), and an **intersection** —
  deleting/updating an item needs management rights on the parent list *and*
  ownership (so a viewer who owns an item still can't delete it), while
  `admin`/`evil_genius` on the parent bypass ownership. The interop's test-only
  "evil_genius" user is modeled with a **contextual tuple**, as the suite does.
  Ships with `model.sql`, `seed.sql`, `demo.sql`, and a `tests.sql` derived from the interop
  `.fga.yaml` assertions (wired into `tests/test.sh`).
- **AuthZEN console in the playground.** A second perspective — global
  `Access Explorer` | `AuthZEN` tabs — that drives the real `authzen-opa` service
  through the BFF (the session token is injected server-side; the SPA never sees
  it). An endpoint picker (evaluation, evaluations, subject/resource/action search,
  discovery), a **templated request** built from the shared subject/action/resource
  fields, and a response pane. The JSON editors gained a **Format** button, a
  read-only highlighted mode (used for responses), and now fill their pane.
- **Multi-issuer AuthZEN service.** `authzen-opa` can trust several JWT issuers at
  once via `JWT_ISSUERS` (a JSON list of `{issuer, audience, jwks_url|jwks_file}`);
  the token's `iss` selects that issuer's JWKS validator. The legacy single-issuer
  env vars still work (as one issuer). Lets one instance serve demo-issuer tokens
  (tests) and Keycloak tokens (playground) side by side.
- **Role-gated reverse search.** The AuthZEN search endpoints
  (`search/subject|resource|action`) enumerate the access graph, so they can now
  require a role: `SEARCH_REQUIRED_ROLE` (+ `JWT_ROLES_CLAIM` for the claim paths,
  aggregated like OPA's). A new Keycloak `authzen_auditor` realm role (granted to
  alice) gates them in the playground, which disables the search tabs for users
  without it (`/api/me` → `search_enabled`). Off by default (search stays open).
- **Folder support in the demo model.** A nestable `folder` type: `parent` for
  nesting, `viewer`/`editor`/`owner` grants, `can_share` (owner *or* editor), and
  recursive `can_view`/`can_edit`/`can_manage_access from parent`; documents gain an
  additive `parent_folder`, so a grant on a folder inherits **down** through
  subfolders to the documents inside. A new [`docs/MODEL_DESIGN.md` §14 — Recursive
  Hierarchies](docs/MODEL_DESIGN.md) covers the pattern in depth: stable IDs, which
  folders to store (mirror the tree vs. contextual tuples vs. app-resolved
  ancestors), single-check recursion, and cheap subtree moves via
  `write_tuples_checked`.
- **AuthZEN token-forwarding to OPA.** `authzen-opa` can forward the verified bearer
  token to OPA (`FORWARD_TOKEN_TO_OPA`) so OPA re-validates it via `input.token`
  instead of trusting a forwarded subject — letting OPA run in the secure
  `REQUIRE_TOKEN_FOR_READS=true` mode (no tokenless subject-trust), enabled for the
  playground. Off by default; trusted-PEP deployments that check arbitrary subjects
  on behalf of others keep subject-forwarding.
- **Playground: Model Explorer perspective + model-driven type graph.** The UI now
  groups into three perspectives — **Model Explorer** (model DSL + type graph),
  **Access Explorer** (query + resolution path), and **AuthZEN**. The type graph can
  render the model's **declared type restrictions** (all direct relations, matching
  the DSL) or the **tuple-observed** edges, via a model/data toggle, with a legend
  distinguishing direct (`[type]`) from userset (`[type#relation]`, dashed) edges.
  Zoom gained Ctrl/⌘-scroll and trackpad-pinch (about the cursor); hidden nodes are
  now excluded from the layout.

### Changed

- **The demo model declares explicit type restrictions.** Every direct relation now
  lists its assignable subject types (e.g. `define payroll_clerk: [internal_user,
  team#member]`) instead of accepting any type (`[any]`), matching how OpenFGA models
  must declare them. Write-enforced, so `describe_model` and the playground type
  graph now show the real schema. (Example-model change only; no engine change.)

### Fixed

- **Subject search over the OPA path returned no results in trusted-PEP mode.**
  `data.authz.accessible_subjects` reused the `_subject_valid` guard, which in
  no-token mode requires an `input.subject` that subject search doesn't carry — its
  subject is the *result*, not the caller. A dedicated `_subject_search_valid` guard
  authorizes the caller instead (valid token, or trusted PEP), so `authzen-opa`
  subject search now works. Token-mode callers were unaffected.

## [0.3.0] - 2026-07-01

### Added

- **Playground web UI ([`playground/`](playground/README.md)).** An
  OpenFGA-playground-style app to browse a store's model, tuples, and conditions
  and run access queries, then **visualize the `explain_access` resolution path**
  as a tree and an access graph — through the real OIDC → OPA → PostgREST → engine
  path, so the UI shows exactly what the engine decides. A Go backend-for-frontend
  (OIDC authorization-code + PKCE against Keycloak; tokens held server-side, single
  `ISSUER` discovery) plus a no-build Lit SPA, packaged as one self-contained
  container image served under `/playground`. Brought up with the
  `compose-playground.yml` overlay (or `start.sh --playground`). A trusted
  **admin/dev tool** — keep it access-restricted.
- **Advisory type labels.** Migration `0003_type_labels.sql` adds a
  `labels text[]` column (free-form `key:value`, GIN-indexed) to `authz.types` — a
  many-to-many logical grouping orthogonal to `namespace`, for tooling to cluster,
  filter, or hide types by domain. `model_register_type` gains an optional
  `p_labels`; new `model_{set,add,remove}_type_labels` manage them; the playground
  renders them as type-graph clusters.
- **Keycloak demo OIDC issuer ([`keycloak/`](keycloak/)).** Opt-in, realistic
  OIDC/OPA demo (Terraform-provisioned realm and clients, nginx TLS proxy) used by
  the playground and the OPA front-door examples.
- **OPA `explain` endpoint + `token_debug` diagnostics.** OPA now exposes the
  engine's `explain_access`, plus optional token diagnostics (keep off in
  production).
- **Time-boxed conditional grant in the demo seed.** A `non_expired_grant` SQL
  condition + a grant gated by it — a runnable ABAC example that fails closed
  without a request context.
- **Synchronous-replication / zero-RPO failover knob in the Helm chart.**
  CloudNativePG already does automatic write failover when
  `database.instances >= 2` (promotes a standby, repoints the `-rw` Service); the
  new `database.replication.synchronous` block lets a commit wait for a standby
  ack so an acknowledged grant/revoke is never lost on failover (RPO 0). Off by
  default (asynchronous); enable via the new
  [`values-ha.yaml`](deploy/helm/pgauthz/values-ha.yaml) overlay. A render-time
  guard fails the install if `maxSyncReplicas >= instances`. Documented in
  [`docs/PRODUCTION.md` → High availability & failover](docs/PRODUCTION.md) and
  the chart README, with a copy-paste **failover game-day runbook** (planned
  `cnpg promote` switchover + unplanned pod-kill + the single-node-k3d
  stuck-`Terminating` gotcha). `start.sh` gained an `HA=1` toggle (and
  multi-file `VALUES` layering) to deploy the synchronous overlay. The drill was
  validated live on k3d: auto-promotion, `-rw` repoint, and RPO 0 (a
  pre-failover acked write survived) all confirmed.
- **`deploy/helm/pgauthz/failover-test.sh`** — one-command game-day helper:
  `MODE=switchover` (default, graceful `cnpg promote`) or `MODE=failover`
  (pod-kill, auto-force-deletes a stuck-`Terminating` primary). Discovers the
  cluster/primary/standby, checks sync status, lays down a probe write, triggers
  the handover, and asserts RPO 0 (the probe survived) + write-path recovery on
  the new primary, then cleans up.

### Changed

- **Read-replica memo now fails fast at its cap instead of silently degrading.**
  `authz.memo_max_entries` defaults to **5000** (was unlimited), and when a check
  on the GUC (read-only/replica) backend would exceed it, `check_access` raises
  `memo_limit_exceeded` (SQLSTATE `53400`) rather than continuing un-memoized —
  silent degradation past the cap would reintroduce the ~quadratic re-work the
  memo prevents (raised in the external project review). Callers should catch it
  and **retry on the primary** (whose temp-table backend is uncapped). Set
  `authz.memo_max_entries = 0` to restore the old unlimited/no-abort behavior.
  The primary/temp-table path is unaffected. Test:
  `tests/sql/tests_readonly.sql` (`ro_08`/`ro_09`).

### Fixed

- Helm `Chart.yaml` `home:` pointed at the wrong repo (`…/authz-dev`); now
  `https://github.com/thomasdarimont/pgauthz`.
- **Fresh-install / CI init.** `db/security/roles.sql` still referenced the old
  five-argument `model_register_type`; realigned to the new six-argument signature
  (with `p_labels`) and granted the new label functions, so `init.sh` (and every CI
  job that runs it) no longer fails with `function … does not exist`.
- **Playground.** Backend HTTP errors now propagate to the UI instead of rendering
  empty/stale state; conditional **userset** grants receive the correct condition
  annotation (the lookup now includes `user_relation`); the decision and the
  resolution graph are derived from a **single `explain_access` result**, so they
  can no longer disagree (and it halves the work); access-graph nodes that differ by
  rule / condition / wildcard stay distinct instead of collapsing into one.
- **CI.** Fixed a flaky `test-scaling` streaming-replication test.

### Security

- **Playground hardening.** Explore mode (engine-direct, arbitrary-subject checks)
  is now gated behind `PLAYGROUND_EXPLORE_ENABLED` (off by default) plus an optional
  `PLAYGROUND_EXPLORE_ROLE` (a Keycloak realm/client role); the BFF's engine
  connection uses a dedicated least-privilege `authz_metadata` role (read-only
  metadata `SELECT` + `check`/`explain`/`describe_model`) instead of the engine
  superuser; the `write` OPA rule was removed from the BFF's allow-list (read-only);
  and the HTTP server now sets read/write/idle timeouts.

## [0.2.2] - 2026-06-29

### Added

- **`STORE_RETIRED` watch/changefeed event.** `retire_store` now records one
  store-lifecycle event (`action = 'STORE_RETIRED'`) in the audit log and fires
  the `authz_changes` doorbell, so watch consumers learn a store was retired and
  can invalidate everything for it. The event is store-wide: it bypasses the
  per-tuple object-type / namespace / relation filters, and `watch_changes` /
  `watch_cursor` now resolve retired stores (so a consumer can drain the
  changefeed's final events). Time-travel ignores it (the snapshot builders
  filter `action = 'INSERT'`).

### Changed

- **`retire_store` is now O(1), not O(tuples), in audit terms.** It previously
  ran `DELETE FROM authz.tuples` before dropping the live partitions purely to
  make the audit trigger record the removal — writing **one `tuples_audit` row
  per tuple**, a huge-transaction / WAL / replication-lag / partition-lock hazard
  for stores with millions of tuples (raised in the external project review).
  The redundant `DELETE` is gone: dropping the partitions (DDL) already removes
  the data, and a single `STORE_RETIRED` lifecycle event (+ the `deleted_at`
  marker) records the retirement once, regardless of tuple count. The time-travel
  evaluator (`_build_audit_snapshot`) treats a retired store as denying
  everything as of `>= deleted_at`, while the kept INSERT history still answers
  "could X do Y at time T `<` retirement?". Tradeoff: the audit log no longer
  holds a per-tuple deletion record at retirement — the lifecycle event replaces
  it; `audit_list_user`/`audit_list_object` still show the full INSERT history.

## [0.2.1] - 2026-06-29

### Added

- **`retire_store(store)` — soft-delete for audit retention.** Drops only a
  store's live tuples (reclaiming their partitions) and marks it retired
  (`stores.deleted_at`, migration `0002_store_retire.sql`), while keeping the
  dictionary (`types`/`relations`/`models`/`conditions`) and full audit log.
  The `audit_*` time-travel API still resolves a retired store **by name**, so
  preserved history stays queryable — closing the gap where `delete_store`
  removed the name dictionary and orphaned its own preserved audit rows (raised
  in the external project review). Live APIs reject a retired store and its name
  stays reserved; `delete_store` remains the explicit physical-removal/erasure
  path and can later purge a retired store.

### Changed

- `authz._s(name)` now resolves **live (non-retired) stores only**, so every
  live API rejects a retired store with a clear error; the `audit_*` functions
  opt into resolving retired stores. `delete_store` resolves retired stores too,
  so a retired store can be purged.

### Fixed

- **Memoization broke `check_access` on read replicas.** The per-check memo
  builds a session temp table, which cannot be created in a read-only
  transaction (a hot standby), so checks on a replica failed with `cannot
  execute CREATE TABLE in a read-only transaction`. On a read-only transaction
  the memo now switches to a session-GUC `jsonb` backend (the only mutable
  scratch a standby allows) instead of the temp table — so checks on replicas
  are both **correct and still protected** against converging/diamond graphs
  (the GUC backend is slower than the temp table but still polynomial). The
  fast temp-table backend is unchanged on the primary. The GUC payload (visited
  object ids + decisions) is cleared before the check returns (success or error)
  so it never lingers in the session, and `authz.memo_max_entries` (default
  `0` = unlimited) can hard-cap the map size; a check with thousands of distinct
  subproblems is slow on a replica regardless and should be routed to the
  primary (`statement_timeout` is the backstop). Time-travel
  (`audit_check_access`) is unaffected: it materializes its as-of state into
  temp tables, so it already requires a writable transaction and is primary-only.
  Regression test: `tests/sql/tests_readonly.sql`.
- Logical-replication demo (`db/replication/init-replication.sh`) hardcoded
  applying only `0001_baseline.sql`, so the new `0002_store_retire.sql` column
  (`stores.deleted_at`) was missing and every `authz._s()` call failed with
  `column "deleted_at" does not exist`. It now replays **all**
  `db/migrations/*.sql` in order, staying correct as future structural deltas
  land.

### Performance

- **Memoized the `check_access` evaluator** (and the time-travel
  `audit_check_access` twin): converging / diamond relationship graphs that
  re-evaluated a node once per path (`O(2^depth)`) are now collapsed to ~linear
  with a per-check memo that caches only path-independent (cycle-free)
  sub-results — identical decisions on every input, proven differentially in
  `tests/sql/tests_memoization.sql`. A depth-12 diamond DENY dropped from
  ~732 ms to ~1.9 ms (live) / ~1.6 s to ~6 ms (time-travel). Toggle with
  `SET authz.memoize = 'off'`.

## [0.2.0] - 2026-06-29

### ⚠️ Breaking

- **Widened all identifier columns from `smallint` to `integer`** — stores,
  types, relations, models, conditions, and every FK referencing them, including
  the `tuples` partition key `object_type` and the `_tuple_key` / `access_check`
  composite types. This lifts the previous **32,767** cumulative-ID ceiling
  (IDENTITY never reuses values) to ~**2.1 billion**, removing the practical limit
  for dynamic / multi-tenant deployments that create and delete many
  stores/types/relations over time (raised in the external project review).
- **No in-place upgrade from 0.1.x.** Because `tuples` is partitioned by
  `object_type`, a partition-key column type cannot be altered in place, so 0.2.0
  **re-baselines** the schema (`0001_baseline.sql`). Upgrading from a 0.1.x
  install is a **reinstall**, not a migration. (There are no production 0.1.x
  deployments; the `upgrade-test` CI job skips the pre-0.2.0 boundary and resumes
  for 0.2.x onward.) **Performance is unchanged** — verified A/B on one machine:
  integer ≡ smallint within run-to-run noise.

## [0.1.4] - 2026-06-29

Release-process tooling and docs (no engine changes).

### Added
- `docs/RELEASING.md` — a release runbook + pre-release checklist (the bump →
  notes → push → CI-green → tag flow, with the gotchas we've hit); linked from
  `CONTRIBUTING.md`.
- `scripts/release.sh` automation:
  - `--auto` — wait for the GitHub CI run on HEAD to pass, then tag and push
    (= `--wait-ci` + `--push` + `--strict-changelog`).
  - `--wait-ci` — block until CI is green before tagging, so a red commit is
    never tagged (needs the `gh` CLI).
  - `--strict-changelog` — fail instead of warn when the release notes are empty.
- `scripts/release.sh` now warns when the `## [X.Y.Z]` CHANGELOG section has no
  notes (empty-release-notes guard).

## [0.1.3] - 2026-06-29

### Added
- CI `scaling-test` job + `tests/test-scaling.sh` covering the streaming-
  replication (read-replica) demo: the standby streams the schema + data,
  resolves `check_access` on the read-only replica, and serves the
  OPA → PostgREST → replica read path.
- `-version` flag on the AuthZEN Go apps (`authzen-direct` / `authzen-opa`),
  stamped at build time via ldflags (tracks the image tag; `dev` for local
  builds). No HTTP endpoint.

### Fixed
- Streaming-replication scaling demo (`compose-scaling.yml`) was broken in four
  places:
  - `db/scaling/start-replica.sh`: the standby FATAL'd because
    `max_connections` (100) was below the primary's 250 — pin it to 250.
  - `env.sh` ignored the documented `COMPOSE_FILE=compose-scaling.yml ./init.sh`
    override and aborted under `set -e` on `ps -q authz-db` — honor
    `COMPOSE_FILE` and resolve `authz-db` or `authz-primary`.
  - `compose-scaling.yml`: OPA was missing the `REQUIRE_TOKEN_FOR_READS`
    mapping the base stack has, so it denied the documented tokenless demo read.

## [0.1.2] - 2026-06-29

### Added
- CI `replication-test` job + `tests/test-replication.sh` covering the logical-
  replication demo end to end: subscribers reach `ready`, the full replica
  resolves `check_access` on replicated data, the derived replica receives the
  flat `materialized_permissions` table, and a live write on the primary
  propagates.

### Fixed
- Logical-replication demo (`db/replication/`) was silently broken
  (`init-replication.sh` lacked `ON_ERROR_STOP`, so SQL errors left a broken
  setup but the script still exited 0). Four fixes:
  - `init-replication.sh` resolved `PG_DIR` to `db/db/...` after the script
    moved under `db/replication/` — point it at the repo root.
  - `setup-publication.sql`: `ALTER DEFAULT PRIVILEGES … GRANT SELECT` was
    missing `ON TABLES` (syntax error).
  - `setup-subscription.sql`: the metadata subscription copied data into tables
    the subscriber already populates by loading the model, causing duplicate-key
    crash-loops — use `copy_data = false` (stream changes only).
  - `materialized_permissions.sql` `_queue_permissions_refresh()`: an `INSERT`
    had three target columns but two expressions — add the missing `store_id`.

## [0.1.1] - 2026-06-29

### Added
- **Non-destructive in-place upgrade** — `upgrade.sh` (`SKIP_RESET=1 ./init.sh`)
  applies pending migrations and reloads the idempotent engine code without
  `DROP SCHEMA`, preserving stores/tuples/audit. The local analog of the
  CloudNativePG `deploy/migrations/run-migrations.sh` path.
- CI `upgrade-test` job: install the previous release tag, seed fixtures,
  upgrade in place to HEAD, and assert the data survived and access still
  resolves (ADR 0001 step 6).
- `scripts/bump-version.sh` — bump every pinned version reference and roll the
  CHANGELOG; pairs with `scripts/release.sh`.

### Fixed
- sqlx migration-ledger shadowing on re-runs / in-place upgrades: connecting as
  role `authz` let the baseline-created `authz` schema shadow the real
  `public._sqlx_migrations` via `search_path`, so sqlx treated the baseline as
  unapplied and tried to re-run it. Pin `search_path=public` on every sqlx
  connection (`env.sh`, `deploy/migrations/run-migrations.sh`,
  `scripts/gen-schema.sh`). Fresh installs and the CloudNativePG path (which
  connects as `postgres`) were unaffected.

## [0.1.0] - 2026-06-29

Initial tagged release: a PostgreSQL-native authorization engine implementing
Google Zanzibar / OpenFGA relationship-based access control (ReBAC) in pure
PL/pgSQL.

### Engine
- Recursive relationship resolution with union (OR), intersection (AND), and
  exclusion (BUT NOT) rule semantics; type restrictions and wildcards.
- Multi-store architecture — every operation scoped to a `store_id`.
- `check_access`, `list_objects` / `list_subjects` (search) with keyset
  pagination, and `explain_access` (decision trace + human-readable summary).
- Conditions / ABAC with a `lang` discriminator: `sql` built-in plus optional
  `cel` via the `pg_cel` extension; conditions evaluate in the zero-privilege
  `authz_eval` sandbox. Management API (`create_condition*` / `delete_condition`).
- Atomic, conditional writes with optimistic-concurrency preconditions
  (`write_tuples_checked`).
- Immutable, monthly-partitioned audit trail with time-travel queries and a
  cursored changefeed (`watch_changes` + `NOTIFY`).
- `describe_model` renders a stored model as OpenFGA-DSL text; OpenFGA JSON
  model/tuple import.

### Deployment
- Three-tier reference stack: PostgreSQL engine, PostgREST REST bridge, OPA as
  the single front door for reads and writes (JWT authn, policy-as-code).
- Go AuthZEN 1.0 API services: `authzen-direct` (Go→PostgreSQL) and
  `authzen-opa` (Go→OPA→PostgREST→PostgreSQL).
- Deployment profiles (substrate / read / write / audit) via a manifest;
  read-only install (`init-readonly.sh`) for an embedded engine fed by logical
  replication.
- Helm chart on CloudNativePG, with `extraRoles` for declarative app roles.
- Logical-replication and streaming-replication (read-replica) topologies.

### Schema management
- Forward-only structural migrations in `db/migrations/` applied by `sqlx-cli`
  and tracked in `public._sqlx_migrations`; idempotent engine code loaded after.
  Install and upgrade are the same non-destructive operation — no `DROP SCHEMA`
  (see [ADR 0001](docs/adr/0001-schema-migrations.md)).

### Requirements
- PostgreSQL 18.x (developed/tested on 18.4). PostgREST, OPA, the AuthZEN
  services, and `pg_cel` are optional components of the reference deployment.

[Unreleased]: https://github.com/thomasdarimont/pgauthz/compare/v0.18.0...HEAD
[0.18.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.3...v0.8.0
[0.7.3]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/thomasdarimont/pgauthz/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/thomasdarimont/pgauthz/releases/tag/v0.1.0
