# pgauthz Console — management UI (proof of concept)

A web console for the people who run pgauthz: design and edit a store's
model, test decisions for any subject, share objects, publish and roll out
registry versions, and read what happened. Its distinguishing idea: **who may
do what in the console is itself a pgauthz question**, answered by a pgauthz
store (`examples/models/console`) before every screen and every action.

```
Browser ──OIDC code+PKCE──▶ Keycloak
   │ http-only cookie
   ▼
console-bff (Go)  ──1. "may alice can_edit_model store:demo?"──▶ pgauthz (console store)
                  ──2. model_add_rule('demo', …) as alice     ──▶ pgauthz (store demo)
                  ──3. record_event('console', …)             ──▶ pgauthz (console store)
```

Status: **proof of concept** on branch `poc/console`. It works end to end on
the dev stack; see *What is not there yet* before relying on it.

## Run it

```bash
./keycloak/config/generate-mkcerts.sh          # once: *.pgauthz.test certs
./start.sh --cel --console                      # implies --keycloak (and --opa)
(cd keycloak/terraform && terraform init && terraform apply)   # console-bff client, console_admin role
./init.sh                                       # engine + roles (creates authz_console)
source env.sh
psql_file "$PG_DB" examples/models/console/model.sql
psql_file "$PG_DB" examples/models/console/seed.sql
open https://app.pgauthz.test/console/
```

`tests/test.sh` loads the console store as a fixture, so after a full
`./bootstrap.sh` the two `psql_file` lines are already done. Add
`127.0.0.1 app.pgauthz.test` to `/etc/hosts` if it does not resolve.

**Without Keycloak, in the dev stack:** `./start.sh --console-local` (add
`--cel` to keep CEL) serves the console at `http://localhost:8095/console/`
with the local admin `admin` / `admin` (`CONSOLE_LOCAL_ADMIN_PASSWORD`), no
proxy, no OPA — `compose-console-local.yml`; run `./init.sh` once if the
engine is not installed yet. The personas above need the Keycloak overlay.

**Without an identity provider** — a first look, a test deployment — the BFF
offers a **local admin sign-in**: set `CONSOLE_LOCAL_ADMIN_USER` and
`CONSOLE_LOCAL_ADMIN_PASSWORD` (and no `ISSUER`, or both). That person signs
in as `user:<name>` with the memberships in `CONSOLE_LOCAL_ADMIN_TEAMS`
(default `role_console_admin`, the team the seed makes platform admin) and
holds `CONSOLE_LOCAL_ADMIN_STORE_ROLE` (default `owner`; `none` for no store
role) on every store — contextually, nothing is written — so the account can
test, edit, publish and share everywhere, which is what a testing account is
for; the console store still decides every question. Deactivate it by unsetting the
two variables and restarting: the form disappears and every local session is
rejected at once. It is one shared password, so the BFF refuses it under
`DEPLOYMENT_ENVIRONMENT=production` unless
`CONSOLE_LOCAL_ADMIN_ALLOW_IN_PRODUCTION=true` is set deliberately.

**Deployments:** the Helm chart (`console.enabled`,
[deploy/helm/pgauthz](../deploy/helm/pgauthz/README.md#management-console))
and the Docker Compose deployment (`--profile console`,
[deploy/compose](../deploy/compose/README.md#profiles)) run the console next
to the engine, create its store once and give it its own sessions database.

Demo users (password `password`) come in two kinds. The **console personas**
each hold one realm role that the console turns into a team membership, so
what they see follows from `examples/models/console/seed.sql`:

| User | Realm role | Who they are | What they can do in the console |
|---|---|---|---|
| `platform-admin` | `console_admin` | IT / operations | platform admin: create, adopt and delete stores, reassign owners, health, issuers; owner of the `console` store |
| `auditor` | `console_auditor` | audit | `auditor` on every demo store and registry viewer: Activity, decisions, point-in-time checks; read-only |
| `iam-dev` | `console_iam_dev` | IAM developer, owns the models | `author` + `publisher` on every demo store, registry publisher: edits, publishes, rolls out |
| `app-dev` | `console_app_dev` | application developer | `viewer` + `tester` on `demo` and `todo`: reads the model, tests their own access under the test policy |
| `app-secarch` | `console_app_secarch` | application security architect | `author` on `demo` (their application's store), `tester` on `todo`, registry viewer |
| `support` | `console_support` | support | `supporter` on `demo`, `todo`, `gdrive`: checks and explains anyone's access, never edits |

**alice**, **bob**, **carol** and **eva** are the *application users* — the
subjects the demo models decide about (alice also keeps `console_admin` and
owns `demo`, `todo` and `gdrive`; bob tests `demo` and authors `todo`; carol
views `demo`; eva audits it).

## What you see

| Area | Screen | Needs (console store) |
|---|---|---|
| **Stores** | the stores you can see, with your capabilities; unclaimed stores (platform admin) and *New store* | `store#can_view`; `platform#can_view_all_stores`, `platform#can_create_store` |
| Store → **Model** | three read views of the live model (DSL, canonical JSON, SQL calls); "Edit as DSL" to write the whole model in that DSL (a starter model for an empty store); the structured editor, one tab per section (types with their namespace and labels, relations with their rules and type restrictions in one step and their payload schema, rules, type restrictions, conditions, temporal gates, grant rules), each section's add button and edit form inside its tab; the section is in the URL (`stores/<store>/model/<section>`) | `can_view`; editing `can_edit_model` |
| Store → **Data** | tuples with filter; grant/revoke; **Export** as JSON (native, round-trippable with conditions, context and expiry), CSV or the OpenFGA ReadTuples shape — a dedicated capability, and every export is recorded in the console's action log (who, when, format, rows); **Import** of any of the three (shape detected, preview, then one transaction as you, scoped by the namespaces of the object types touched, up to 10000 tuples); **Offboard** a subject (count, confirm, `delete_user_tuples`); **Share** an object under the model's grant rules as a chosen actor of the store — `grant_options` says what that actor may grant and revoke per relation and who may hold it, additions and removals queue up and are saved as one `apply_grants` transaction, each decided by the engine | `can_view`; writes and sharing `can_grant`; export `can_export` (exporter, owner) |
| Store → **Test** | four modes: single check + explain; matrix (subjects × actions × resources, one batch call); reverse search (which objects can X reach / who can reach Y); "as me via pgauthzd" (your own token, with the detail envelope: OPA, hooks, veto). The **test policy** limits a plain tester to their own access with redacted trees, no enumeration and no history; every test is recorded in the console's action log | `can_run_tests`; `can_test_others`, `can_test_explain_full`, `can_test_search`, `can_test_history` widen it |
| Store → **Rollout** | managed-model state and drift, the versions of the store's model (an unmanaged store picks a registry model first), plan (dry run), apply; publish the live model | `can_view`; `can_rollout` to apply; `can_publish` on the store **and** `registry#can_publish` to publish |
| Store → **Activity** | console actions on this store, the relationship audit trail, the model change history (rules, conditions, gates, grant rules added or removed, by whom), the store's action log | `can_view_audit` |
| Store → **Access** | who has which console role on the store; grant/remove; a store never loses its last owner. **Namespaces**: `author` / `viewer` on one namespace of the store (an application team's slice) | `can_view`; `can_manage_access` to change |
| Store → **Policies** | when OPA fronts the deployment: the Rego that applies to this store — its hooks, the global hooks, shared libraries, platform policy — with sources, plus OPA's version and bundle revisions; read-only (policies are authored in git and shipped as validated bundles) | `can_view`; `CONSOLE_OPA_URL` + `CONSOLE_OPA_TOKEN` on the BFF |
| Store → **Operations** | can the gates be trusted (`events_readiness`, every clause's window); the recorder allowlist (`grant_recorder_actions` / `revoke_recorder_actions`); tuple maintenance (reclaim expired tuples with a grace, find and remove redundant tuples); this store's action-log retention (`purge_events`, refused inside a live gate window unless forced); the changefeed cursor and safe-until, the derived-permissions status when installed; the partitions of both logs (read-only here) | `can_view_audit`; actions `can_manage_access` |
| Store → **Admin** | the store's lifecycle: retire it (soft delete — live data gone, history and name kept) or delete it (typed name, optional audit purge) | `can_manage_access` |
| **Registry** | one picker over models and stores: the models are the landing chips (few by design), typing searches models and stores by name, description and model (matches capped, never the whole fleet as chips). A model (`registry/model/<name>`) shows its versions and its fleet — every store running it, a (?) explaining the colours; a store (`registry/<store>`) shows the model and version it runs, the versions with the applied one marked, and the fleet | `registry#can_view` |
| **Platform** | admins (grant/remove; never zero), configuration and health; **Operations**: the monthly partitions of both logs with sizes and coverage ahead, create them ahead (`ensure_audit_partitions` + `ensure_event_partitions`), fleet-wide action-log retention (`drop_event_partitions_before`, gate-guarded), gate readiness per store, the longest gate window, store sizes | `platform#can_view_health`, `platform#can_manage_access` |

Relations carry a kind (migration 0019): **what a subject is** (a relation:
viewer, owner, member) versus **what a subject can do** (a permission:
can_read, or a directly granted capability such as `run: [agent]`). The Test tab groups the action
picker by kind, words the question accordingly ("is alice *a viewer of*
doc:x?" versus "is alice *allowed can_read on* doc:x?"), and explains a "no"
on a relation by offering the type's permissions; the Data tab's Add form
completes only assignable relations, since the engine refuses tuples on a
permission.

Removing anything (model parts, tuples, role assignments) is select →
"Remove selected…" → an inline confirmation that lists what goes → one
transaction; there is no single-click delete. A whole store leaves through
its Admin tab (owners and platform admins), after its name is typed back:
**Retire** (`authz.retire_store`) is the audit-safe way out — the live
tuples go and every live API refuses the store from then on, but the model
dictionary, the audit history and the name stay, the console roles on it
stay, and the store shows as *retired* (Activity, Access and Admin remain
usable; a retired store's action log is live-only and comes back empty;
the home table hides retired stores unless "show retired" is ticked);
**Delete** in the "Danger zone" (`authz.delete_store`) removes it for good,
retired or not, with the choice to purge the audit history too, and the
console roles on that store go with it. Stores carry a description
and a documentation link (`authz.update_store`), edited by owners on the
store header. The home page lists the stores you can see as a table with
their model status, your access, the creation time (`stores.created_at`)
and the last model, condition or tuple change from the audit trail; platform
admins also see stores nobody manages in the console yet and can adopt or
delete them there (typed confirmation as well). Conditions and temporal
gates are listed with their description, mode and clauses, created and
last-changed times, and a *Details* row showing the SQL call that recreates
the item and its JSON (a condition's row also has *Try it*: a request
context and a mocked stored context evaluated without any tuple); both are edited in place (a save under the same name
replaces the definition; gate clauses are JSON with one template per
primitive; every JSON field is one shared editor that highlights, parses as
you type and names the line and column of a mistake, and the form will not
submit while it is invalid). Inputs carry no placeholder text: what goes in
and an example are in the label or the (?) next to it, so the guidance stays
once you start typing. The UI is in English by default with a German translation
(chosen on the personal Settings page behind the gear in the top bar), and
columns and sections carry (?) help texts. Dictionaries are plain JSON
(`frontend/src/i18n/<lang>.json`, English strings are the keys). An operator
overrides entries, or adds a language, without rebuilding: put `<lang>.json`
files in a directory and point `CONSOLE_I18N_DIR` at it — the BFF serves them
at `api/i18n/<lang>` and the SPA merges them over the built-in dictionary; an
`"@language": "Français"` entry names a new language in the picker.

The console's own store is created by `./start.sh --console` from
`examples/models/console/model.sql` + `seed.sql` when it is missing, and
never reset afterwards; the test suite loads the same fixture under the name
`console_test` (psql variable `cs`), so a test run leaves the live grants
alone. When a release extends the console model (a new role or capability),
an existing console store needs that delta applied once, as the engine's
admin role — the fixture is the reference; the statements are idempotent.
The `exporter` role and `can_export` (2026-10) are:

```sql
SELECT authz.model_register_relation('console', r) FROM unnest(ARRAY['exporter', 'can_export']) AS r;
SELECT authz.model_add_rule('console', 'store', 'exporter', 'direct');
SELECT authz.model_add_type_restriction('console', 'store', 'exporter', 'user');
SELECT authz.model_add_type_restriction('console', 'store', 'exporter', 'team', 'member');
SELECT authz.model_add_rule('console', 'store', 'can_view', 'computed', 'exporter');
SELECT authz.model_add_rule('console', 'store', 'can_export', 'computed', r) FROM unnest(ARRAY['exporter', 'owner']) AS r;
SELECT authz.model_set_relation_metadata('console', 'can_export', '{"kind": "permission"}');
```

The console store's model, in OpenFGA style, is in
[`examples/models/console/model.sql`](../examples/models/console/model.sql);
the roles are `owner`, `author`, `publisher`, `sharer`, `tester`, `supporter` (tests anyone's access with full trees, edits nothing), `auditor`,
`viewer` on a store, `admin` on the platform, `publisher`/`viewer` on the
registry, and `author`/`viewer` on a **namespace** (`namespace:<store>/<name>`).
A namespace role is how an application team owns its slice of a shared
store: types carry a namespace, and the console checks every model or data
change against the namespace of the type it touches — a namespace author may
add types, rules, restrictions, gates and tuples inside their namespace,
while relations, conditions, the DSL apply and types without a namespace are
store-wide and need the store role. Both namespace roles open the store (two
link tuples written on the first grant make the store's `can_view` reach the
namespace). Namespaces themselves are managed on the Model tab: a type gets
one on creation or through "Namespace…" on its row (empty = store-wide), the
summary under the types table renames a namespace, moving its types and its
role assignments together — a namespace exists exactly as long as a type
names it.

Who should use the console for what: the **platform team** creates and
retires stores and owns shared core types (`platform:admin`, store `owner`);
**model owners** per bounded context are `author`/`publisher` on their store
or namespace; **application developers** are `viewer` plus `tester` and use
the Test tab under the test policy; **auditors** are `auditor`. One store per
cluster of bounded contexts that share identity and vocabulary and need
decisions across applications, namespaces for ownership inside it; separate
stores where nothing is shared (and always per tenant).

## How the access works

- **People** are `user:<preferred_username>` in the console store (the local
  admin sign-in: `user:<CONSOLE_LOCAL_ADMIN_USER>`, with the configured teams
  instead of token claims).
- **Directory memberships come from the token, as contextual tuples.** For
  every realm role, group and organization in the access token the BFF adds
  `user:alice member team:role_<name>` / `team:group_<path>` / `team:org_<alias>`
  to each console check (`CONSOLE_TEAM_CLAIMS`, default
  `role=realm_access.roles,groups,organization`). Nothing is written: the
  IdP stays the source of truth for membership, and the Access tab can grant
  a role to a team that only exists there.
- **Explicit roles** are ordinary tuples of the console store, written by the
  Access tab (`user:bob tester store:demo`). The creator of a store becomes
  its first owner; ownership is transferable; the last owner cannot be
  removed.
- **Decided twice, the second time for real.** The screen asks before it
  shows a button; the BFF asks again *inside* the transaction that makes the
  change, after taking a per-object lock (`pg_advisory_xact_lock` on
  `store:X` / `platform:default`). A role revoked in between denies the
  change, and two owners removing each other at once leave one owner — the
  last-owner rule is counted under the same lock. Because a store role can
  come from `platform#admin`, store changes hold the platform lock shared
  and platform-admin changes take it exclusively: revoking an admin waits
  for what they already started and denies what they start afterwards.
- **Sessions live as long as the access token.** Memberships come from the
  token, so the BFF renews it with the refresh token shortly before expiry
  and ends the session (401, sign in again) when it cannot. The cookie's 8
  hours are an upper bound, not a promise.
- **"Your own access" in the test policy** means the person's id under the
  console subject type or one of `CONSOLE_SELF_SUBJECT_TYPES` (the types
  that denote people in the managed stores); `agent:alice` is another
  principal and needs `can_test_others`.
- **The platform admin** reaches every store through `store:X platform
  platform:default`: they can see it, adopt unclaimed stores and reassign
  owners, but editing, publishing or sharing still needs a store role.
- **Every action is attributed and recorded.** Writes run in one
  transaction with `authz.performed_by = user:alice`, so the tuple audit
  trail, `created_by` of a published version and `applied_by` of a rollout
  name the person, not the service role. Each console action is also an
  event in the console store's action log (`record_event('console', 'user',
  'alice', 'can_edit_model', 'store', 'demo', …)`), which the Activity tab
  shows.
- A **403** from the BFF names the missing capability and object, and the UI
  says so ("This needs *edit model* on store:demo").

## Tests

`go test ./...` in `backend/` runs the unit tests; the database-backed race
tests (concurrent last-owner removal, platform-revocation ordering, the
namespace-rename gate) need `PGAUTHZ_TEST_DATABASE_URL` and a console store
(`PGAUTHZ_TEST_CONSOLE_STORE`, default `console`) and skip without them.
`../tests/test-console-go.sh` loads the fixture as `console_gotest`, runs
them as mandatory (`PGAUTHZ_TEST_REQUIRE_DATABASE=1`) and drops the store;
`tests/test-all.sh` and CI include it. The access model's own SQL checks are
`../examples/models/console/tests.sql` (run by `tests/test.sh`).

### API shapes

`frontend/src/types.js` holds the BFF's response shapes as JSDoc typedefs
(no runtime): the `api.js` calls declare what they resolve to and each
component types the state it keeps a response in, so an editor resolves
fields and flags a misspelt one. Keep it in step with the Go structs' json
tags when a response changes.

### Test ids

Every control an end-to-end test would drive carries a `data-testid`, named
`<tab>-<thing>[-<key>]` in kebab-case: the tab or screen first (`model`,
`admin`, `activity`, `store`), then the element, then the item it belongs to
when there is one (`model-type-labels-edit-document`,
`model-grant-rule-document-viewer`, `admin-retire-submit`,
`activity-view-model`, `store-tab-admin`). New UI gets them as it is built,
so a Playwright suite can select by role and test id instead of by text,
which is translated.

## Pieces

- `backend/` — the Go BFF (`cmd/console`, `internal/{config,oidc,server}`):
  OIDC login (code + PKCE, confidential client), sessions in its own
  Postgres, the gate (`internal/server/authz.go`), one handler file per tab.
  Talks to the engine as the `authz_console` role
  (`db/security/roles.sql`): admin tier + contextual-tuple checks + SELECT on
  the metadata and audit tables — the console store is the gate in front of
  that privilege.
- `frontend/` — a Lit 3 SPA with no build step (import map pins `lit`);
  `npm run check` lints. Light DOM, styled by `styles.css`; the explain tree
  is the playground's component.
- [`../pgauthzadm`](../pgauthzadm) — the embeddable library the BFF uses for
  model export, the SQL rendering and the registry lifecycle; `pgauthzctl`
  uses the same code (no subprocesses in the container).
- `compose-console.yml`, `Dockerfile` (build context = repo root, for
  `pgauthzadm`), `proxy.conf` (serves `/console/` and `/playground/` on
  `app.pgauthz.test`, so both overlays compose), Keycloak client
  `keycloak/terraform/client.console-bff.tf`.

Configuration (environment): `ENGINE_DSN`, `PG_DSN` (sessions), `ISSUER`,
`CLIENT_ID`/`CLIENT_SECRET`, `REDIRECT_URI`, `BASE_URL`, `BASE_PATH`,
`TLS_CA_FILE`, `CONSOLE_STORE` (default `console`), `CONSOLE_PLATFORM_ID`,
`CONSOLE_REGISTRY_ID`, `CONSOLE_SUBJECT_TYPE`, `CONSOLE_SELF_SUBJECT_TYPES`, `CONSOLE_TEAM_CLAIMS`,
`CONSOLE_I18N_DIR` (translation overrides), `CONSOLE_OPA_URL` / `CONSOLE_OPA_TOKEN` (Policies tab), `PGAUTHZD_URL` (readiness shown on Settings), `PGAUTHZD_DECISION_URL` (the
"as me" test mode; empty hides it), `CONSOLE_LOCAL_ADMIN_USER` / `_PASSWORD` /
`_TEAMS` / `_ALLOW_IN_PRODUCTION` (the local admin sign-in; `ISSUER` may then be
empty).

## What is not there yet

- **Decisions.** `can_view_decisions` is modelled but the decision log
  (ADR 0013) lives in pgauthzd's stdout, not in the database; the tab is
  not built. The "as me" test mode shows OPA's part for one decision; the
  log line (`via`, `policy`, `hooks`, `hook_denials`) is where it is kept.
- **Arbitrary subjects through OPA.** With `FORWARD_TOKEN_TO_OPA`, OPA takes
  the subject from the token, so the OPA path is self-subject only; other
  subjects are decided engine-direct (no hooks). A tester-grade PEP client
  (ADR 0014) with a service token would lift that.
- **Saved test scenarios.** The matrix a tester builds is not yet saved as a
  `tests.authz.yaml` fixture; the runner lives in pgauthzctl.
- **Replacing the playground.** The console is the successor of
  [`playground/`](../playground/README.md); still to move over before the
  playground goes: the resolution-path **graph** (the explain tree is shown
  as a tree here, not drawn), the DOT export, and the "act as the PEP" bar
  (record / reserve events against a store's gates). Then the playground,
  its Keycloak client and its compose overlay are removed.
- **Identities are usernames.** People are `user:<preferred_username>`,
  so a username reassigned in the IdP inherits the old holder's console
  roles. The durable key is `(issuer, sub)`; moving to it means a mapping
  table (or `user:<issuer-alias>|<sub>` ids) and a display-name lookup for
  the Access tab, and it changes every tuple in the console store — a
  deliberate open item while there are no deployments to migrate. Until
  then, treat username reuse as an IdP policy question.
- **End-user sharing semantics.** The Data tab's Add writes tuples directly
  for console sharers; its Share dialog exercises `apply_grants` under the
  grant rules as a chosen actor, which is what an application does through
  pgauthzd with the token's subject — the console lets a sharer act as any
  subject, pgauthzd does not.
- **pgauthzd as the data plane.** The BFF goes to the engine directly (one
  service role, gated by the console store). Routing writes through
  pgauthzd-full with the person's token as an ADR 0014 PEP client would add
  the daemon's decision log and claim gates; the Keycloak client already
  carries the API audience for that.
- **Model import from files** and the playground's graphs are not absorbed
  yet (pasting `.fga` content into "Edit as DSL" works, since it is the same
  parser pgauthzctl uses); the playground overlay still runs alongside
  (`--playground --console`).
- No model-change preview: edits are live in the store (publish the model
  first, then roll back by applying the previous version).
