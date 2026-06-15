# Developer Guide

How to work with the PostgreSQL authorization model day-to-day.

## Concepts

The authorization model is based on [Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) /
[OpenFGA](https://openfga.dev/) and stores relationships as **tuples**:

```
user  --relation-->  object
```

For example: `internal_user:alice --member--> team:payroll_team`

Permissions are resolved by following chains of tuples and model rules.
There are three rule types:

| Rule type | Meaning | Example |
|---|---|---|
| **direct** | A stored tuple directly grants the relation | `alice` is a `member` of `team:payroll_team` |
| **computed** | An alias — if you have relation A, you also have relation B | `can_read` on document includes `viewer` |
| **tuple-to-userset (ttu)** | Follow a link to another object, then check a relation there | `can_read` on document = `can_view` from `in_internal_space` |

### Multi-Store

All operations are scoped to a **store** — an independent authorization
namespace. Each store has its own model rules, tuples, and conditions.
Types and relations are scoped per store — each store has its own
independent set of types and relations.

The demo store is `'demo'`. All API functions take the store name as
their first parameter.

```sql
-- Create a new store for testing a different model
INSERT INTO authz.stores (name) VALUES ('v2_experiment');

-- Write rules and tuples to the new store
SELECT authz.write_tuple('v2_experiment',
    'internal_user', 'alice', 'member', 'team', 'payroll_team');
SELECT authz.check_access('v2_experiment',
    'internal_user', 'alice', 'member', 'team', 'payroll_team');
```

### Access Control Roles

All `authz` functions have `EXECUTE` revoked from `PUBLIC`. Access is
controlled through these application roles:

| Role | Can do | Inherits |
|---|---|---|
| `authz_auditor` | `audit_check_access`, `audit_list_actions`, `audit_list_user`, `audit_list_object` | — |
| `authz_reader` | `check_access`, `check_access_with_context`, `list_objects`, `list_subjects`, `list_actions`, `validate_condition`, `explain_access` | — |
| `authz_contextual_reader` | `check_access_with_contextual_tuples`, `check_access_with_contextual_tuples_jsonb` (inject ephemeral tuples — grant only to trusted PDP callers, NOT to roles reachable by untrusted clients) | — |
| `authz_writer` | `write_tuple`, `delete_tuple`, `write_tuples`, `delete_tuples`, `write_tuples_jsonb`, `delete_tuples_jsonb`, `delete_user_tuples` | `authz_reader` |
| `authz_admin` | `create_store`, `delete_store`, `model_register_type`, `model_register_relation`, `model_add_rule`, `model_remove_rule`, `model_remove_rules`, `find_redundant_tuples`, manage `namespace_access` table | `authz_writer` |

`authz_auditor` is a peer of `authz_reader`, not part of the linear chain.
The PostgREST anonymous role (`api_anon`) inherits `authz_reader`.

All public functions are `SECURITY DEFINER` — they run as the `authz` owner,
so application roles need no direct table access.

Grant the appropriate role to your application database users:

```sql
-- Backend that needs to write tuples
GRANT authz_writer TO my_backend_user;

-- Admin tool that can manage stores
GRANT authz_admin TO my_admin_user;
```

### Namespace-Based Write Access Control

When multiple applications share a single store, you can restrict which
application can manage (write/delete) tuples for which object types by
assigning **namespaces** to types and granting DB roles per namespace.

- Types with `namespace = NULL` remain **unrestricted** — any role can read/write tuples for them.
- Types with a non-NULL namespace require the `session_user` to be a member of a role listed in `authz.namespace_access` with the appropriate `can_read`/`can_write` flag.

```sql
-- Assign namespaces to types
UPDATE authz.types SET namespace = 'hr'        WHERE store_id = authz._s('demo') AND name IN ('engagement', 'assignment');
UPDATE authz.types SET namespace = 'documents' WHERE store_id = authz._s('demo') AND name IN ('document', 'upload_request');

-- Grant access per namespace (can_read, can_write)
INSERT INTO authz.namespace_access (store_id, namespace, db_role, can_read, can_write) VALUES
    (authz._s('demo'), 'hr',        'app_hr',  true, true),
    (authz._s('demo'), 'documents', 'app_dms', true, true);

-- Create application roles and grant them to DB users
CREATE ROLE app_hr NOLOGIN;
CREATE ROLE app_dms NOLOGIN;
GRANT authz_writer TO app_hr;
GRANT authz_writer TO app_dms;
GRANT app_hr  TO hr_backend_user;
GRANT app_dms TO dms_backend_user;
```

Now `hr_backend_user` can only read and write tuples for `engagement` and `assignment`,
while `dms_backend_user` can only read and write tuples for `document` and `upload_request`.

Write namespace enforcement applies to: `write_tuple`, `delete_tuple`, `write_tuples`,
`write_tuples_jsonb`, `delete_tuples`, `delete_tuples_jsonb`, and `delete_user_tuples`.

Read namespace enforcement applies to: `check_access`, `check_access_with_context`,
`check_access_with_contextual_tuples`, `check_access_with_contextual_tuples_jsonb`,
`list_objects`, `list_subjects`, `list_actions`, `explain_access`, `audit_check_access`,
`audit_list_actions`.

### Condition Expression Security

Condition expressions are evaluated via `authz._exec_condition()`, which is
a `SECURITY DEFINER` function owned by the `authz_eval` role. This role has
zero table/function access — only pure SQL operators and casts work inside
expressions, preventing malicious expressions from reading or modifying data.

## Common Operations

### Granting access (writing a tuple)

Use `authz.write_tuple()` to create a relationship between a user and an object.
Returns `true` if a new tuple was created, `false` if it already existed (idempotent).
The first argument is always the store name. An optional `p_performed_by` parameter
records the application user identity in the audit trail.

```sql
-- write_tuple(store, user_type, user_id, relation, object_type, object_id)
SELECT authz.write_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');

-- With userset: pass user_relation as 7th parameter
SELECT authz.write_tuple('demo',
    'team', 'payroll_team', 'payroll_clerk', 'assignment', 'eng_42_payroll',
    'member');

-- With condition: pass condition name and stored context as 8th/9th parameters
SELECT authz.write_tuple('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    NULL, 'non_expired_grant',
    '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb);
```

After writing the tuple, Grace inherits all permissions that flow from
team membership (e.g. `can_read` on documents in the payroll data space).

### Revoking access (deleting a tuple)

Use `authz.delete_tuple()` to remove a relationship. Returns `true` if a
tuple was deleted, `false` if no matching tuple existed.

```sql
-- delete_tuple(store, user_type, user_id, relation, object_type, object_id)
SELECT authz.delete_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
```

### Checking access

```sql
-- Can Alice read the payroll doc?
SELECT authz.check_access('demo', 'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- With request context (for conditional tuples)
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
);
```

### Search queries (AuthZen Search API)

```sql
-- Which documents can Bob read?
SELECT * FROM authz.list_objects('demo', 'internal_user', 'bob', 'can_read', 'document');

-- With pagination (stable ordering by object_id / subject_id)
SELECT * FROM authz.list_objects('demo', 'internal_user', 'bob', 'can_read', 'document',
    p_limit => 10, p_offset => 0);

-- Which users can read this document?
SELECT * FROM authz.list_subjects('demo', 'internal_user', 'can_read', 'document', 'doc_payroll_001');

-- What can Alice do on this document?
SELECT * FROM authz.list_actions('demo', 'internal_user', 'alice', 'document', 'doc_payroll_001');
```

## Modifying the Authorization Model

### Adding a new relation

1. **Register the relation** in `model.sql` by adding it to the
   `INSERT INTO authz.relations` block:

```sql
INSERT INTO authz.relations (id, store_id, name) OVERRIDING SYSTEM VALUE VALUES
    ...
    (34, authz._s('demo'), 'can_manage'),
    (35, authz._s('demo'), 'can_archive');   -- new relation
```

2. **Add model rules** that define how the relation is resolved.
   Use the helper functions `authz._t()`, `authz._r()`, `authz._s()`, and the rule type
   helpers (`authz._rel_direct()`, `authz._rel_computed()`, `authz._rel_ttu()`):

```sql
-- Direct: users can be assigned 'can_archive' directly on a document
(authz._s('demo'), authz._t('demo', 'document'), authz._r('demo', 'can_archive'), authz._rel_direct(), NULL, NULL, NULL),

-- Computed: anyone with 'editor' also gets 'can_archive'
(authz._s('demo'), authz._t('demo', 'document'), authz._r('demo', 'can_archive'), authz._rel_computed(), authz._r('demo', 'editor'), NULL, NULL),

-- Tuple-to-userset: inherit 'can_archive' from the internal_data_space via 'in_internal_space'
(authz._s('demo'), authz._t('demo', 'document'), authz._r('demo', 'can_archive'), authz._rel_ttu(), NULL, authz._r('demo', 'in_internal_space'), authz._r('demo', 'can_edit')),
```

3. **Re-run init.sh** to reload the model:

```bash
./init.sh
```

4. **Add tests** in `tests/sql/tests.sql` or `tests/sql/tests_search.sql`, then run:

```bash
./tests/test.sh
```

### Adding a new type

1. **Register the type** in `examples/demo/model.sql`:

```sql
INSERT INTO authz.types (id, store_id, name) OVERRIDING SYSTEM VALUE VALUES
    ...
    (10, authz._s('demo'), 'upload_request'),
    (11, authz._s('demo'), 'audit_log');      -- new type
```

2. **Create a tuple partition** for the new type:

```sql
SELECT authz._ensure_tuple_partition(authz._s('demo'), 'audit_log');
```

3. **Define relations and model rules** for the new type (see above).

4. **Re-run init.sh**.

### Tuple partitioning

The `tuples` table is LIST-partitioned by `object_type`. Each object type
gets its own partition so that `check_access` queries benefit from partition
pruning — only the relevant partition is scanned.

Partitions are created automatically:
- For the demo model: via `_ensure_tuple_partition` calls in `examples/demo/model.sql`
- For imported OpenFGA models: `import_openfga_model` calls it for each type

For high-volume object types (e.g. millions of invoices), you can add a
second level of HASH sub-partitioning on `object_id`:

```sql
-- 4 hash buckets: spreads tuples across tuples_demo_invoice_0 .. tuples_demo_invoice_3
SELECT authz._ensure_tuple_partition(authz._s('demo'), 'invoice', 4);
```

This creates:
```
tuples (LIST by object_type)
  └── tuples_demo_invoice (HASH by object_id)
        ├── tuples_demo_invoice_0
        ├── tuples_demo_invoice_1
        ├── tuples_demo_invoice_2
        └── tuples_demo_invoice_3
```

Sub-partitioning reduces index size and lock contention per partition.
Choose a modulus that matches your expected data volume — 4 is a good
starting point, powers of 2 allow future splitting.

All partition management is idempotent — calling `_ensure_tuple_partition`
for a type that already has a partition is a no-op.

**Locking behavior:** creating a partition detaches and re-attaches the
default partition, which briefly takes an `ACCESS EXCLUSIVE` lock on the
partitioned table — concurrent reads and writes block for the duration.
The lock is short when the default partition holds few rows for the new
partition's key (rows must be migrated), but it is not free. A truly
non-blocking variant is not possible here: PostgreSQL forbids
`DETACH PARTITION ... CONCURRENTLY` whenever the partitioned table has a
default partition (and inside functions/procedures altogether), and the
default partition is what guarantees writes never fail for unpartitioned
keys.

Therefore, create partitions **ahead of need**, not lazily under load:

- **Tuple partitions:** call `_ensure_tuple_partition` when you register a
  new object type, while the type has no tuples yet.
- **Audit partitions:** keep the current and next month created via
  `ensure_audit_partitions()` (see below).

### Audit partition maintenance

`authz.ensure_audit_partitions(p_months_ahead int DEFAULT 1)` creates
monthly audit partitions for the current month plus N months ahead and
migrates any rows of those months out of the default partition. It is
idempotent (returns the number of partitions created) and granted to
`authz_admin`. `init.sh` runs it once at setup.

Schedule it so month rollovers never let rows accumulate in the default
partition — the default partition is only a fail-safe, and retention
(dropping old months) requires rows to live in their monthly partitions:

```bash
# External cron (daily):
0 3 * * *  psql "$AUTHZ_DB_URL" -c 'SELECT authz.ensure_audit_partitions()'
```

```sql
-- Or with the pg_cron extension, if installed:
SELECT cron.schedule('authz-audit-partitions', '0 3 * * *',
    $$SELECT authz.ensure_audit_partitions()$$);
```

Retention then becomes a cheap partition drop:

```sql
ALTER TABLE authz.tuples_audit DETACH PARTITION authz.tuples_audit_2025_01;
DROP TABLE authz.tuples_audit_2025_01;
```

### Suppressing the audit trail (DBA bulk operations)

There is deliberately **no API-level switch** to skip audit logging: the
audit trail is meant to be complete, and `audit_check_access` (time travel)
reconstructs past permissions by replaying it — any unlogged tuple change
silently corrupts historical answers. For maintenance jobs, prefer keeping
the audit rows and tagging them via `p_performed_by` (e.g.
`'cleanup_redundant_tuples'`) so they remain filterable.

The audit table is also structurally **append-only**: a trigger rejects
`UPDATE` always and `DELETE` outside of sanctioned maintenance (partition
row migration, and `delete_store(..., p_purge_audit => true)`). Retention
by detaching/dropping old monthly partitions is DDL and unaffected.
`delete_store` preserves the store's audit history by default.

If a bulk operation (large migration, store re-import) genuinely must skip
audit generation, a **superuser** can disable ordinary triggers — including
the audit trigger — for the **current session only**:

```sql
-- Superuser-only, affects only this session. Ordinary triggers
-- (including trg_tuples_audit) do not fire while this is set.
SET session_replication_role = replica;

-- ... bulk tuple changes without audit rows ...

SET session_replication_role = DEFAULT;
```

Caveats:

- Requires a real superuser connection. It is not reachable through the
  API roles or PostgREST — which is the intended barrier.
- Do **not** use `ALTER TABLE ... DISABLE TRIGGER` instead: that disables
  the trigger globally for all concurrent sessions until re-enabled.
- Changes made this way are invisible to `audit_check_access` — time-travel
  queries will not reflect them. Consider backfilling synthetic audit
  entries for the affected tuples if historical accuracy matters.

### Adding a conditional tuple

Conditions let you attach runtime constraints to tuples (time windows,
IP ranges, quotas, etc.). Conditions are scoped per store.

1. **Define the condition** (if it doesn't exist yet):

```sql
INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
(authz._s('demo'),
 'non_expired_grant',
 $$($1->>'current_time')::timestamptz
   < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval$$,
 '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
);
```

- `$1` = request context (passed at check time)
- `$2` = stored context (saved with the tuple)
- `required_context` is optional but recommended — it validates keys at
  write time and in `validate_condition()`

2. **Write the conditional tuple**:

```sql
SELECT authz.write_tuple('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    NULL, 'non_expired_grant',
    '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
);
```

3. **Check with context**:

```sql
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
);
-- => true (within the 2-hour window)
```

4. **Validate a condition** before writing (optional dry-run):

```sql
SELECT authz.validate_condition('demo',
    'non_expired_grant',
    '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb,
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb
);
-- => true (expression evaluates without error)
```

### Adding a new store

To run multiple authorization models in parallel (e.g. for testing or migration):

1. **Create the store**:

```sql
INSERT INTO authz.stores (name) VALUES ('v2');
```

2. **Register types and relations** for the new store, then **add model rules**:

```sql
-- Register types and relations (scoped to the new store)
INSERT INTO authz.types (store_id, name) VALUES (authz._s('v2'), 'internal_user'), (authz._s('v2'), 'document');
INSERT INTO authz.relations (store_id, name) VALUES (authz._s('v2'), 'can_read');
SELECT authz._ensure_tuple_partition(authz._s('v2'), 'document');

INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed) VALUES
(authz._s('v2'), authz._t('v2', 'document'), authz._r('v2', 'can_read'), authz._rel_direct(), NULL, NULL, NULL);
```

3. **Write tuples** to the new store:

```sql
SELECT authz.write_tuple('v2',
    'internal_user', 'alice', 'can_read', 'document', 'doc_001');
```

4. **Check access** in the new store:

```sql
SELECT authz.check_access('v2', 'internal_user', 'alice', 'can_read', 'document', 'doc_001');
```

Stores are fully isolated — types, relations, tuples, model rules, and conditions
in one store do not affect another.

## Data Model at a Glance

```
engagement
 +-- advisor, assistant, client
 +-- internal_collaborator = advisor or assistant
 +-- can_view = internal_collaborator or client

assignment (parent_engagement -> engagement)
 +-- accountant, payroll_clerk, tax_clerk, assistant
 +-- can_view = any role or internal_collaborator from parent_engagement
 +-- can_edit = accountant or payroll_clerk or tax_clerk

internal_data_space (parent_assignment -> assignment, parent_engagement -> engagement)
 +-- can_view = viewer or can_view from assignment or internal_collaborator from engagement
 +-- can_edit = editor or can_edit from assignment or advisor from engagement

client_data_space (parent_engagement -> engagement, client_org -> client_org)
 +-- client_member = direct_client_user or member from client_org
 +-- can_view / can_upload = client_member
 +-- can_manage_sharing = direct_internal_manager or can_manage_client_collaboration from engagement

document (in_internal_space -> internal_data_space, in_client_space -> client_data_space)
 +-- can_read = viewer or can_view from space
 +-- can_edit = editor or can_edit from internal_space
 +-- can_delete = can_manage_access from internal_space

upload_request (in_client_space -> client_data_space)
 +-- can_submit = requested_from
 +-- can_manage = created_by or can_manage_sharing from client_space
```

## Application Integration

### Where to check authorization

Check authorization **before** fetching data. If the user cannot access
a resource, don't waste time querying databases or calling downstream
services.

For resources that also require business-rule checks, use a two-phase
approach: structural check first (cheap, no data needed), then
business-rule check after fetching the resource.

### Spring Boot example (AuthZEN via HTTP)

Call the AuthZEN API from a Spring Boot controller. The structural
permission check runs before any data fetching:

```java
@RestController
@RequestMapping("/documents")
public class DocumentController {

    private final AuthZenClient authz;
    private final DocumentService documents;

    @GetMapping("/{id}")
    public Document getDocument(@PathVariable String id, JwtAuthenticationToken jwt) {
        // 1. Structural check — cheap, no data needed
        //    Calls POST /access/v1/evaluation on authzen-direct or authzen-opa
        if (!authz.checkAccess(jwt, "can_read", "document", id)) {
            throw new AccessDeniedException("Access denied");
        }

        // 2. Fetch data — only reached if authorized
        Document doc = documents.findById(id);

        return doc;
    }

    @PostMapping("/{id}/approve")
    public void approve(@PathVariable String id, JwtAuthenticationToken jwt) {
        // 1. Structural check
        if (!authz.checkAccess(jwt, "can_approve", "document", id)) {
            throw new AccessDeniedException("Access denied");
        }

        // 2. Fetch data
        Document doc = documents.findById(id);

        // 3. Business-rule check — needs application data
        if (doc.getAmount().compareTo(currentUser.getApprovalLimit()) > 0) {
            throw new AccessDeniedException("Amount exceeds approval limit");
        }
        if (!doc.getStatus().equals("pending")) {
            throw new IllegalStateException("Document is not pending approval");
        }

        documents.approve(doc);
    }
}
```

The `AuthZenClient` wraps the HTTP call to the AuthZEN evaluation endpoint:

```java
@Component
public class AuthZenClient {

    private final RestClient rest;

    public AuthZenClient(@Value("${authzen.url}") String baseUrl) {
        this.rest = RestClient.builder().baseUrl(baseUrl).build();
    }

    public boolean checkAccess(JwtAuthenticationToken jwt,
                               String action, String resourceType, String resourceId) {
        var body = Map.of(
            "subject", Map.of("type", subjectType(jwt), "id", subjectId(jwt)),
            "action",  Map.of("name", action),
            "resource", Map.of("type", resourceType, "id", resourceId)
        );

        var resp = rest.post()
            .uri("/access/v1/evaluation")
            .header("Authorization", "Bearer " + jwt.getToken().getTokenValue())
            .body(body)
            .retrieve()
            .body(EvalResponse.class);

        return resp != null && resp.decision();
    }

    private String subjectId(JwtAuthenticationToken jwt) {
        String name = jwt.getToken().getClaimAsString("preferred_username");
        return name != null ? name : jwt.getToken().getSubject();
    }

    private String subjectType(JwtAuthenticationToken jwt) {
        String type = jwt.getToken().getClaimAsString("subject_type");
        return type != null ? type : "internal_user";
    }

    record EvalResponse(boolean decision) {}
}
```

Configure in `application.yml`:

```yaml
authzen:
  url: http://localhost:8090   # authzen-direct (or 8091 for authzen-opa)
```

### Direct SQL example (JDBC / pgx)

For applications that connect directly to PostgreSQL, call the SQL
function without the HTTP layer:

```java
// Spring JdbcTemplate
boolean allowed = jdbc.queryForObject(
    "SELECT authz.check_access(?, ?, ?, ?, ?, ?)",
    Boolean.class,
    "demo", "internal_user", userId, "can_read", "document", docId
);
```

```go
// Go pgx
var allowed bool
err := pool.QueryRow(ctx,
    "SELECT authz.check_access($1, $2, $3, $4, $5, $6)",
    "demo", "internal_user", userID, "can_read", "document", docID,
).Scan(&allowed)
```

## Write API (OPA-fronted)

The read path (OPA / AuthZEN) handles authorization checks. Tuple **writes**
go through the **same front door**: OPA verifies the JWT, requires the
configured writer role, and forwards the operation to a PostgREST **writer**
instance that runs as a fixed `authz_writer` role and is reachable only by OPA.

```
Read path  (authorization checks):
Application ──▶ OPA / AuthZEN ──▶ PostgREST (reader, :3000) ──▶ PG

Write path (tuple management):
Application ──▶ OPA (:8181, POST /v1/data/authz/write)
                 │ verifies JWT + writer role
                 ▼
              PostgREST-writer (fixed authz_writer, internal) ──▶ PG
```

There is **no** host-exposed write endpoint and **no** Nginx gateway — the
writer has no host port and does no JWT verification of its own. (Earlier
versions put an Nginx gateway + JWT-verifying writer on `:3001`; that's removed
— see [ARCHITECTURE.md ADR-6](ARCHITECTURE.md).)

### Write authorization

OPA verifies the JWT (ES256 against the issuer's JWKS, like the read path) and
requires the configured **writer role** to appear in the JWT's **roles claim**.
Both are configurable on the OPA service:

| Env var | Default | Meaning |
|---|---|---|
| `JWT_ROLES_CLAIM` | `roles` | Dotted path to the roles array in the token (e.g. `realm_access.roles` for Keycloak) |
| `WRITER_ROLE` | `authz_writer` | Role value that authorizes tuple writes |
| `POSTGREST_WRITER_URL` | *(unset)* | Writer instance OPA forwards to. **Unset ⇒ writes disabled** (read-only deployment) |

The Postgres role is **not** taken from the token — the writer always runs as
`authz_writer`, so a forged or over-scoped role claim cannot reach admin
operations. A token that authorizes writes (with the default config):

```json
{
  "preferred_username": "svc-docs",
  "subject_type": "internal_user",
  "roles": ["authz_writer"],
  "iss": "https://auth.example.com",
  "aud": "authz-api",
  "exp": 1710003600
}
```

### The write endpoint

`POST /v1/data/authz/write` with an OPA `{"input": {...}}` envelope. The
`operation` field selects the action:

| `operation` | Payload field | Maps to |
|---|---|---|
| `write` / `delete` | `tuple` (object) | `write_tuple` / `delete_tuple` |
| `write_batch` / `delete_batch` | `tuples` (array) | `write_tuples_jsonb` / `delete_tuples_jsonb` |
| `delete_user` | `user` (`{user_type, user_id}`) | `delete_user_tuples` (offboarding) |

A tuple object is `{user_type, user_id, relation, object_type, object_id}` plus
optional `user_relation` and (writes only) `condition` + `condition_context`.
`store` is optional (defaults to OPA's `DEFAULT_STORE`). The authenticated
subject is recorded as the audit author (`performed_by`).

```bash
TOKEN=...   # JWT whose roles claim contains authz_writer

# Single write
curl -sX POST http://localhost:8181/v1/data/authz/write \
  -H "Content-Type: application/json" \
  -d '{"input":{"token":"'"$TOKEN"'","store":"demo","operation":"write",
        "tuple":{"user_type":"internal_user","user_id":"alice","relation":"viewer",
                 "object_type":"document","object_id":"doc_new_001"}}}'
# => {"result":{"allowed":true,"result":{"status":200,"body":true}}}

# Batch write (body = number of tuples inserted)
curl -sX POST http://localhost:8181/v1/data/authz/write \
  -H "Content-Type: application/json" \
  -d '{"input":{"token":"'"$TOKEN"'","store":"demo","operation":"write_batch",
        "tuples":[
          {"user_type":"internal_user","user_id":"alice","relation":"viewer","object_type":"document","object_id":"doc_001"},
          {"user_type":"internal_user","user_id":"bob","relation":"editor","object_type":"document","object_id":"doc_001"}
        ]}}'
# => {"result":{"allowed":true,"result":{"status":200,"body":2}}}

# Offboarding — remove every tuple for a subject
curl -sX POST http://localhost:8181/v1/data/authz/write \
  -H "Content-Type: application/json" \
  -d '{"input":{"token":"'"$TOKEN"'","store":"demo","operation":"delete_user",
        "user":{"user_type":"internal_user","user_id":"alice"}}}'
```

Outcomes:

| Result | Meaning |
|---|---|
| `{"allowed":true,"result":{"status":200,"body":…}}` | applied; `body` is the function return (boolean, or the affected count for batch) |
| `{"allowed":false,"error":"not_authorized"}` | missing/invalid token, or roles claim lacks `WRITER_ROLE` |
| `{"allowed":false,"error":"invalid_request"}` | authorized, but malformed `operation` / `tuple` / `tuples` / `user` |
| `{"allowed":false,"error":"writes_disabled"}` | no `POSTGREST_WRITER_URL` configured (read-only deployment) |

### Admin / model operations

Store lifecycle (`create_store`/`delete_store`), model evolution (`model_*`),
namespace management, and OpenFGA import are **not** exposed over OPA — they
require `authz_admin` and are run via **direct SQL** (or your own admin
tooling), not the public write API. See [direct SQL](#via-direct-sql-jdbc).

### Compose configuration

The writer + OPA wiring ships **enabled** in `compose.yml`:

```yaml
postgrest-writer:
  image: postgrest/postgrest:v14.13
  environment:
    PGRST_DB_URI: postgres://authz_authenticator:${AUTHZ_AUTHENTICATOR_PASSWORD:-authz}@authz-db:5432/authz
    PGRST_DB_ANON_ROLE: authz_writer   # fixed role; NO JWT verification
    PGRST_DB_SCHEMAS: authz
    PGRST_DB_POOL: "20"
    PGRST_SERVER_PORT: "3001"
  expose:
    - "3001"            # internal only — reachable solely by OPA

opa:
  environment:
    POSTGREST_WRITER_URL: "http://postgrest-writer:3001"
    # JWT_ROLES_CLAIM: "realm_access.roles"   # default: roles
    # WRITER_ROLE: "authz_writer"             # default
```

> **Serialization failures under concurrent writes.** As of PostgREST 14,
> PostgREST no longer automatically retries transactions that fail with a
> serialization error (`SQLSTATE 40001`); the error surfaces to the
> caller instead. pgauthz writes are single-statement RPC calls and the
> workload is read-dominant, so `40001` is rare — but a client driving
> heavy concurrent writes (or running against `SERIALIZABLE`/`REPEATABLE
> READ` replicas) should be prepared to catch `40001` and retry the call
> itself. (Earlier PostgREST versions retried transparently.)

### Operations reference

All tuple writes go through `POST /v1/data/authz/write` (above). The `operation`
maps to a SQL function:

| Operation | SQL function | `body` returns |
|---|---|---|
| `write` | `write_tuple` | boolean (created?) |
| `delete` | `delete_tuple` | boolean (deleted?) |
| `write_batch` | `write_tuples_jsonb` | count inserted (duplicates skipped) |
| `delete_batch` | `delete_tuples_jsonb` | count deleted |
| `delete_user` | `delete_user_tuples` | count removed |

**Admin / model operations** require `authz_admin` and are **direct SQL only**
(not exposed over OPA):

| Function | Purpose |
|---|---|
| `create_store` / `delete_store` | Store lifecycle |
| `model_register_type` / `model_register_relation` | Register types / relations |
| `model_add_rule` / `model_remove_rule` / `model_remove_rules` | Model-rule management |
| `import_openfga_model` / `import_openfga_tuples` | OpenFGA import |
| `grant_namespace_access` / `revoke_namespace_access` | Namespace access |
| `find_redundant_tuples` / `cleanup_redundant_tuples` | Redundant-tuple maintenance |

### Integration patterns

#### Direct call (simplest)

Call the write API synchronously after the local transaction commits:

```
Application:
  1. BEGIN
  2. INSERT INTO documents (id, ...) VALUES ('doc_123', ...);
  3. COMMIT
  4. POST /v1/data/authz/write → OPA → writer → PG primary
```

Simple, but if step 4 fails, the document exists without the permission
grant. Acceptable when the application can retry.

#### Outbox pattern (recommended)

Write the authorization change into an outbox table within the same
local transaction. A separate processor reads the outbox and calls the
write API:

```
Application (single transaction):
  1. INSERT INTO documents (id, ...) VALUES ('doc_123', ...);
  2. INSERT INTO outbox (event_type, payload)
     VALUES ('authz_update', '{"action":"write_tuple",...}');
  COMMIT;

Outbox processor (async):
  3. Read from outbox → POST /v1/data/authz/write (OPA) → mark as processed
```

No distributed transactions. The outbox processor retries on failure.
All write functions are idempotent, so replaying the same event is safe.

#### Message broker (Kafka, RabbitMQ, etc.)

For event-driven architectures, publish authorization changes to a topic.
A consumer calls the write API:

```
Application ──▶ Kafka topic ──▶ Consumer ──▶ OPA ──▶ writer ──▶ PG primary
```

Partition by `(object_type, object_id)` to preserve ordering per
resource.

#### Read-after-write consistency

Reads on the primary (the default, non-replicated stack) are always
read-your-writes — MVCC makes every committed grant/revoke immediately
visible. With read replicas, streaming replication is asynchronous, so a
write may not be visible on a replica for a few milliseconds. The
security-relevant case is a **stale allow after a revoke**: a check routed
to a lagging replica can still return `allowed` until the revoke
replicates (a stale *deny* after a grant is only an availability hiccup).
See the "Consistency model" section in the README for the full contract.

If a check must reflect a just-committed change, either:

- **Route the confirming check to the primary** (bypass the replica) — the
  simplest correct option, and the one to use for revocations
- Accept eventual consistency (sub-second lag is fine for most workloads)
- Pin the replica read manually: capture `pg_current_wal_lsn()` on the
  primary **just after the write commits** (a value read inside the write
  is pre-commit and unsound — see ARCHITECTURE.md), then wait until the
  replica's `pg_last_wal_replay_lsn()` reaches it before reading (a manual
  stand-in for a Zanzibar revision token)

### Writing tuples from Spring Boot

When your application creates resources or changes ownership, it needs to
write authorization tuples. Use the OPA write endpoint (which verifies the JWT
and forwards to the writer) or direct SQL.

**Via OPA (HTTP):** POST `/v1/data/authz/write` with an `{"input": {...}}`
envelope. Pass the caller's JWT (its roles claim must contain the writer role);
OPA records the subject as the audit author.

```java
@Component
public class AuthZWriter {

    private final RestClient rest;

    public AuthZWriter(@Value("${authz.opa-url}") String opaUrl) {
        this.rest = RestClient.builder().baseUrl(opaUrl).build();
    }

    /** Grant a relation on a resource to a subject. */
    public void writeTuple(String token, String store, String userType, String userId,
                           String relation, String objectType, String objectId) {
        send(token, store, "write", "tuple", tuple(userType, userId, relation, objectType, objectId));
    }

    /** Write multiple tuples in a single round-trip. Returns the number inserted. */
    public int writeTuples(String token, String store, List<Map<String, String>> tuples) {
        return count(send(token, store, "write_batch", "tuples", tuples));
    }

    /** Revoke a relation. */
    public void deleteTuple(String token, String store, String userType, String userId,
                            String relation, String objectType, String objectId) {
        send(token, store, "delete", "tuple", tuple(userType, userId, relation, objectType, objectId));
    }

    /** Remove all tuples for a user (offboarding). */
    public void deleteUserTuples(String token, String store, String userType, String userId) {
        send(token, store, "delete_user", "user",
             Map.of("user_type", userType, "user_id", userId));
    }

    private static Map<String, String> tuple(String userType, String userId, String relation,
                                              String objectType, String objectId) {
        return Map.of("user_type", userType, "user_id", userId, "relation", relation,
                      "object_type", objectType, "object_id", objectId);
    }

    private WriteResponse send(String token, String store, String operation,
                               String payloadKey, Object payload) {
        var input = new HashMap<String, Object>();
        input.put("token", token);
        input.put("store", store);
        input.put("operation", operation);
        input.put(payloadKey, payload);

        var resp = rest.post()
            .uri("/v1/data/authz/write")
            .body(Map.of("input", input))
            .retrieve()
            .body(WriteResponse.class);

        if (resp == null || resp.result() == null || !resp.result().allowed()) {
            throw new IllegalStateException("authz write denied: " +
                (resp != null && resp.result() != null ? resp.result().error() : "no response"));
        }
        return resp;
    }

    private int count(WriteResponse resp) {
        var fwd = resp.result().result();
        return fwd != null && fwd.body() instanceof Number n ? n.intValue() : 0;
    }

    // OPA wraps the policy decision under "result".
    record WriteResponse(Decision result) {
        record Decision(boolean allowed, String error, Forward result) {}
        record Forward(int status, Object body) {}
    }
}
```

Usage in a service:

```java
@Service
public class DocumentService {

    private final AuthZWriter authzWriter;
    private final DocumentRepository repo;

    /** Create a document and grant the creator edit + read access.
     *  `token` is the caller's JWT (its roles claim carries the writer role). */
    @Transactional
    public Document create(String token, String title, String creatorId) {
        Document doc = repo.save(new Document(title));

        // Grant the creator ownership via authorization tuples
        authzWriter.writeTuples(token, "demo", List.of(
            Map.of("user_type", "internal_user", "user_id", creatorId,
                   "relation", "owner", "object_type", "document",
                   "object_id", doc.getId()),
            Map.of("user_type", "internal_user", "user_id", creatorId,
                   "relation", "editor", "object_type", "document",
                   "object_id", doc.getId())
        ));

        return doc;
    }

    /** Share a document with another user. */
    public void share(String token, String docId, String userId, String relation) {
        authzWriter.writeTuple(token, "demo",
            "internal_user", userId, relation, "document", docId);
    }

    /** Revoke a user's access to a document. */
    public void unshare(String token, String docId, String userId, String relation) {
        authzWriter.deleteTuple(token, "demo",
            "internal_user", userId, relation, "document", docId);
    }
}
```

Configure in `application.yml`:

```yaml
authz:
  opa-url: http://localhost:8181      # OPA — read checks AND the write endpoint
  # AuthZEN read API (alternative to calling OPA directly):
  #   http://localhost:8090 (authzen-direct) / :8091 (authzen-opa)
```

**Via direct SQL (JDBC):**

```java
// Single tuple
jdbc.update(
    "SELECT authz.write_tuple(?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)",
    "demo", "internal_user", userId, "owner", "document", docId, "document-service"
);

// Batch (faster — single INSERT)
jdbc.queryForObject(
    "SELECT authz.write_tuples(?, ?::authz.tuple_input[], ?)",
    Integer.class,
    "demo",
    new Object[]{new String[]{"internal_user", userId, null, "editor", "document", docId}},
    "document-service"
);

// Delete all tuples for a user (offboarding)
jdbc.update(
    "SELECT authz.delete_user_tuples(?, ?, ?, ?)",
    "demo", "internal_user", userId, "offboarding"
);
```

### Downstream services

Each service in the call chain should independently verify access
(defense in depth). The calling service checking first avoids
unnecessary network round-trips when access is denied, but the
downstream service should not trust the caller blindly. Forward the
JWT so each service can verify independently.

## Debugging

### Trace which tuples exist for an object

```sql
SELECT t.*, ty.name AS user_type_name, r.name AS relation_name
  FROM authz.tuples t
  JOIN authz.types ty ON ty.id = t.user_type
  JOIN authz.relations r ON r.id = t.relation
 WHERE t.store_id    = authz._s('demo')
   AND t.object_type = authz._t('demo', 'document')
   AND t.object_id = 'doc_payroll_001';
```

### List all model rules for a type

```sql
SELECT relation, rule_type, computed_relation, tupleset_relation, tupleset_computed
  FROM authz.models_view
 WHERE store = 'demo'
   AND object_type = 'document'
 ORDER BY relation, rule_type;
```

### See all permissions a user has (quick audit)

```sql
-- All actions user has on a specific object
SELECT * FROM authz.list_actions('demo', 'internal_user', 'bob', 'document', 'doc_payroll_001');

-- All objects of a type user can access
SELECT * FROM authz.list_objects('demo', 'internal_user', 'bob', 'can_read', 'document');
```
