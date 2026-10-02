# Use cases

An index of what pgauthz is used for: the ask in plain words, how you would
express it, and where it is shown in full. Each sketch is deliberately short:
the model as the pgauthz calls that build it (`model_add_rule`,
`model_add_type_restriction`, `add_gate`; types and relations are assumed
registered), then the one or two calls that matter. `describe_model`
renders any store as OpenFGA-style DSL for review. The linked owner has the
complete, tested version. Grouped from simple to advanced; real systems
combine several.

## Contents

- [Simple](#simple)
  - [Direct and computed relations — editors write, viewers read](#direct-and-computed-relations--editors-write-viewers-read)
  - [Computed chains, usersets, tuple-to-userset — role hierarchies without role explosion](#computed-chains-usersets-tuple-to-userset--role-hierarchies-without-role-explosion)
  - [Subject wildcard — public or anonymous access](#subject-wildcard--public-or-anonymous-access)
  - [Tuple expiry — a grant that ends by itself](#tuple-expiry--a-grant-that-ends-by-itself)
- [Common](#common)
  - [Recursive tuple-to-userset — share a folder, everything inside follows](#recursive-tuple-to-userset--share-a-folder-everything-inside-follows)
  - [Conditions (ABAC) — only from the office network, only in business hours](#conditions-abac--only-from-the-office-network-only-in-business-hours)
  - [Conditional object wildcard, intersection, detailed check — deny from unmanaged devices, fail closed when you don't know](#conditional-object-wildcard-intersection-detailed-check--deny-from-unmanaged-devices-fail-closed-when-you-dont-know)
  - [Rule groups: intersection and exclusion — delete your own items unless you're admin; blocked members can't edit](#rule-groups-intersection-and-exclusion--delete-your-own-items-unless-youre-admin-blocked-members-cant-edit)
  - [Object wildcard — an auditor who sees every document, now and in future](#object-wildcard--an-auditor-who-sees-every-document-now-and-in-future)
  - [Checked writes — who may share, and never more than they hold](#checked-writes--who-may-share-and-never-more-than-they-hold)
  - [Marker tuples and exclusion — archived, under legal hold, draft only](#marker-tuples-and-exclusion--archived-under-legal-hold-draft-only)
  - [Object wildcard, bulk delete, expiry — suspended, offboarded, break-glass](#object-wildcard-bulk-delete-expiry--suspended-offboarded-break-glass)
  - [Search API as a JOIN — show me only what I may see](#search-api-as-a-join--show-me-only-what-i-may-see)
  - [Time travel and the audit trail — could Grace read payroll last Tuesday, and who revoked it?](#time-travel-and-the-audit-trail--could-grace-read-payroll-last-tuesday-and-who-revoked-it)
  - [Changefeed — react to changes: cache invalidation, sync](#changefeed--react-to-changes-cache-invalidation-sync)
  - [Policy hooks (OPA) — an org-wide rule that narrows but never widens](#policy-hooks-opa--an-org-wide-rule-that-narrows-but-never-widens)
  - [Store per tenant, tuple-to-userset — one user in several workspaces](#store-per-tenant-tuple-to-userset--one-user-in-several-workspaces)
  - [Namespaces — per-application isolation inside one store](#namespaces--per-application-isolation-inside-one-store)
  - [Model registry and model-as-code — one model, many tenants](#model-registry-and-model-as-code--one-model-many-tenants)
  - [Typed service principals — jobs, exporters, and acting on behalf of a user](#typed-service-principals--jobs-exporters-and-acting-on-behalf-of-a-user)
  - [OpenFGA import — "we already have an OpenFGA model"](#openfga-import--we-already-have-an-openfga-model)
  - [Policies as data — "our policies are already in Cedar"](#policies-as-data--our-policies-are-already-in-cedar)
- [Advanced](#advanced)
  - [Temporal gates: count_within, sum_within — rate limits and spend caps](#temporal-gates-count_within-sum_within--rate-limits-and-spend-caps)
  - [Temporal gates: formerly_within — prior approval, step-up freshness](#temporal-gates-formerly_within--prior-approval-step-up-freshness)
  - [Temporal gates: object scope, count_distinct_within — separation of duties, four-eyes](#temporal-gates-object-scope-count_distinct_within--separation-of-duties-four-eyes)
  - [Temporal gates over denials — lockout after repeated denials](#temporal-gates-over-denials--lockout-after-repeated-denials)
  - [Calendar windows and object scope — daily quotas, per user and per file](#calendar-windows-and-object-scope--daily-quotas-per-user-and-per-file)
  - [reserve_event — exact caps under concurrency](#reserve_event--exact-caps-under-concurrency)
  - [Shadow mode — roll a new rule out without changing a decision](#shadow-mode--roll-a-new-rule-out-without-changing-a-decision)
  - [Expiring or contextual tuples, intersection — an AI agent may only work on this task's customer](#expiring-or-contextual-tuples-intersection--an-ai-agent-may-only-work-on-this-tasks-customer)
  - [Sequencing gates — email only after a summary exists; at most N tool calls an hour](#sequencing-gates--email-only-after-a-summary-exists-at-most-n-tool-calls-an-hour)
  - [Delegation with attenuation, checked writes — subagents never exceed their parent](#delegation-with-attenuation-checked-writes--subagents-never-exceed-their-parent)
  - [Type restrictions — guard the control plane by absence](#type-restrictions--guard-the-control-plane-by-absence)
  - [Authorize before retrieval — RAG](#authorize-before-retrieval--rag)
- [All four at once](#all-four-at-once)

## Simple

### Direct and computed relations — editors write, viewers read

**Scenario:** Alice edits the readme and Bob may only read it. The "roles"
belong to the document, not to the people.

**Solution:** What RBAC calls a role is here a relation between a subject and one
resource: `alice → editor → document:readme` says what alice may do with
*this* document, not what kind of user she is. `viewer` and `editor` name
capabilities on the resource type; permissions are computed from them;
assigning one is a tuple, revoking it a delete, both audited. A global role
in the RBAC sense (an admin everywhere) is a different shape — an object
wildcard, or a role object whose members are a userset — covered by the
hierarchy and auditor entries below.

```sql
SELECT authz.model_add_rule('helloworld', 'document', 'viewer',    'direct');
SELECT authz.model_add_rule('helloworld', 'document', 'editor',    'direct');
SELECT authz.model_add_rule('helloworld', 'document', 'can_read',  'computed', 'viewer');
SELECT authz.model_add_rule('helloworld', 'document', 'can_read',  'computed', 'editor');
SELECT authz.model_add_rule('helloworld', 'document', 'can_write', 'computed', 'editor');

SELECT authz.write_tuple('helloworld', 'user', 'alice', 'editor', 'document', 'readme');
SELECT authz.check_access('helloworld', 'user', 'bob', 'can_write', 'document', 'readme');  -- false
```
Shown in: the README's [complete example](../README.md#a-complete-example),
[`examples/models/helloworld/`](../examples/models/helloworld).

### Computed chains, usersets, tuple-to-userset — role hierarchies without role explosion

**Scenario:** GitHub-style repository roles: admins can do what writers can,
writers what readers can; whole teams get a role at once; an organisation's
admins are admins of every repo it owns. In RBAC that is a role per repo per
level, multiplied by teams.

**Solution:** Three model constructs, each one line of model.

**1. The chain.** Each level *implies* the one below it, as a computed
relation on the same object. Granting `admin` once makes the subject a
`writer` and a `reader` without further tuples.

```sql
SELECT authz.model_add_rule('github', 'repo', 'reader', 'direct');
SELECT authz.model_add_rule('github', 'repo', 'writer', 'direct');
SELECT authz.model_add_rule('github', 'repo', 'admin',  'direct');
SELECT authz.model_add_rule('github', 'repo', 'writer', 'computed', 'admin');    -- every admin is a writer
SELECT authz.model_add_rule('github', 'repo', 'reader', 'computed', 'writer');   -- every writer is a reader
```

**2. Teams as grantees.** A type restriction says a role may be held by a
single user *or* by a userset, `team#member`: everyone who is a member of
that team, now and later. One tuple grants the whole team; membership
changes need no further writes on the repo.

```sql
SELECT authz.model_add_type_restriction('github', 'repo', 'writer', 'user');
SELECT authz.model_add_type_restriction('github', 'repo', 'writer', 'team', p_allowed_user_relation => 'member');

SELECT authz.write_tuple('github', 'team', 'eng', 'writer', 'repo', 'api', p_user_relation => 'member');
```

**3. Roles that flow down from the owner.** The third construct is the
*tuple-to-userset* rule, the one that makes relationships compose across
objects. It has two parts: a **tupleset** relation, which is a link from
this object to another one (`repo → owner → organization:acme` is an
ordinary tuple), and a **computed** relation, which is read on the object
the link points to. The rule says: *to decide `admin` on this repo, follow
the repo's `owner` link, and whoever holds `repo_admin` on that
organisation holds `admin` here.* "Userset" is the name for that set of
subjects on the linked object (everyone who is `repo_admin` of
`organization:acme`). Give someone `repo_admin` on the org once and they
are admin of every repo the org owns, including repos created tomorrow;
move a repo to another org and its admins change with one tuple.

```sql
SELECT authz.model_add_rule('github', 'repo', 'owner', 'direct');
SELECT authz.model_add_rule('github', 'repo', 'admin', 'ttu',
    p_tupleset_relation => 'owner',          -- follow repo → owner
    p_tupleset_computed => 'repo_admin');    -- … and take the org's repo_admin
```

A check such as *can dave read repo:api?* walks all three: dave is a member
of `team:eng`, the team is a `writer` of the repo, and every writer is a
`reader`. `explain_access` shows exactly that path.

Shown in: [`examples/models/github/`](../examples/models/github) (imported
from an OpenFGA JSON model, with the full five-level hierarchy and nested
teams).

### Subject wildcard — public or anonymous access

**Scenario:** A public folder, a "share with anyone who has the link"
document, an anonymous read.

**Solution:** Instead of a tuple per user, one tuple whose subject id is
`*` grants the relation to every subject of that type, present and future.
It behaves like any other tuple: computed relations and folder inheritance
carry it down, an exclusion can still subtract a specific user, a condition
or `expires_at` can bound it, and searches report it as a typed wildcard row
rather than enumerating everyone. The model must allow it: the relation's
type restriction opts in with `p_allow_wildcard`.

```sql
-- the model opts in: viewers of a folder may be "any user"
SELECT authz.model_add_type_restriction('gdrive', 'folder', 'viewer', 'user', p_allow_wildcard => true);

-- everyone can view the public folder (and, via inheritance, what is in it)
SELECT authz.write_tuple('gdrive', 'user', '*', 'viewer', 'folder', 'public');

SELECT authz.check_access('gdrive', 'user', 'anyone', 'can_read', 'doc', 'announcement');   -- true
SELECT * FROM authz.list_subjects('gdrive', 'user', 'viewer', 'folder', 'public');
--  subject_id | is_wildcard
--  *          | t            ← "all users", not a list of them
--  alice      | f            ← plus anyone who also holds it by name or inheritance
--  charlie    | f
```
Shown in: [`examples/models/gdrive/`](../examples/models/gdrive),
[MODEL_DESIGN → Wildcard tuples](MODEL_DESIGN.md#wildcard-tuples-public-access).

### Tuple expiry — a grant that ends by itself

**Scenario:** A contractor needs access for 30 days, a reviewer until the
end of the quarter. Nobody should have to remember to revoke it.

**Solution:** Expiry is a column on the tuple, judged by the server clock on every check,
search and time-travel path, and garbage-collected with its audit history.
`p_expires_at` is an ordinary `timestamptz` parameter, so the deadline is
whatever SQL expression computes it — no date arithmetic in the application,
no second clock to keep in sync, and the same value for every replica:

```sql
-- a contractor for 30 days
SELECT authz.write_tuple('demo', 'internal_user', 'carol', 'viewer', 'document', 'plan',
    p_expires_at => now() + interval '30 days');

-- until the end of the quarter
SELECT authz.write_tuple('demo', 'internal_user', 'carol', 'viewer', 'document', 'forecast',
    p_expires_at => date_trunc('quarter', now()) + interval '3 months');

-- until midnight tonight, Berlin time
SELECT authz.write_tuple('demo', 'internal_user', 'carol', 'viewer', 'document', 'agenda',
    p_expires_at => (date_trunc('day', now() AT TIME ZONE 'Europe/Berlin') + interval '1 day')
                    AT TIME ZONE 'Europe/Berlin');

-- as long as the contract in your own table runs (co-located: one transaction)
SELECT authz.write_tuple('demo', 'internal_user', 'carol', 'viewer', 'document', 'sow',
    p_expires_at => (SELECT ends_at FROM contracts WHERE id = 4711));
```

Re-granting the same tuple with a new `p_expires_at` extends it in place
(an upsert, one audit event); a deadline already in the past is rejected
rather than stored dead. Over HTTP the same field is `expires_at` on the
write body, as an ISO timestamp.
Shown in: [MODEL_DESIGN → Representing expiration](MODEL_DESIGN.md#representing-expiration--which-tool)
(when to use expiry, a condition, a scheduled delete, or a contextual tuple).

## Common

### Recursive tuple-to-userset — share a folder, everything inside follows

**Scenario:** Google-Drive-style sharing: give someone access to a folder
and they can read every document in it, in every subfolder, however deep —
and when a document is moved into another folder, its access changes with it.

**Solution:** Nothing is copied down the tree; the engine walks up it at
check time. Three rules.

**1. The tree is tuples.** A folder's `parent` is a link to another folder,
and a document's `parent` is a link to the folder it lives in. Both are
ordinary tuples, written when the object is created or moved.

```sql
SELECT authz.model_add_rule('gdrive', 'folder', 'parent', 'direct');   -- folder → parent folder
SELECT authz.model_add_rule('gdrive', 'doc',    'parent', 'direct');   -- doc → its folder

SELECT authz.write_tuple('gdrive', 'folder', 'root',     'parent', 'folder', 'projects');
SELECT authz.write_tuple('gdrive', 'folder', 'projects', 'parent', 'doc',    'plan');
```

**2. A folder is viewable by its own viewers, or by whoever may view its
parent.** The second rule is the recursive one: `can_view` on a folder is
defined in terms of `can_view` on the parent folder, so the walk continues
up until it finds a grant or runs out of parents (cycles are detected and
pruned).

```sql
SELECT authz.model_add_rule('gdrive', 'folder', 'viewer',   'direct');                 -- shared with me directly
SELECT authz.model_add_rule('gdrive', 'folder', 'can_view', 'computed', 'viewer');     -- … or
SELECT authz.model_add_rule('gdrive', 'folder', 'can_view', 'ttu',                     -- … whoever can view my parent
    p_tupleset_relation => 'parent', p_tupleset_computed => 'can_view');
```

**3. A document reads through its folder.** Same shape, one level: a doc
can be read by its own viewers, or by whoever can view the folder it is in.

```sql
SELECT authz.model_add_rule('gdrive', 'doc', 'viewer',   'direct');
SELECT authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed', 'viewer');
SELECT authz.model_add_rule('gdrive', 'doc', 'can_read', 'ttu',
    p_tupleset_relation => 'parent', p_tupleset_computed => 'can_view');
```

Now share the top folder once:

```sql
SELECT authz.write_tuple('gdrive', 'user', 'ann', 'viewer', 'folder', 'root');

SELECT authz.check_access('gdrive', 'user', 'ann', 'can_read', 'doc', 'plan');   -- true:
-- plan → parent projects → parent root, where ann is a viewer (three hops)
```

What this costs in writes: sharing a folder is one tuple, however many
documents it holds; renaming anything is zero (ids are stable); moving a
document or a subfolder is one tuple (its `parent`). A 15-level chain
resolves in a few milliseconds; the walk is memoised, so a document reachable
through several branches is not re-resolved per branch.

Shown in: [`examples/models/gdrive/`](../examples/models/gdrive),
[MODEL_DESIGN → Recursive hierarchies](MODEL_DESIGN.md#14-recursive-hierarchies--folders--filesystems)
(which folders to store, moves and renames, the contextual-tuple alternative).

### Conditions (ABAC) — only from the office network, only in business hours

**Scenario:** Bob may read the payroll report, but only from the office
network and during business hours.

**Solution:** The grant itself is a relationship; the two
constraints are attributes of the *request*, so they go on a **condition**
attached to the tuple and evaluated at check time.

A condition is a named boolean expression over two JSON documents: the
**request context** the caller sends with the check (client address, time,
device…), and the **stored context** saved with the tuple when it was
written (the allowed network, a grant time…). A tuple carries one condition;
`required_context` declares which keys each side must provide.

**1. SQL conditions.** The default language. `$1` is the request context,
`$2` the stored context, and the expression is any SQL boolean (run in a
zero-privilege sandbox). Start with one idea per condition. `current_time`
is the **server's** clock by default: the engine sets it itself, so a caller
can neither forget it nor backdate it (pass `p_time_source => 'caller'` when
the request legitimately asserts a time, as tests and demos do).

```sql
-- business hours: the time of day is between 8 and 17 — by the server's clock
SELECT authz.create_condition_sql('demo', 'office_hours',
    $$ extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17 $$,
    '{"request": ["current_time"]}');

-- office network: the request's address is inside the network stored with the grant
SELECT authz.create_condition_sql('demo', 'office_network',
    $$ ($1->>'client_ip')::inet <<= ($2->>'allowed_cidr')::cidr $$,
    '{"request": ["client_ip"], "stored": ["allowed_cidr"]}');
```

**2. The same in CEL.** With the optional `pg_cel` evaluator a condition can
be written in CEL; the two contexts are the `request.*` and `stored.*`
namespaces. Use it when policy authors already think in CEL (OpenFGA, Cedar)
or when the expression must not be SQL. CEL has no CIDR function, so network
checks stay in SQL; business hours read like this:

```sql
SELECT authz.create_condition_cel('demo', 'office_hours_cel',
    'timestamp(request.current_time).getHours() >= 8 && timestamp(request.current_time).getHours() < 18',
    '{"request": ["current_time"]}');
```

Both languages are validated when the condition is created and can be
dry-run with `validate_condition` before any tuple uses them. A tuple
carries **one** condition, so "network *and* hours" is the two expressions
joined in one condition:

```sql
SELECT authz.create_condition_sql('demo', 'office_network_hours',
    $$ ($1->>'client_ip')::inet <<= ($2->>'allowed_cidr')::cidr
       AND extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17 $$,
    '{"request": ["client_ip", "current_time"], "stored": ["allowed_cidr"]}');
```

(Weekdays, IPv4-mapped IPv6 addresses from dual-stack listeners, and other
refinements: [MODEL_DESIGN → Other condition examples](MODEL_DESIGN.md#other-condition-examples).)

**3. Bind it to the grant.** The condition name goes on the tuple, with the
stored context it needs.

```sql
SELECT authz.write_tuple('demo', 'internal_user', 'bob', 'viewer', 'document', 'payroll',
    p_condition         => 'office_network_hours',
    p_condition_context => '{"allowed_cidr": "10.0.0.0/8"}');
```

**4. Check with the request context.** The caller supplies what the
condition needs — here only the address, since the clock is the server's. A
missing key is never guessed: the check denies, and the detailed check
reports which key would settle it.

```sql
SELECT authz.check_access_with_context('demo', 'internal_user', 'bob', 'viewer', 'document', 'payroll',
    '{"client_ip": "10.1.2.3"}');          -- true during office hours, false at 22:30 — the server decides
SELECT authz.check_access_detailed('demo', 'internal_user', 'bob', 'viewer', 'document', 'payroll', '{}');
-- {"state": "conditional", "missing_context": ["request.client_ip"], ...}
```

Choose `p_time_source => 'caller'` when the request legitimately asserts a
time: tests and demos that pin the clock, "would this be allowed at T" asked
live. Time travel with `audit_check_access` evaluates every condition at
`p_at`. For a plain "until T", prefer tuple expiry.

Shown in: [`examples/models/demo/`](../examples/models/demo) (`demo.sql`
and `demo_cel.sql`), [MODEL_DESIGN → Conditions](MODEL_DESIGN.md#8-conditions-abac),
[MODEL_DESIGN → Condition languages](MODEL_DESIGN.md#condition-languages-lang).

### Conditional object wildcard, intersection, detailed check — deny from unmanaged devices, fail closed when you don't know

**Scenario:** Employees may view documents only from a managed device. The
rule applies to every employee and every document, and if the request does
not say whether the device is managed, the answer is deny — not a guess.

**Solution:** In a policy engine this is a global `forbid`; here it is one
relation, one condition and one tuple.

**Why a relation for something that is not a relationship?** A ReBAC
decision is computed from exactly two things: the rules of the model and
the tuples in the store. There is no third place to hang "and the request
must say the device is managed" — the only way a request attribute reaches
a decision is through a **condition on a tuple**. So the constraint becomes
a relation (`managed_device`, read as "is on a managed device, as far as
this document is concerned") that every employee must hold in addition to
their grant — and **one** tuple, with a wildcard subject and a wildcard
object, stands in for all employee × document pairs: a million employees
and a million documents still need exactly one row, found by one index
probe, whose condition then decides per request. The alternatives are worse: attaching the condition to every
grant tuple duplicates it across thousands of grants and across team
grants that are not per person, and forgetting it once opens a hole;
moving the rule to a policy sidecar takes it out of the model, so
`list_objects`, `explain_access` and time travel no longer know about it.
Modelled this way, all three do.

**1. The constraint is a relation every employee path must also hold.**
`view` for employees is an intersection: the ordinary grant *and*
`managed_device`. AND inside a rule group means "both must resolve to this
subject on this object"; the grant resolves through the graph as usual, the
constraint resolves through the wildcard tuple below. (Customers have their
own path without it.)

```sql
-- view = customer_readers  OR  (employee_can_view AND managed_device)
SELECT authz.model_add_rule('aia_acme', 'document', 'view', 'computed', 'customer_readers');
SELECT authz.model_add_rule('aia_acme', 'document', 'view', 'computed', 'employee_can_view',
    p_group_id => 1, p_group_op => 'intersection');
SELECT authz.model_add_rule('aia_acme', 'document', 'view', 'computed', 'managed_device',
    p_group_id => 1, p_group_op => 'intersection');
```

**2. One tuple grants it to everyone, on everything — conditionally.** The
tuple reads "every employee holds `managed_device` on every document,
provided the condition passes". A subject wildcard (`employee:*`) covers
every employee, an object wildcard (`document:*`) covers every document,
and the condition makes the match depend on the request, so the relation is
true for exactly the requests that come from a managed device. Both
wildcards are opt-in in the model: the rule must allow object wildcards and
the type restriction must allow the subject wildcard, so a relation cannot
become store-wide by accident.

```sql
SELECT authz.model_add_rule('aia_acme', 'document', 'managed_device', 'direct', p_allow_object_wildcard => true);
SELECT authz.model_add_type_restriction('aia_acme', 'document', 'managed_device', 'employee', p_allow_wildcard => true);

SELECT authz.write_tuple('aia_acme', 'employee', '*', 'managed_device', 'document', '*',
    p_condition => 'managed_device');
```

**3. The condition reads the request, and defaults to "no".** `COALESCE(…,
false)` turns an absent or malformed value into false, so the tuple never
matches by accident; `required_context` declares the key so a missing one is
reported rather than silently false.

```sql
SELECT authz.create_condition_sql('aia_acme', 'managed_device',
    $$ COALESCE(($1 #>> '{device,managed}')::boolean, false) $$,
    '{"request": ["device"]}');
```

**4. Three requests, three answers.** Bob is an employee reader of the Q3
plan.

```sql
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan',
    '{"device": {"managed": true}}');    -- true
SELECT authz.check_access_with_context('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan',
    '{"device": {"managed": false}}');   -- false
SELECT authz.check_access_detailed('aia_acme', 'employee', 'bob', 'view', 'document', 'q3-plan', '{}');
-- {"state": "conditional", "missing_context": ["request.device"], ...}
--  ↑ denied, and the enforcement point learns which key it forgot
```

The third answer is the point: `conditional` means "denied, but supplying
`request.device` could change that", which is what a PEP needs to fix its
request rather than retry blindly.

Shown in: [`examples/models/aia-acme/`](../examples/models/aia-acme/README.md)
(the full Cedar-to-ReBAC mapping, this rule included),
[MODEL_DESIGN → Missing context](MODEL_DESIGN.md#missing-context).

### Rule groups: intersection and exclusion — delete your own items unless you're admin; blocked members can't edit

**Scenario:** A todo item may be deleted by its owner, but only if the owner
may still manage the list it belongs to; an admin of the list may delete
anything. In a shared folder, the editors may edit — except Bob, who has
been blocked.

**Solution:** A relation's rules are grouped. Inside a group the rules are
combined with AND (`intersection`) or with BUT NOT (`exclusion`); separate
groups are OR'd. A plain relation is one group with one rule.

**1. AND: two things must both be true.** `can_delete_todo` needs the
subject to be the item's `owner` *and* to hold `can_manage_todo_items` on
the list the item belongs to (a tuple-to-userset rule through `parent`).
Both rules go into group 1 with `intersection`.

```sql
SELECT authz.model_add_rule('todo', 'todo', 'can_delete_todo', 'computed', 'owner',
    p_group_id => 1, p_group_op => 'intersection');
SELECT authz.model_add_rule('todo', 'todo', 'can_delete_todo', 'ttu',
    p_tupleset_relation => 'parent', p_tupleset_computed => 'can_manage_todo_items',
    p_group_id => 1, p_group_op => 'intersection');
```

**2. OR: a second group is an alternative path.** An admin of the list may
delete the item regardless of ownership. That is a different group, so it is
OR'd with the first one.

```sql
SELECT authz.model_add_rule('todo', 'todo', 'can_delete_todo', 'ttu',
    p_tupleset_relation => 'parent', p_tupleset_computed => 'admin',
    p_group_id => 2);
-- can_delete_todo = (owner AND can_manage_todo_items from parent) OR admin from parent
```

**3. BUT NOT: subtract a relation.** An `exclusion` group ANDs its ordinary
rules and subtracts the ones marked `p_negated`. `can_edit` on a folder is
"editor, but not blocked"; blocking Bob is then one tuple, and the team
share he is part of stays untouched. (Group ids are numbered per relation:
this group 1 belongs to `folder.can_edit` and has nothing to do with group 1
of `todo.can_delete_todo` above.)

```sql
SELECT authz.model_add_rule('fourq', 'folder', 'can_edit', 'computed', 'editor',
    p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('fourq', 'folder', 'can_edit', 'computed', 'blocked',
    p_group_id => 1, p_group_op => 'exclusion', p_negated => true);

SELECT authz.write_tuple('fourq', 'team', 'marketing', 'editor',  'folder', 'campaign', p_user_relation => 'member');
SELECT authz.write_tuple('fourq', 'user', 'bob',       'blocked', 'folder', 'campaign');
SELECT authz.check_access('fourq', 'user', 'bob', 'can_edit', 'folder', 'campaign');   -- false, though bob is in marketing
```

Two rules keep this safe: a subtracted relation whose condition cannot be
evaluated (missing context) still subtracts, so an exclusion never fails
open; and `explain_access` reports the exclusion as the reason, not a
missing grant.

Shown in: [`examples/models/todo/`](../examples/models/todo),
[`examples/models/fourquestions/`](../examples/models/fourquestions/README.md),
[MODEL_DESIGN → Rule groups](MODEL_DESIGN.md#rule-groups--intersection-and-exclusion).

### Object wildcard — an auditor who sees every document, now and in future

**Scenario:** An auditor must be able to read every document, including the
ones created after she was appointed.

**Solution:** An object wildcard grants the relation on every object of a
type. It is default-deny: the direct rule must opt in.

```sql
SELECT authz.model_add_rule('demo', 'document', 'viewer', 'direct', p_allow_object_wildcard => true);
SELECT authz.write_tuple('demo', 'internal_user', 'nadia', 'viewer', 'document', '*');
```
Shown in: [MODEL_DESIGN → Object wildcards](MODEL_DESIGN.md#object-wildcards-privileged-grants).

### Checked writes — who may share, and never more than they hold

**Scenario:** Editors may share a document for viewing; only the owner may
make someone an editor. "Can view" and "can change who views" must never be
the same question, and a share must be refused if the sharer lost the right
a moment earlier.

**Solution:** Sharing rights are relations like any other, and the
enforcement point writes the share **through a precondition** that checks
the sharer's right inside the same transaction as the write.

**1. Sharing rights are computed relations.** `can_share_view` and
`can_share_edit` are separate from `can_view`; the owner holds both, an
editor only the first.

```sql
SELECT authz.model_add_rule('docs', 'document', 'can_view',       'computed', 'viewer');
SELECT authz.model_add_rule('docs', 'document', 'can_view',       'computed', 'editor');
SELECT authz.model_add_rule('docs', 'document', 'can_view',       'computed', 'owner');
SELECT authz.model_add_rule('docs', 'document', 'can_share_view', 'computed', 'editor');
SELECT authz.model_add_rule('docs', 'document', 'can_share_view', 'computed', 'owner');
SELECT authz.model_add_rule('docs', 'document', 'can_share_edit', 'computed', 'owner');
```

**2. The share is a checked write.** `write_tuples_checked` takes
preconditions and writes; a precondition with `"match": "allowed"` runs a
full access check for the *sharer*, and the write happens only if it
passes. Everything runs in one transaction under a lock on the object, so a
right revoked concurrently is seen.

```sql
-- bob (an editor) shares view access with carol: allowed
SELECT authz.write_tuples_checked('docs',
  p_preconditions => '[{"match": "allowed", "user_type": "user", "user_id": "bob",
                        "relation": "can_share_view", "object_type": "document", "object_id": "plan"}]',
  p_writes        => '[{"user_type": "user", "user_id": "carol", "relation": "viewer",
                        "object_type": "document", "object_id": "plan"}]',
  p_performed_by  => 'bob');
-- {"deleted": 0, "written": 1}

-- bob tries to make dave an editor: the precondition fails, nothing is written
SELECT authz.write_tuples_checked('docs',
  p_preconditions => '[{"match": "allowed", "user_type": "user", "user_id": "bob",
                        "relation": "can_share_edit", "object_type": "document", "object_id": "plan"}]',
  p_writes        => '[{"user_type": "user", "user_id": "dave", "relation": "editor",
                        "object_type": "document", "object_id": "plan"}]',
  p_performed_by  => 'bob');
-- ERROR: Write precondition failed: allowed {... "relation": "can_share_edit" ...}
```

**3. Variations with the same mechanism.** "Grant no more than you hold" is
a precondition that the sharer is `allowed` the relation being granted.
Revoking someone else's access is a `can_unshare` relation checked the same
way, with the tuple in `p_deletes`. "Nobody removes the owner" is a relation
nobody holds, so the precondition can never pass. Over HTTP the same call is
`POST /pgauthz/v1/write-checked`, and the audit trail records `performed_by`
as the sharer, so "who gave carol access" is one query later.

Shown in: [DEVELOPMENT → Conditional / atomic writes](DEVELOPMENT.md#conditional--atomic-writes-optimistic-concurrency),
[`examples/models/aia-acme/`](../examples/models/aia-acme/README.md)
(`employee_can_share`, `share_locked`), [Delegation with attenuation](#delegation-with-attenuation-checked-writes--subagents-never-exceed-their-parent) below.

### Marker tuples and exclusion — archived, under legal hold, draft only

**Scenario:** An archived document can be read but not edited; a document
under legal hold cannot be deleted, not even by its owner; some documents
may be edited only while they are drafts. The state lives in the
application's own table and changes in the application's own transaction.

**Solution:** A state is a **marker tuple** on the object: a relation whose
subject is the wildcard `user:*`, so it holds for everyone. Permissions
subtract it with an exclusion (or require it with an intersection). Because
the engine lives in the same database, the marker is written in the same
transaction as the state column, so the two can never disagree.

**1. Marker relations allow the wildcard subject.**

```sql
SELECT authz.model_add_rule('docs', 'document', 'archived',   'direct');
SELECT authz.model_add_rule('docs', 'document', 'legal_hold', 'direct');
SELECT authz.model_add_type_restriction('docs', 'document', 'archived',   'user', p_allow_wildcard => true);
SELECT authz.model_add_type_restriction('docs', 'document', 'legal_hold', 'user', p_allow_wildcard => true);
```

**2. Permissions subtract the marker.**

```sql
-- can_edit   = editor BUT NOT archived
SELECT authz.model_add_rule('docs', 'document', 'can_edit', 'computed', 'editor',
    p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('docs', 'document', 'can_edit', 'computed', 'archived',
    p_group_id => 1, p_group_op => 'exclusion', p_negated => true);
-- can_delete = owner BUT NOT legal_hold
SELECT authz.model_add_rule('docs', 'document', 'can_delete', 'computed', 'owner',
    p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('docs', 'document', 'can_delete', 'computed', 'legal_hold',
    p_group_id => 1, p_group_op => 'exclusion', p_negated => true);
```

**3. Changing state is writing or deleting one tuple.**

```sql
SELECT authz.check_access('docs', 'user', 'bob', 'can_edit', 'document', 'q3');     -- true: bob is an editor

UPDATE documents SET state = 'archived' WHERE id = 'q3';                            -- your table …
SELECT authz.write_tuple('docs', 'user', '*', 'archived', 'document', 'q3');          -- … and the marker, same transaction
SELECT authz.check_access('docs', 'user', 'bob', 'can_edit', 'document', 'q3');     -- false

SELECT authz.write_tuple('docs', 'user', '*', 'legal_hold', 'document', 'q3');
SELECT authz.check_access('docs', 'user', 'alice', 'can_delete', 'document', 'q3'); -- false, though alice owns it

SELECT authz.delete_tuple('docs', 'user', '*', 'archived', 'document', 'q3');         -- un-archive
SELECT authz.check_access('docs', 'user', 'bob', 'can_edit', 'document', 'q3');     -- true again
```

"Editable only while draft" is the same marker with an intersection instead:
`can_edit = editor AND draft`, with `user:* → draft → document:x` written on
creation and deleted on submit. Every marker change is in the audit trail
and visible to time travel, so "was it archived when bob edited it?" is
answerable; `list_objects` honours markers too, so an archived document
drops out of "what can bob edit" without application code.

Shown in: [MODEL_DESIGN → Rule groups](MODEL_DESIGN.md#rule-groups--intersection-and-exclusion),
[MODEL_DESIGN → Wildcard tuples](MODEL_DESIGN.md#wildcard-tuples-public-access).

### Object wildcard, bulk delete, expiry — suspended, offboarded, break-glass

**Scenario:** A suspended account must lose access immediately but keep its
grants for when it is reinstated; an offboarded employee loses everything,
auditable; an on-call engineer gets edit rights for one hour during an
incident, and someone must be able to see who granted what.

**Solution:** Three different lifetimes, three different tools.

**1. Suspension: one object-wildcard tuple, subtracted everywhere.** A
`suspended` relation with the object wildcard holds for the user on every
document; each permission subtracts it. The grants stay in place.

```sql
SELECT authz.model_add_rule('docs', 'document', 'suspended', 'direct', p_allow_object_wildcard => true);
SELECT authz.model_add_type_restriction('docs', 'document', 'suspended', 'user');
-- can_read = (viewer BUT NOT suspended) OR (editor BUT NOT suspended)
SELECT authz.model_add_rule('docs', 'document', 'can_read', 'computed', 'viewer',    p_group_id => 1, p_group_op => 'exclusion');
SELECT authz.model_add_rule('docs', 'document', 'can_read', 'computed', 'suspended', p_group_id => 1, p_group_op => 'exclusion', p_negated => true);
SELECT authz.model_add_rule('docs', 'document', 'can_read', 'computed', 'editor',    p_group_id => 2, p_group_op => 'exclusion');
SELECT authz.model_add_rule('docs', 'document', 'can_read', 'computed', 'suspended', p_group_id => 2, p_group_op => 'exclusion', p_negated => true);

SELECT authz.write_tuple('docs', 'user', 'bob', 'suspended', 'document', '*');
SELECT authz.check_access('docs', 'user', 'bob', 'can_read', 'document', 'q3');   -- false
SELECT * FROM authz.list_objects('docs', 'user', 'bob', 'editor', 'document');    -- q3: the grant is still there
SELECT authz.delete_tuple('docs', 'user', 'bob', 'suspended', 'document', '*');   -- reinstate
```

One tuple per object type that carries permissions; a suspension that must
cover every type is one tuple per type, written together.

**2. Offboarding: delete every tuple for the subject, in one audited call.**

```sql
SELECT authz.delete_user_tuples('docs', 'user', 'bob', p_performed_by => 'hr-sync');   -- → number removed
SELECT authz.check_access('docs', 'user', 'bob', 'can_read', 'document', 'q3');         -- false
SELECT * FROM authz.audit_list_user('docs', 'user', 'bob');   -- every grant he had, and the DELETEs by hr-sync
```

The audit trail keeps what bob had, so "what could bob reach on his last
day" is a time-travel query, and the changefeed tells caches to drop him.

**3. Break-glass: an expiring grant with an attributed writer.** The grant
ends by itself; the audit row says who made it; the reason belongs in the
incident ticket, or in the action log as a recorded event.

```sql
SELECT authz.write_tuple('docs', 'user', 'oncall-erin', 'editor', 'document', 'q3',
    p_expires_at   => now() + interval '1 hour',
    p_performed_by => 'erin');
SELECT authz.record_event('docs', 'user', 'oncall-erin', 'break_glass', 'document', 'q3',
    p_payload => '{"ticket": "INC-4711"}', p_recorded_by => 'svc:incident-portal');
```

For the review afterwards: `audit_list_user` shows the grant and its expiry,
`list_events` the recorded reason. A gate can even require the ticket:
`formerly_within` on `break_glass` recorded by the incident portal, so an
on-call edit without a ticket is denied.

Shown in: [API → delete_user_tuples](API.md#delete_user_tuples--remove-all-tuples-for-a-user),
[MODEL_DESIGN → Object wildcards](MODEL_DESIGN.md#object-wildcards-privileged-grants),
[AUDIT → Audit trail and time travel](AUDIT.md#audit-trail-and-time-travel).

### Search API as a JOIN — show me only what I may see

**Scenario:** A listing page shows the twenty newest documents the user may
read — without a check per row, and without fetching what it then hides.

**Solution:** `list_objects` returns the objects a subject may act on, or the
typed wildcard row when the answer is "all of them". Co-located, the listing
query joins against it; over HTTP, AuthZEN resource search returns the ids.

```sql
WITH authorized AS MATERIALIZED (
    SELECT object_id, is_wildcard
      FROM authz.list_objects('demo', 'internal_user', 'bob', 'can_read', 'document'))
SELECT d.* FROM documents d
 WHERE EXISTS (SELECT 1 FROM authorized WHERE is_wildcard)
    OR d.id IN (SELECT object_id FROM authorized)
 ORDER BY d.created_at DESC LIMIT 20;
```
Shown in: [`examples/filtering/`](../examples/filtering/README.md).

### Time travel and the audit trail — could Grace read payroll last Tuesday, and who revoked it?

**Scenario:** Grace can no longer read the payroll report. Could she last
Tuesday, and who changed what in between?

**Solution:** Decisions replay from the audit log as of any instant; the
audit listing shows the change with the acting application user. Explain is
live: it traces today's decision.

```sql
SELECT authz.audit_check_access('demo', 'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001',
    '2026-09-22 10:00+00');                                   -- true: she still had it
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'grace');
-- DELETE member team:payroll_team  performed_by=hr-sync  performed_at=…
```
Shown in: [AUDIT.md](AUDIT.md#audit-trail-and-time-travel),
[`examples/models/demo/demo.sql`](../examples/models/demo/demo.sql).

### Changefeed — react to changes: cache invalidation, sync

**Scenario:** A permission cache, a search index or a downstream system must
learn about every grant and revoke promptly, without polling the whole store.

**Solution:** A cursored changefeed over the audit log plus a `NOTIFY`
doorbell; filter by type, namespace or relation; resume from the last cursor.

```sql
SELECT * FROM authz.watch_changes('demo', p_after_at => :last_at, p_after_seq => :last_seq);
LISTEN authz_changes;
```
Shown in: [AUDIT.md → Watching for changes](AUDIT.md#watching-for-changes-changefeed),
[`examples/watch/`](../examples/watch).

### Policy hooks (OPA) — an org-wide rule that narrows but never widens

**Scenario:** Security wants one rule across every store: exporting requires
a specific client role in the token, whatever the graph says.

**Solution:** Policy hooks are Rego files, global or per store, evaluated by
the optional OPA sidecar on the verified token claims and server time; they
can only add denials.

```rego
package authz.hooks.v1.global.claims_guard
import data.authz.hooks.lib.v1.keycloak

deny contains {"code": "export_requires_client_role"} if {
  input.action == "can_export"
  not keycloak.has_client_role(input.actor, "document-api", "exporter")
}
```
Shown in: [`examples/opa-hooks/`](../examples/opa-hooks/README.md),
[ADR 0011](adr/0011-opa-policy-hooks.md).

### Store per tenant, tuple-to-userset — one user in several workspaces

**Scenario:** Alice is a member of two customers' workspaces. Nothing she
holds in one may ever grant her anything in the other, a document belongs to
exactly one workspace, and a support engineer's access must be deliberate
and visible, not a side effect of a global role.

**Solution:** Two boundaries, one hard and one modelled.

**1. The hard boundary is the store.** Every tuple, model rule and check
carries a `store_id`; a check in one store cannot see another store's tuples
at all. One store per tenant is the recommended shape, with the registry
keeping the model identical across them. Over HTTP, pgauthzd binds each
JWT issuer to the stores it may select, so a token for tenant A cannot even
address tenant B.

```sql
SELECT authz.check_access('tenant_a', 'user', 'alice', 'can_view', 'document', 'd1');   -- decided from tenant_a only
SELECT authz.check_access('tenant_b', 'user', 'alice', 'can_view', 'document', 'd1');   -- tenant_b has no such document: denied
```

**2. Inside a tenant, scope flows down the container chain.** A document
belongs to a project, a project to a workspace, and membership is granted
on the workspace. Each level reads `can_view` from its parent with a
tuple-to-userset rule, so a user in workspace W2 is never a hop away from
W1's documents: there is no edge to follow.

```sql
SELECT authz.model_add_rule('tenant_a', 'workspace', 'can_view', 'computed', 'member');
SELECT authz.model_add_rule('tenant_a', 'project',   'can_view', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'can_view');
SELECT authz.model_add_rule('tenant_a', 'document',  'can_view', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'can_view');

SELECT authz.write_tuple('tenant_a', 'user', 'alice', 'member', 'workspace', 'w1');
SELECT authz.write_tuple('tenant_a', 'user', 'bob',   'member', 'workspace', 'w2');
SELECT authz.write_tuple('tenant_a', 'workspace', 'w1', 'parent', 'project',  'p1');
SELECT authz.write_tuple('tenant_a', 'project',   'p1', 'parent', 'document', 'd1');

SELECT authz.check_access('tenant_a', 'user', 'alice', 'can_view', 'document', 'd1');   -- true
SELECT authz.check_access('tenant_a', 'user', 'bob',   'can_view', 'document', 'd1');   -- false
```

Type restrictions make "exactly one workspace" structural: `project.parent`
accepts only a `workspace`, `document.parent` only a `project`, and a
tuple naming anything else is refused at write time. Support access is then
an ordinary, expiring grant in the tenant's store, written by the support
tool with `p_performed_by`, so it shows up in that tenant's audit trail
rather than hiding behind a global role.

Shown in: [MODEL_DESIGN → Multi-store support](MODEL_DESIGN.md#multi-store-support),
[Model registry](#model-registry-and-model-as-code--one-model-many-tenants) below,
[pgauthzd → Multi-store support](../pgauthzd/README.md#multi-store-support) (issuer-to-store binding).

### Namespaces — per-application isolation inside one store

**Scenario:** Billing and support share one store, but neither application
may read or write the other's types.

**Solution:** Types belong to a namespace; database roles are granted read or
write on a namespace; the engine refuses a write from a role without the
grant.

```sql
SELECT authz.model_register_type('demo', 'invoice', p_namespace => 'billing');
SELECT authz.grant_namespace_access('demo', 'billing', 'app_billing', p_can_read => true, p_can_write => true);
```
Shown in: [MODEL_DESIGN → Namespace-based access control](MODEL_DESIGN.md#namespace-based-access-control),
[PRODUCTION → Role recipes](PRODUCTION.md#role-recipes).

### Model registry and model-as-code — one model, many tenants

**Scenario:** One SaaS product, one authorization model, a thousand tenants.
A model change must be tried on one tenant before it reaches the rest.

**Solution:** A store per tenant for data isolation; one named, immutable
model version in the registry, applied per store; canary one tenant, then the
fleet; drift detection; models in git with CI tests through `pgauthzctl`.

```sql
SELECT authz.publish_model('saas_core', 'tenant_canary');          -- version N
SELECT authz.plan_model_apply('tenant_a', 'saas_core');           -- dry run
SELECT authz.apply_model('tenant_a', 'saas_core');
SELECT * FROM authz.model_rollout_status('saas_core');
```
Shown in: [MODEL_DESIGN → Model registry](MODEL_DESIGN.md#16-sharing-one-model-across-stores-model-registry),
[`pgauthzctl/`](../pgauthzctl/README.md).

### Typed service principals — jobs, exporters, and acting on behalf of a user

**Scenario:** A nightly job exports every report; a queue worker renders a
document a user asked for; an API gateway forwards requests with the user's
identity. None of them should quietly inherit a broad database role, and
"the job can do it" must never become "the user could do it".

**Solution:** A service is a principal with its own type and its own
grants, and a job working for a user checks the **user**, not itself.

**1. Services are a subject type with their own relations.** The exporter
holds `exporter` on every report through an object wildcard; it holds no
`viewer`, so it cannot read as itself.

```sql
SELECT authz.model_add_rule('reports', 'report', 'exporter', 'direct', p_allow_object_wildcard => true);
SELECT authz.model_add_type_restriction('reports', 'report', 'exporter', 'service');   -- only services
SELECT authz.model_add_rule('reports', 'report', 'can_export', 'computed', 'exporter');

SELECT authz.write_tuple('reports', 'service', 'nightly-export', 'exporter', 'report', '*');
SELECT authz.check_access('reports', 'service', 'nightly-export', 'can_export', 'report', 'r1');   -- true
SELECT authz.check_access('reports', 'service', 'nightly-export', 'can_read',   'report', 'r1');   -- false: not its job
```

**2. On behalf of a user: check the user, record the service.** The worker
asks whether *alice* may read the report, and records what happened under
its own name, so the action log shows both who the action was for and who
performed it.

```sql
SELECT authz.check_access('reports', 'user', 'alice', 'can_read', 'report', 'r1');   -- alice's rights, not the worker's
SELECT authz.record_event('reports', 'user', 'alice', 'export', 'report', 'r1',
    p_kind => 'response', p_recorded_by => 'svc:nightly-export');
```

For bulk work, `list_objects` for the user gives the set to process in one
call; for many single checks, the batch endpoint evaluates them in one
request.

**3. Over HTTP, identity is the token's.** pgauthzd takes the subject from
the verified JWT; a request body naming a different subject is rejected
unless the instance is explicitly configured as a trusted decision point
for a PEP (`ALLOW_SUBJECT_OVERRIDE`). Every issuer must pin an audience, so
a token minted for another API is not accepted here (the confused-deputy
case), and each issuer is bound to the stores and database roles its tokens
may use. A service gets its own issuer entry or client role with exactly
that binding, which is how a migration job is kept from running as the
full writer.

Shown in: [`examples/models/agents/`](../examples/models/agents/README.md)
(a non-human principal end to end), [pgauthzd → Authentication](../pgauthzd/README.md#authentication),
[PRODUCTION → AuthZEN subject policy](PRODUCTION.md#authzen-subject-policy),
[pgauthzd → Batch evaluations](../pgauthzd/README.md#batch-evaluations).

### OpenFGA import — "we already have an OpenFGA model"

**Scenario:** The model and the tuples already exist in OpenFGA and should
carry over, without anyone re-typing them.

**Solution:** Import the JSON model and the tuples as they are. Types,
relations, `this`/`computedUserset`/`tupleToUserset`, `union`,
`intersection` and `difference` map one-to-one onto rules and rule groups;
type restrictions keep their usersets, wildcards and `with <condition>`
facets; tuples keep their condition name and context. `describe_model`
renders the result back as DSL so you can diff it against the source.

```sql
SELECT authz.import_openfga_model('github', '{ "schema_version": "1.1", "type_definitions": [ … ] }');
-- {"store": "github", "types": [...], "relations": [...], "rules_imported": 31, "rules_replaced": 0,
--  "placeholder_conditions": [], "warnings": []}
SELECT authz.import_openfga_tuples('github', '{ "tuples": [ … ] }');
```

What does **not** carry over, and what happens instead:

- **Condition bodies.** OpenFGA conditions are CEL over its own vocabulary;
  only the condition *names* are imported. A facet or tuple that references
  a condition you have not defined yet gets a **deny-all placeholder** (the
  summary lists it under `placeholder_conditions`), so the model stays as
  strict as the original until you write the expression with
  `create_condition_sql` or `create_condition_cel`. Dropping the binding
  instead would silently widen the model.
- **Operators nested deeper than one level below `union`**, such as
  `(a and b) but not (c or (d and e))`. Rule groups are one level deep, so
  the importer raises and names the relation; re-model it by hand as groups
  (the MODEL_DESIGN section below shows how). It never imports a more
  permissive approximation.
- **Modules and model ids.** A modular (1.2) model imports as one flat
  model; module and `source_info` metadata are not kept. Version history
  stays with the OpenFGA store, so publish the imported model to the
  registry if you need versions here.
- **The store is replaced.** Importing a model deletes the store's existing
  rules and type restrictions first; tuples are added, not replaced.

Shown in: [MODEL_DESIGN → Importing from OpenFGA](MODEL_DESIGN.md#13-importing-from-openfga)
(including [how intersection and exclusion map to rule groups](MODEL_DESIGN.md#example-how-intersectionexclusion-map-to-rule-groups)),
[`examples/models/github/`](../examples/models/github).

### Policies as data — "our policies are already in Cedar"

**Scenario:** The policies are written in Cedar. Can the same rules be
expressed as relationships, without losing any of them?

**Solution:** Attributes become relations, attribute traversals become
tuple-to-userset rules, a global `forbid` becomes a required conditional
relation, a policy template becomes a tuple.

Shown in: [`examples/models/aia-acme/`](../examples/models/aia-acme/README.md),
which maps the *Authorization in Action* case study policy by policy.

## Advanced

Everything below reads the **action log**: what principals actually did, as
the enforcement point records it after the fact (`record_event`). A
**temporal gate** attaches history clauses to a relation and vetoes after
the graph allows. Gates never grant.

### Temporal gates: count_within, sum_within — rate limits and spend caps

**Scenario:** At most five transfers an hour from an account, and no more
than 5,000 in total over that hour.

**Solution:** A gate attached to the `transfer` relation of `account`. The
graph still decides *whether* the principal may transfer; the gate then
looks at what that principal has already done and vetoes if a clause fails.

**1. The enforcement point records what happened.** Gates read the action
log, and the log is written by your application after it acts, never by the
check itself. Two kinds matter here: a `request` event when a transfer is
attempted, and a `response` event when it completed, carrying the amount in
the payload.

```sql
SELECT authz.record_event('bank', 'user', 'alice', 'transfer', 'account', 'acc-1',
    p_kind => 'request');
SELECT authz.record_event('bank', 'user', 'alice', 'transfer', 'account', 'acc-1',
    p_kind => 'response', p_payload => '{"input": {"amount": 1200}}');
```

**2. The gate: two clauses, both must hold.** `all_of` is an AND of clauses;
each clause is one primitive with its settings.

```sql
SELECT authz.add_gate('bank', 'account', 'transfer', 'velocity', '{"all_of": [
  {"count_within": {"window": "1h", "kind": "request", "max": 5, "plus": 1}},
  {"sum_within":   {"window": "1h", "kind": "response", "field": "input.amount",
                    "plus": "$request.input.amount", "max": 5000}}]}');
```

Reading the first clause, key by key:

- `count_within` counts the principal's events; by default those of the
  gate's own action (`transfer`), on any object. `"scope": "object"` would
  count only transfers from the checked account.
- `"window": "1h"` is a sliding hour ending now, by the database clock.
- `"kind": "request"` counts attempts, so a transfer that was attempted and
  failed still counts; `response` would count completed ones.
- `"max": 5` is the inclusive limit, and `"plus": 1` adds the request being
  decided before comparing. So five attempts in the hour allow a sixth check
  to pass only if 5 + 1 ≤ 5, which it is not: the cap is five *including*
  this one. Without `plus` the sixth would still be allowed.

The second clause sums instead of counting:

- `"field": "input.amount"` is the payload path to add up, over `response`
  events in the window. It must be a number on every matched event; a
  malformed row fails the clause rather than being skipped, so a sloppy
  recorder cannot relax the cap.
- `"plus": "$request.input.amount"` adds the amount of *this* transfer,
  taken from the request context of the check. If the context does not
  carry it, the clause fails: `check_access_detailed` answers
  `conditional` with `missing_context: ["request.input"]`, and the explain
  step is marked `gate_missing_context`.

**3. Check with the amount in the context.**

```sql
SELECT authz.check_access_with_context('bank', 'user', 'alice', 'transfer', 'account', 'acc-1',
    '{"input": {"amount": 1200}}');
-- true while alice has made at most 4 requests this hour and her completed amounts + 1200 ≤ 5000
```

A denial by the gate shows up as reason `gate_denied` in `explain_access`,
with the clause, the observed value and the threshold. Two concurrent
checks can both see "4 of 5"; when the cap must be exact, use
`reserve_event` (below). Unknown keys are rejected at `add_gate` time, so a
typo cannot silently weaken a gate.

Shown in: [MODEL_DESIGN → Temporal gates](MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules),
[MODEL_DESIGN → The grammar](MODEL_DESIGN.md#the-grammar) (every key of every primitive).

### Temporal gates: formerly_within — prior approval, step-up freshness

**Scenario:** A transfer needs an approval from the approvals service first;
revealing a secret needs an MFA event less than 15 minutes old.

**Solution:** `formerly_within` is an existence test: *some* matching event
for this principal must lie inside the window. The three settings that make
it precise are `action` (which event), `match` (what it must say) and
`recorded_by` (who may have recorded it).

**1. The event must have a name.** A gate can only look for an action that
the store knows. `transfer` already exists as a relation; `approve_sale` and
`mfa` are events that are never checked, only recorded, so they are
registered as plain relations.

```sql
SELECT authz.model_register_relation('bank',  'approve_sale');
SELECT authz.model_register_relation('vault', 'mfa');
```

**2. The gates.**

```sql
SELECT authz.add_gate('bank', 'account', 'transfer', 'approved_first', '{"all_of": [
  {"formerly_within": {"window": "1h", "action": "approve_sale", "kind": "response",
                       "match": {"output.approved": true}, "recorded_by": ["svc:approvals"]}}]}');

SELECT authz.add_gate('vault', 'secret', 'reveal', 'step_up', '{"all_of": [
  {"formerly_within": {"window": "15m", "action": "mfa", "kind": "response"}}]}');
```

Reading the first one:

- `"action": "approve_sale"` looks for approval events instead of the gate's
  own action. Without `action`, the clause would look for earlier
  `transfer` events.
- The event is searched **for the checked principal**: an approval counts
  only if it was recorded with alice as its subject. The approvals service
  records "alice's transfer was approved", it does not record its own
  action. (`"scope": "object"` would further require that it was recorded
  on the checked account.)
- `"kind": "response"` with `"match": {"output.approved": true}` looks at
  the recorded outcome, so a request that was denied by the approver does
  not count. `match` is containment on the event payload; a value may also
  be `"$request.<path>"` to tie the approval to the request at hand, for
  instance the same stock.
- `"recorded_by": ["svc:approvals"]` is an allowlist on who recorded the
  event. Without it, any recorder, including the application that is about
  to act, could write its own approval.
- `"window": "1h"`: the approval expires after an hour by the database
  clock. There is no `since`/`until`; a stale approval simply stops
  matching.

The second gate has no `action` beyond the event name and no `match`:
any `mfa` response for this principal in the last 15 minutes satisfies it.
Step-up freshness is nothing more than that.

**3. Record, then check.**

```sql
-- the approvals service, on alice's behalf
SELECT authz.record_event('bank', 'user', 'alice', 'approve_sale', 'account', 'acc-1',
    p_kind => 'response', p_payload => '{"output": {"approved": true}}', p_recorded_by => 'svc:approvals');
SELECT authz.check_access('bank', 'user', 'alice', 'transfer', 'account', 'acc-1');   -- true for the next hour

-- the login service, after a successful second factor
SELECT authz.record_event('vault', 'user', 'alice', 'mfa', p_kind => 'response', p_recorded_by => 'svc:login');
SELECT authz.check_access('vault', 'user', 'alice', 'reveal', 'secret', 'db-password');   -- true for 15 minutes
```

A check before the event, or after the window, is denied with reason
`gate_denied`; the explain step shows the clause and the window, never the
matched event's payload. "Must *not* have happened" is not a
`formerly_within`; it is `count_within` with `max: 0`, shown next.

Shown in: [MODEL_DESIGN → Temporal gates](MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules)
(the full `velocity_backstop` gate, which combines this clause with the caps above),
[MODEL_DESIGN → What belongs in a gate](MODEL_DESIGN.md#what-belongs-in-a-gate).

### Temporal gates: object scope, count_distinct_within — separation of duties, four-eyes

**Scenario:** Whoever submitted this document may not approve it; a large
payment needs two distinct approvers, neither of them the executor.

**Solution:** Both rules are about events on *this* object, so the clauses
use `"scope": "object"`. The first is a "must not have happened"; the
second counts *distinct* approvers and then subtracts the caller.

**1. Not the submitter.** A `count_within` with `max: 0` over the
principal's own `submit` events on the checked document: if the person
asking to approve has submitted this document in the last 30 days, the
count is 1, the clause fails, and the approval is denied. Without
`"scope": "object"` the clause would count submissions of *any* document
and lock out every active author.

```sql
SELECT authz.add_gate('docs', 'doc', 'approve', 'not_the_submitter', '{"all_of": [
  {"count_within": {"window": "30 days", "action": "submit", "scope": "object", "max": 0}}]}');
```

**2. Two distinct approvers, and not yourself.** The payments service
records each approval as an `approval_received` event on the payment, with
the requester as the subject and the approver's id in the payload. Two
clauses read those same events:

```sql
SELECT authz.add_gate('fourq', 'payment', 'execute_large', 'four_eyes', '{"all_of": [
  {"count_distinct_within": {"window": "30 days", "action": "approval_received", "scope": "object",
                             "kind": "response", "key": "payload.input.approver", "min": 2,
                             "recorded_by": ["svc:payments"]}},
  {"count_within": {"window": "30 days", "action": "approval_received", "scope": "object",
                    "kind": "response", "match": {"input.approver": "$request.self"}, "max": 0,
                    "recorded_by": ["svc:payments"]}}]}');
```

- `count_distinct_within` counts how many *different* values of
  `"key": "payload.input.approver"` appear among the matched events, and
  `"min": 2` requires at least two. The same approver approving twice is
  one value. (`key` may also be `object_id` or `object_type`: "has acted
  on at least N different objects".)
- `"scope": "object"` on both clauses: only approvals recorded on the
  payment being checked count. Approvals of another payment, even by the
  same people, do not.
- The second clause is the separation of duties. `"match":
  {"input.approver": "$request.self"}` selects the approvals whose approver
  is the caller, and `"max": 0` requires that there are none. `self` is
  the caller's id, placed in the request context by the enforcement point
  (the same one that records the approvals). A check **without** `self`
  does not quietly pass: the clause fails with `gate_missing_context`.
- `recorded_by` pins both clauses to the payments service, so neither the
  requester nor the approver can record an approval themselves.

**3. Record, then check.**

```sql
SELECT authz.check_access_with_context('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1',
    '{"self": "dave"}');                                                              -- false: no approvals yet

SELECT authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
    '{"input": {"approver": "carol", "amount": 12000}}', p_recorded_by => 'svc:payments');
SELECT authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
    '{"input": {"approver": "grace", "amount": 12000}}', p_recorded_by => 'svc:payments');

SELECT authz.check_access_with_context('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1',
    '{"self": "dave"}');                                                              -- true: carol and grace
SELECT authz.check_access('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1');   -- false: no self → fails closed
```

Had one of the two approvals named `dave`, the first clause would still
see two distinct approvers but the second would count one match and veto.
Why `execute_large` is its own action rather than `execute` with an amount
threshold: gates are AND-only vetoes, so the tier has to be a different
relation; the fourquestions README records that decision.

Shown in: [`examples/models/fourquestions/`](../examples/models/fourquestions/README.md)
(this gate, with a demo and tests).

### Temporal gates over denials — lockout after repeated denials

**Scenario:** Five denied logins in fifteen minutes lock the account.

**Solution:** `kind: denied` counts the recorded denials; the gate vetoes
once the count reaches `max`.

```sql
SELECT authz.add_gate('portal', 'account', 'login', 'lockout', '{"all_of": [
  {"count_within": {"window": "15m", "kind": "denied", "max": 5}}]}');
```
Shown in: [MODEL_DESIGN → What belongs in a gate](MODEL_DESIGN.md#what-belongs-in-a-gate).

### Calendar windows and object scope — daily quotas, per user and per file

**Scenario:** A hundred downloads a day per user, and no single file more
than three times a day.

**Solution:** `calendar: day` with a time zone counts within the calendar day
instead of a sliding window; `scope: object` makes the second gate per file.

```sql
SELECT authz.add_gate('gdrive', 'doc', 'download', 'daily_quota', '{"all_of": [
  {"count_within": {"calendar": "day", "tz": "UTC", "kind": "response", "max": 100, "plus": 1}}]}');
SELECT authz.add_gate('gdrive', 'doc', 'download', 'per_file', '{"all_of": [
  {"count_within": {"calendar": "day", "tz": "UTC", "scope": "object", "kind": "response", "max": 3, "plus": 1}}]}');
```
Shown in: [`examples/models/gdrive/`](../examples/models/gdrive).

### reserve_event — exact caps under concurrency

**Scenario:** Two concurrent downloads both see "4 of 5" and both go
through. The cap must hold exactly.

**Solution:** The enforcement point reserves because it is about to act: the
decision and the record happen under one lock.

```sql
SELECT authz.reserve_event('gdrive', 'user', 'bob', 'download', 'doc', 'design_spec');
-- {"allowed": true, "seq": 42, "reason": "allowed", "gates": [...]}
```
Shown in: [MODEL_DESIGN → The strict tier](MODEL_DESIGN.md#the-strict-tier-reserve_event).

### Shadow mode — roll a new rule out without changing a decision

**Scenario:** A new velocity rule should run against real traffic for a
week before it denies anyone.

**Solution:** A gate in shadow mode evaluates exactly as enforcement would and
logs every would-be denial; drop the mode key to enforce.

```sql
SELECT authz.add_gate('bank', 'account', 'transfer', 'velocity', '{"mode": "shadow", "all_of": [ … ]}');
```
Shown in: [MODEL_DESIGN → Shadow mode](MODEL_DESIGN.md#rolling-a-gate-out-shadow-mode).

### Expiring or contextual tuples, intersection — an AI agent may only work on this task's customer

**Scenario:** One AI assistant serves every customer, but while it works on
a task for CustCo it must not read any other customer's data.

**Solution:** Every tool call is a check with the agent as principal. The
task's scope is a relationship with the lifetime of the task (expiring, or
contextual for one request), intersected into the agent's authority.

```sql
-- grants go to an agent's reach userset; the task's customer is a separate relation;
-- the agent's effective authority is the intersection of the two
SELECT authz.model_add_rule('agents', 'customer', 'agent_reader', 'direct');
SELECT authz.model_add_type_restriction('agents', 'customer', 'agent_reader', 'agent', p_allowed_user_relation => 'reach');
SELECT authz.model_add_rule('agents', 'customer', 'task_scope',  'direct');
SELECT authz.model_add_rule('agents', 'customer', 'agent_scope', 'computed', 'agent_reader', p_group_id => 1, p_group_op => 'intersection');
SELECT authz.model_add_rule('agents', 'customer', 'agent_scope', 'computed', 'task_scope',   p_group_id => 1, p_group_op => 'intersection');

SELECT authz.write_tuple('agents', 'agent', 'acme_assist', 'task_scope', 'customer', 'CustCo',
    p_expires_at => now() + interval '8 hours');
```
Shown in: [`examples/models/agents/`](../examples/models/agents/README.md),
[AGENTIC-AUTHORIZATION → Task scope](AGENTIC-AUTHORIZATION.md#3-task-scope).

### Sequencing gates — email only after a summary exists; at most N tool calls an hour

**Scenario:** The agent may send an email only after it has produced a
summary, and may make at most N tool calls an hour.

**Solution:** Task state lives in the action log, not in the prompt; the
recorder is the enforcement point, never the agent.

```sql
SELECT authz.add_gate('agents', 'mailbox', 'send_email', 'summary_first', '{"all_of": [
  {"formerly_within": {"window": "1h", "action": "documents_summarize", "kind": "response"}}]}');
```
Shown in: [AGENTIC-AUTHORIZATION → Sequencing and rate guardrails](AGENTIC-AUTHORIZATION.md#4-sequencing-and-rate-guardrails).

### Delegation with attenuation, checked writes — subagents never exceed their parent

**Scenario:** A research subagent spawned by the assistant must get no more
than the assistant has, and lose it when the assistant does.

**Solution:** Grants go to an agent's `reach` userset, so a delegate reads
through the delegator's grant and loses it when the delegator does; an
over-broad delegation is refused at write time by a precondition.

```sql
-- reach = the agent itself, plus (transitively) whoever it delegated to
SELECT authz.model_add_rule('agents', 'agent', 'delegate', 'direct');
SELECT authz.model_add_rule('agents', 'agent', 'reach',    'direct');
SELECT authz.model_add_rule('agents', 'agent', 'reach',    'ttu',
    p_tupleset_relation => 'delegate', p_tupleset_computed => 'reach');

SELECT authz.write_tuples_checked('agents',
  p_preconditions => '[{"match": "allowed", "user_type": "agent", "user_id": "acme_assist",
                        "relation": "agent_scope", "object_type": "customer", "object_id": "CustCo"}]',
  p_writes => '[{"user_type": "agent", "user_id": "research_agent", "relation": "delegate",
                 "object_type": "agent", "object_id": "acme_assist", "expires_at": "2026-10-01T18:00:00Z"}]');
```
Shown in: [AGENTIC-AUTHORIZATION → Delegation](AGENTIC-AUTHORIZATION.md#5-delegation-and-subagents).

### Type restrictions — guard the control plane by absence

**Scenario:** Agents may run automations, never create or change them.

**Solution:** No agent path exists in the model for `create` and `update`,
and the type restriction rejects writing one.

```sql
SELECT authz.model_add_rule('agents', 'automation', 'run',    'direct');
SELECT authz.model_add_type_restriction('agents', 'automation', 'run',    'agent');
SELECT authz.model_add_type_restriction('agents', 'automation', 'run',    'user');
SELECT authz.model_add_rule('agents', 'automation', 'create', 'direct');
SELECT authz.model_add_type_restriction('agents', 'automation', 'create', 'user');   -- no agent facet: an agent tuple is refused
SELECT authz.model_add_rule('agents', 'automation', 'update', 'direct');
SELECT authz.model_add_type_restriction('agents', 'automation', 'update', 'user');
```
Shown in: [AGENTIC-AUTHORIZATION → Childproofing the control plane](AGENTIC-AUTHORIZATION.md#6-childproofing-the-control-plane).

### Authorize before retrieval — RAG

**Scenario:** A retrieval-augmented answer may only draw on documents the
asking user (or agent) is allowed to read.

**Solution:** Filter, then search: the ids from `list_objects` become the
vector store's metadata filter. Or search, then check: the top-k ids through
one batch check before any content is fetched. Same relation, so task scope
applies.

Shown in: [AGENTIC-AUTHORIZATION → Authorize before retrieval](AGENTIC-AUTHORIZATION.md#7-retrieval-augmented-generation-authorize-before-retrieval).

## All four at once

*"Share this folder with the marketing team, except Bob; give external
reviewers read-only until next Friday, but only once they have accepted the
NDA; cap downloads at three a day; and any payment over 10k needs two
distinct approvers."* A userset share, an exclusion, an expiring tuple and
three temporal gates in one store, with tests:
[`examples/models/fourquestions/`](../examples/models/fourquestions/README.md).
