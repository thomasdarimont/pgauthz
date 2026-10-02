# Designing Authorization Models

This guide walks through designing and implementing a custom authorization model
step by step. We use a **Google Drive**-like permission system as the running
example -- folders, documents, groups, and inherited access.

The target model in OpenFGA DSL looks like this:

```
model
  schema 1.1

type user

type group
  relations
    define member: [user]

type folder
  relations
    define owner:  [user]
    define parent: [folder]
    define viewer: [user, user:*, group#member] or owner or viewer from parent

    define can_create_file: owner
    define can_write:       owner or can_write from parent
    define can_share:       owner or can_share from parent

type doc
  relations
    define owner:  [user]
    define parent: [folder]
    define viewer: [user, user:*, group#member]

    define can_change_owner: owner
    define can_read:         viewer or owner or viewer from parent
    define can_share:        owner or can_share from parent
    define can_write:        owner or can_write from parent
```

By the end of this guide you will have translated every line of that model into
SQL and understand **when to use which relationship type**.

---

## 1. Core Concepts

The authorization engine implements a
[Google Zanzibar](https://research.google/pubs/pub48190/)-style model with three
building blocks:

| Concept  | What it does | Database table |
|----------|-------------|----------------|
| **Type** | A category of object or user (`user`, `folder`, `doc`, `group`) | `authz.types` |
| **Relation** | A named permission or role (`owner`, `viewer`, `can_read`) | `authz.relations` |
| **Tuple** | A fact: *subject has relation on object* | `authz.tuples` |
| **Model Rule** | How to resolve a relation -- direct lookup, alias, or follow a link | `authz.models` |

A **tuple** is the atomic unit of access:

```
user:alice  →  owner  →  doc:design_spec
```

A **model rule** tells the engine *how* to evaluate a relation. There are three
rule types:

| Rule Type | Internal ID | Meaning |
|-----------|-------------|---------|
| **Direct** | 1 | Check if a matching tuple exists |
| **Computed** | 2 | Alias: check another relation on the *same* object |
| **TTU** (Tuple-to-Userset) | 3 | Follow a link to another object, then check a relation *there* |

---

## 2. Step 1 -- Create a Store

A **store** is an isolated authorization namespace. Each store has its own types,
relations, model rules, and tuples.

```sql
SELECT authz.create_store('gdrive', 'Google Drive permission model');
```

All subsequent definitions reference this store.

### Multi-Store Support

Every authorization operation is scoped to a **store** — an independent
authorization namespace. Each store has its own types, relations, models,
conditions, and tuples. Stores are fully isolated from each other.

The demo store is called `'demo'` and is created by the example model
`examples/models/demo/model.sql` (see [Example Models](../examples/models/README.md#example-models)).

```sql
-- Create a new store for testing a model change
INSERT INTO authz.stores (name) VALUES ('v2_experiment');

-- All API functions take the store name as the first parameter
SELECT authz.write_tuple('v2_experiment',
    'internal_user', 'alice', 'can_read', 'document', 'doc_001');
SELECT authz.check_access('v2_experiment',
    'internal_user', 'alice', 'can_read', 'document', 'doc_001');

-- Clean up
SELECT authz.delete_store('v2_experiment');
```

Stores are also the **multi-tenancy** unit: one store per tenant isolates
tuples by construction, while the [model registry](MODEL_DESIGN.md#16-sharing-one-model-across-stores-model-registry)
shares one versioned model across all tenant stores (publish → canary →
fleet, with drift detection and a `plan_model_apply` dry-run).

---

## 3. Step 2 -- Define Types

Look at the OpenFGA model and list every `type` keyword. Use
`model_register_type` to register each one — this creates the type and its
tuple partition in a single call.

From the model:
- `user` -- identity type (people who access things)
- `group` -- collections of users
- `folder` -- containers that hold docs and nest under other folders
- `doc` -- files

```sql
DO $$
BEGIN
    PERFORM authz.model_register_type('gdrive', 'user');
    PERFORM authz.model_register_type('gdrive', 'group');
    PERFORM authz.model_register_type('gdrive', 'folder');
    PERFORM authz.model_register_type('gdrive', 'doc', 8);  -- hash sub-partitions for high volume
END $$;
```

The optional third argument (`p_hash_modulus`) enables hash sub-partitioning
for types where you expect millions of distinct object IDs.
8 is a sensible default; 16 or 32 for very high-volume types.

**Guidelines:**
- Create a type for every distinct kind of entity in your domain.
- Identity types like `user` need no relations of their own -- they exist so
  tuples can reference them as subjects.
- If two entities share the exact same permission model, they can be the same
  type. If their permissions differ, make them separate types.

---

## 4. Step 3 -- Define Relations

Scan each type's `relations` block and collect every unique relation name. These
are shared across types within a store.

From the model:
- `member` (group membership)
- `owner` (ownership of folders and docs)
- `parent` (folder hierarchy link)
- `viewer` (read access)
- `can_create_file`, `can_change_owner`, `can_read`, `can_share`, `can_write`

```sql
DO $$
BEGIN
    PERFORM authz.model_register_relation('gdrive', 'member');
    PERFORM authz.model_register_relation('gdrive', 'owner');
    PERFORM authz.model_register_relation('gdrive', 'parent');
    PERFORM authz.model_register_relation('gdrive', 'viewer');
    PERFORM authz.model_register_relation('gdrive', 'can_create_file');
    PERFORM authz.model_register_relation('gdrive', 'can_change_owner');
    PERFORM authz.model_register_relation('gdrive', 'can_read');
    PERFORM authz.model_register_relation('gdrive', 'can_share');
    PERFORM authz.model_register_relation('gdrive', 'can_write');
END $$;
```

Both `model_register_type` and `model_register_relation` are **idempotent** —
calling them again with the same name returns the existing ID.

**Naming conventions:**
- Structural links: nouns (`parent`, `owner`, `member`)
- Assignable roles: nouns (`viewer`, `editor`, `admin`)
- Permissions / actions: `can_` prefix (`can_read`, `can_write`, `can_share`)

Keeping structural links separate from action permissions makes the model easier
to reason about. Structural links are used by TTU rules to navigate the object
graph; action permissions are what you check in application code.

---

## 5. Step 4 -- Define Model Rules

This is the heart of the model. For each relation on each type, add one or
more rules via `authz.model_add_rule()` that tell the engine how to resolve
that relation. Each call adds a single rule and returns its ID.

```sql
authz.model_add_rule(
    p_store,              -- store name
    p_object_type,        -- type the rule applies to
    p_relation,           -- relation being defined
    p_rule_type,          -- 'direct', 'computed', or 'ttu'
    p_computed_relation,  -- for computed rules: the source relation
    p_tupleset_relation,  -- for TTU rules: the link to follow
    p_tupleset_computed,  -- for TTU rules: the relation on the linked object
    p_group_id,           -- group ID (default 0)
    p_group_op,           -- 'or' (default), 'intersection', 'exclusion'
    p_negated             -- for exclusion groups (default false)
) RETURNS smallint       -- rule ID
```

The function is **idempotent** — adding the same rule twice returns the same
ID without duplicating it.

### Direct Relations

**Use when:** A relation is explicitly assigned via a stored tuple.

In OpenFGA, this corresponds to `[user]`, `[user:*]`, `[group#member]`, or
`this: {}`.

Example -- `group.member` is directly assigned:

```
type group
  relations
    define member: [user]
```

```sql
SELECT authz.model_add_rule('gdrive', 'group', 'member', 'direct');
```

Example -- `doc.owner` is directly assigned:

```
type doc
  relations
    define owner: [user]
```

```sql
SELECT authz.model_add_rule('gdrive', 'doc', 'owner', 'direct');
```

**When to use direct:**
- The relation is explicitly granted by writing a tuple
- Any time you see `[type]` or `this` in an OpenFGA model
- Structural links like `parent`, `owner`, `member`
- Explicit grants like `viewer`, `editor`

### Computed Relations

**Use when:** A relation is an alias for another relation on the **same object**.
This creates role hierarchies and permission inheritance within a single object.

In OpenFGA, this corresponds to `computedUserset` or a bare relation reference
like `owner` in a union.

Example -- `folder.viewer` includes `owner` (owners can view):

```
type folder
  relations
    define viewer: [user, user:*, group#member] or owner
```

The `or owner` part means: anyone who is an `owner` of this folder is also a
`viewer`. This is a computed rule:

```sql
DO $$
BEGIN
    -- folder.viewer: direct assignment
    PERFORM authz.model_add_rule('gdrive', 'folder', 'viewer', 'direct');
    -- folder.viewer: computed from owner (owners can view)
    PERFORM authz.model_add_rule('gdrive', 'folder', 'viewer', 'computed',
        p_computed_relation => 'owner');
END $$;
```

Example -- `doc.can_change_owner` is an alias for `owner`:

```
type doc
  relations
    define can_change_owner: owner
```

```sql
SELECT authz.model_add_rule('gdrive', 'doc', 'can_change_owner', 'computed',
    p_computed_relation => 'owner');
```

Example -- `doc.can_read` includes both `viewer` and `owner`:

```
type doc
  relations
    define can_read: viewer or owner or viewer from parent
```

The `viewer` and `owner` parts are computed rules (the `viewer from parent`
part is TTU, covered next):

```sql
DO $$
BEGIN
    -- doc.can_read: computed from viewer
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
        p_computed_relation => 'viewer');
    -- doc.can_read: computed from owner (owners can read)
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
        p_computed_relation => 'owner');
END $$;
```

**When to use computed:**
- Role hierarchies: `can_read` includes `owner` (owners can read)
- Permission grouping: `can_write` means the same as `owner` on this object
- Anytime one relation implies another on the **same** object

### Tuple-to-Userset (TTU)

**Use when:** Access to one object depends on a relation the user has on a
**different, linked** object. This is the mechanism for inheritance across the
object graph.

In OpenFGA, this corresponds to `tupleToUserset` or the shorthand
`relation from link`, e.g., `viewer from parent`.

A TTU rule has two parts:
1. **Tupleset relation** -- the link to follow (e.g., `parent`)
2. **Computed relation** -- the relation to check on the linked object (e.g., `viewer`)

The engine evaluates: *"find all objects linked via `parent`, then check if the
user has `viewer` on any of them."*

Example -- `doc.can_read` includes `viewer from parent`:

```
type doc
  relations
    define parent: [folder]
    define can_read: viewer or owner or viewer from parent
```

"If the user is a `viewer` of the doc's `parent` folder, they `can_read` the doc."

```sql
DO $$
BEGIN
    -- doc.parent: structural link (direct)
    PERFORM authz.model_add_rule('gdrive', 'doc', 'parent', 'direct');
    -- doc.can_read: inherited from parent folder's viewer
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'viewer');
END $$;
```

Example -- `doc.can_share` means `owner` or `can_share from parent`:

```
type doc
  relations
    define can_share: owner or can_share from parent
```

```sql
DO $$
BEGIN
    -- doc.can_share: direct owners
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_share', 'computed',
        p_computed_relation => 'owner');
    -- doc.can_share: inherited from parent folder's can_share
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_share', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'can_share');
END $$;
```

Example -- `folder.viewer` includes `viewer from parent` (recursive folder
inheritance):

```
type folder
  relations
    define parent: [folder]
    define viewer: [user, user:*, group#member] or owner or viewer from parent
```

```sql
DO $$
BEGIN
    -- folder.parent: structural link
    PERFORM authz.model_add_rule('gdrive', 'folder', 'parent', 'direct');
    -- folder.viewer: inherited from parent folder
    PERFORM authz.model_add_rule('gdrive', 'folder', 'viewer', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'viewer');
END $$;
```

This creates **recursive inheritance**: a viewer of `/root` is also a viewer of
`/root/projects` and `/root/projects/2026`, as long as the `parent` links are in
place.

**Important: TTU follows one link, not a chain.** A TTU rule checks the
relation on the **immediate** linked object only. If you need permissions to
propagate through a hierarchy (e.g., grandparent → parent → child), the
**linked type must also have a TTU rule** that propagates the same relation
upward. This is why `can_read` works across multiple folder levels:

1. `doc.can_read` has TTU: `viewer from parent` → checks `viewer` on `folder:projects`
2. `folder.viewer` has TTU: `viewer from parent` → checks `viewer` on `folder:root`
3. `folder.viewer` has computed: `owner` → Alice is `owner` of `folder:root` → match!

Without step 2, `can_read` would only check the immediate parent. The same
pattern applies to `can_write` and `can_share` — the folder type needs its own
`can_write: owner or can_write from parent` rule so that ownership propagates
recursively through the folder tree.

**When to use TTU:**
- Folder/container hierarchies: documents inherit permissions from their parent
  folder
- Organization structures: repos inherit admin roles from their owning org
- Any time a permission on object A depends on a permission on linked object B

### Combining Rule Types

A single relation can have **multiple rules** (they are OR'd together). This is
how you model OpenFGA unions. Each `model_add_rule` call adds one rule.

For `doc.can_read: viewer or owner or viewer from parent`:

```sql
DO $$
BEGIN
    -- Rule 1: computed from viewer (direct viewers can read)
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
        p_computed_relation => 'viewer');
    -- Rule 2: computed from owner (owners can read)
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
        p_computed_relation => 'owner');
    -- Rule 3: TTU via parent (parent folder viewers can read)
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'viewer');
END $$;
```

The engine checks all three rules. If **any** of them match, access is granted.

### Rule Groups — Intersection and Exclusion

By default, multiple rules for the same relation are combined with **OR** (union).
Rules can be organized into **groups** that use different combination operators:

| Operator | Constant | Meaning |
|----------|----------|---------|
| **OR** (default) | `authz._combine_or()` | Any rule match grants access |
| **AND** | `authz._combine_and()` | All rules must match |
| **Exclusion** | `authz._combine_exclusion()` | Base rules must match AND negated rules must NOT |

Groups themselves are OR'd — if any group grants access, the check passes.
This lets you mix operators: `can_view = (member AND licensed) OR admin`.

`model_add_rule` accepts three additional parameters for group control:

| Parameter | Type | Default | Meaning |
|-----------|------|---------|---------|
| `p_group_id` | smallint | 0 | Groups rules for combined evaluation |
| `p_group_op` | text | `'or'` | How rules in this group are combined |
| `p_negated` | boolean | false | For exclusion groups: true marks the subtracted rule |

All rules in a group must use the same `p_group_op` — `model_add_rule`
enforces this and raises an error on mismatch.

#### Intersection (AND)

**Use when:** access requires satisfying **all** conditions simultaneously.

Example — `can_view` requires both `member` AND `licensed`:

```
can_view = member AND licensed
```

```sql
DO $$
BEGIN
    -- Intersection group 1: both rules must match
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_view', 'computed',
        p_computed_relation => 'member',
        p_group_id => 1::smallint, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_view', 'computed',
        p_computed_relation => 'licensed',
        p_group_id => 1::smallint, p_group_op => 'intersection');
END $$;
```

**Use cases:**
- Licensed access: user must be an org member AND the org must hold an active license
- Dual-role requirements: approving expenses requires both `manager` AND `finance_member`
- Geographic restrictions: accessing patient data requires `care_team_member` AND `facility_assigned`

#### Exclusion (BUT NOT)

**Use when:** access is granted by one relation but denied by another.

Example — `can_comment` requires `member` BUT NOT `blocked`:

```
can_comment = member BUT NOT blocked
```

```sql
DO $$
BEGIN
    -- Exclusion group 1: base must match, negated must NOT
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_comment', 'computed',
        p_computed_relation => 'member',
        p_group_id => 1::smallint, p_group_op => 'exclusion');
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_comment', 'computed',
        p_computed_relation => 'blocked',
        p_group_id => 1::smallint, p_group_op => 'exclusion', p_negated => true);
END $$;
```

The `negated = true` flag marks the rule whose match **denies** access.

**Rules for exclusion groups:**

- An exclusion group must contain **at least one base (non-negated) rule**.
  A negated-only group has no base requirement and would grant access to
  everyone who is not excluded — fail-open. This is enforced at write
  time (insert the base rule before or together with negated rules), and
  the evaluator additionally fails closed if such a group exists anyway.
- `negated = true` is only allowed in exclusion groups.
- **A subtracted term that cannot be evaluated counts as matched.** If the
  negated rule resolves to a conditional tuple whose required request context
  is missing, the engine assumes the ban holds (fail closed) — `check_access`
  denies, `explain_access` shows a `condition_assumed` step, and
  `check_access_detailed` reports `conditional` with the missing keys. The
  assumption flips at every nesting level, so "unresolvable" always resolves
  toward deny.
- **Multiple base rules in one exclusion group are AND-ed** — all base
  rules must match (in addition to no negated rule matching). This
  differs from OpenFGA, where the base of a `difference` is typically a
  union. To express `(viewer OR editor) BUT NOT blocked`, use **two
  exclusion groups** (groups are OR'd):

```sql
-- Group 1: viewer BUT NOT blocked
-- Group 2: editor BUT NOT blocked
-- => (viewer OR editor) BUT NOT blocked
(s, t_doc, r_can_read, authz._rel_computed(), r_viewer,  1, authz._combine_exclusion(), false),
(s, t_doc, r_can_read, authz._rel_computed(), r_blocked, 1, authz._combine_exclusion(), true),
(s, t_doc, r_can_read, authz._rel_computed(), r_editor,  2, authz._combine_exclusion(), false),
(s, t_doc, r_can_read, authz._rel_computed(), r_blocked, 2, authz._combine_exclusion(), true);
```

**Use cases:**
- Blocked users: members can comment UNLESS they are blocked
- Suspended accounts: registered users can log in UNLESS suspended
- Conflict of interest: reviewers can review UNLESS they are the author

#### Mixing Groups

Groups are OR'd together, allowing combinations like
`can_view = (member AND licensed) OR admin`:

```sql
DO $$
BEGIN
    -- Group 1 (intersection): member AND licensed
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_view', 'computed',
        p_computed_relation => 'member',
        p_group_id => 1::smallint, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_view', 'computed',
        p_computed_relation => 'licensed',
        p_group_id => 1::smallint, p_group_op => 'intersection');
    -- Group 0 (OR): admin bypasses the intersection
    PERFORM authz.model_add_rule('mystore', 'resource', 'can_view', 'computed',
        p_computed_relation => 'admin');
END $$;
```

This means: access is granted if the user satisfies **either** the intersection
(member AND licensed) **or** the OR group (admin).

### Usersets (Group Membership)

OpenFGA's `group#member` syntax means "any user who is a `member` of the group."
This is handled automatically through the **userset** mechanism.

When you write a tuple with `p_user_relation`, you're saying "anyone who has
this relation on the subject object":

```sql
-- "members of group:engineering are viewers of folder:shared_docs"
SELECT authz.write_tuple('gdrive',
    'group', 'engineering', 'viewer', 'folder', 'shared_docs',
    'member'  -- p_user_relation: expand group membership
);
```

This means: for any user X, if `user:X` is a `member` of `group:engineering`,
then `user:X` is a `viewer` of `folder:shared_docs`.

The engine expands this automatically during access checks.

### Wildcard Tuples (Public Access)

OpenFGA's `[user:*]` syntax means "any user of this type, without having to
enumerate them individually." This is handled by writing a tuple with
`user_id = '*'`.

```sql
-- "Everyone can view folder:public_docs"
SELECT authz.write_tuple('gdrive', 'user', '*', 'viewer', 'folder', 'public_docs');
```

This means: for **any** user X of type `user`, `user:X` is a `viewer` of
`folder:public_docs` — without needing a tuple per user.

Wildcards propagate through computed relations and TTU just like regular tuples.
If `viewer` implies `can_read` (via a computed rule), then `user:*` having
`viewer` also grants `can_read` to everyone.

**Constraints:**
- Wildcard tuples cannot have a `user_relation` — `team:*#member` is not
  meaningful and is rejected by `write_tuple`.
- Wildcards are type-scoped: `user:*` as `viewer` means all users, not all
  groups. If both user and group types need public access, write separate
  wildcard tuples for each type.

**When to use wildcards:**
- Public/anonymous access: make a resource viewable by everyone
- Default permissions: all employees get a baseline relation (e.g., can view the company directory)
- Open registrations: any user can create a ticket in a public project

**How it works internally:**
When `check_access` evaluates a direct rule, it first looks for an exact
`user_id` match. If none is found, it checks for a wildcard tuple
(`user_id = '*'`) with the same `user_type`. The `explain_access` trace
distinguishes the two: "tuple found" for exact matches, "wildcard tuple (*)"
for wildcard matches.

### Object Wildcards (Privileged Grants)

**Use when:** a subject must hold a relation on **every object of a type** —
super admins, compliance auditors, platform operators. The dual of the
subject wildcard: `object_id = '*'`.

```sql
-- Mark the relationship as privileged (default-deny; direct rules only):
SELECT authz.model_add_rule('mystore', 'document', 'viewer', 'direct',
    p_allow_object_wildcard => true);

-- One tuple per auditor — covers all current AND future documents:
SELECT authz.write_tuple('mystore', 'user', 'auditor1', 'viewer', 'document', '*');

-- Or one tuple for a whole auditor group (userset + object wildcard):
SELECT authz.write_tuple('mystore', 'group', 'auditors', 'viewer', 'document', '*',
    p_user_relation => 'member');
```

Why this matters at scale: without the wildcard, an all-access role needs a
tuple per object (and churn on every create), or resolution through deep
hierarchies; with it, `check_access` is O(1) and `list_objects` answers with
the typed `('*', is_wildcard = true)` row instead of enumerating the store —
the application branches on it and lists from its own database.

Everything composes: computed relations propagate the wildcard grant
(`viewer` → `can_read`), exclusion groups can still subtract per object,
conditions on the wildcard tuple make time-boxed break-glass grants, and
time-travel honors it.

**Design guidance:** writes of `object_id = '*'` are rejected unless the
direct rule is marked — keep the mark on as few relations as possible, and
never pass untrusted external identifiers as object IDs (a stray literal
`'*'` would otherwise be a store-wide grant).

---

### Type restrictions and required conditions

A **type restriction** lists the subject shapes that may be *directly
assigned* to a relation — OpenFGA's `[user, team#member, user:*]`. Each row is
a **facet**: an allowed user type, optionally a userset relation
(`team#member`) or the wildcard (`user:*`). With no facets on a relation,
any shape is accepted (backward compatible); with facets, a write must match
one.

```sql
SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user');
SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'team',
    p_allowed_user_relation => 'member');
SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user',
    p_allow_wildcard => true);
```

A facet may also **require a condition** — OpenFGA's `[user:* with cond]`:

```sql
SELECT authz.create_condition_sql('demo', 'office_hours',
    $$extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17$$,
    '{"request": ["current_time"]}');
SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user',
    p_allow_wildcard => true, p_condition => 'office_hours');
```

Matching rules at write time (`write_tuple`, `write_tuples_jsonb`,
`write_tuples_checked`; the composite-type `write_tuples` batch carries no
conditions, so it only matches open facets):

| Tuple | Open facet (no condition) | Facet `with cond` |
|---|---|---|
| no condition | matches | rejected: *requires a condition (one of: cond)* |
| condition `cond` | matches | matches |
| condition `other` | matches | rejected: *does not allow condition "other"* |

So an **open facet accepts any condition** (pgauthz conditions are per
tuple by design — this differs from OpenFGA, where `[user]` rejects a
conditioned tuple), and to *require* a condition for a shape you define only
conditioned facets for it. `describe_model` renders the binding
(`define viewer: [user, user:* with office_hours]`), `type_restrictions_view`
exposes it as `condition`, the registry exports it as `condition` on the
facet (only when bound, so existing checksums do not move) and applies
conditions before facets. A condition bound to a facet cannot be deleted
until the facet is removed (`model_remove_type_restriction`).

`import_openfga_model` keeps `with <cond>` facets. OpenFGA condition *bodies*
are not imported (their CEL vocabulary differs), so a condition the store
does not have yet is created as a **deny-all placeholder** (`false`) and
reported in the summary's `warnings` and `placeholder_conditions`: the facet's
guarantee holds from the first write, tuples carrying it deny until you define
the real expression with `create_condition_sql` / `create_condition_cel`
(an in-place upsert, so the binding survives).

---

## 6. Step 5 -- Write Tuples

With the model in place, you grant access by writing tuples.

```sql
-- Alice owns the root folder
SELECT authz.write_tuple('gdrive', 'user', 'alice', 'owner', 'folder', 'root');

-- Projects folder is inside root
SELECT authz.write_tuple('gdrive', 'folder', 'root', 'parent', 'folder', 'projects');

-- Design spec is inside the projects folder
SELECT authz.write_tuple('gdrive', 'folder', 'projects', 'parent', 'doc', 'design_spec');

-- Bob is an explicit viewer of the design spec
SELECT authz.write_tuple('gdrive', 'user', 'bob', 'viewer', 'doc', 'design_spec');

-- Frank is the owner of the design spec
SELECT authz.write_tuple('gdrive', 'user', 'frank', 'owner', 'doc', 'design_spec');

-- Engineering group gets viewer access on the root folder
SELECT authz.write_tuple('gdrive',
    'group', 'engineering', 'viewer', 'folder', 'root',
    'member'  -- userset: all group members
);

-- Charlie is a member of the engineering group
SELECT authz.write_tuple('gdrive', 'user', 'charlie', 'member', 'group', 'engineering');
```

**Result:**
- Alice can read, write, and share `design_spec`
  (via `owner` on `root` folder, inherited through `parent` links)
- Alice cannot change ownership of `design_spec` (`can_change_owner` is
  defined as `owner` on the doc itself -- no folder inheritance)
- Bob can read `design_spec` (direct `viewer`)
- Charlie can read `design_spec` (member of `engineering` group, which is
  `viewer` on `root` folder, inherited through `parent` to `projects` to
  `design_spec`)

---

## 7. Step 6 -- Verify with Access Checks

```sql
-- Alice can read (owner of root → can_write from parent chain → can_read)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_read', 'doc', 'design_spec');
-- => true

-- Alice can write (owner of root → can_write from parent chain)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_write', 'doc', 'design_spec');
-- => true

-- Alice cannot change ownership (can_change_owner = owner on the doc itself, no inheritance)
SELECT authz.check_access('gdrive', 'user', 'alice', 'can_change_owner', 'doc', 'design_spec');
-- => false

-- Frank can change ownership (can_change_owner = owner on the doc itself, no inheritance)
SELECT authz.check_access('gdrive', 'user', 'frank', 'can_change_owner', 'doc', 'design_spec');
-- => true

-- Bob can read (direct viewer → can_read)
SELECT authz.check_access('gdrive', 'user', 'bob', 'can_read', 'doc', 'design_spec');
-- => true

-- Bob cannot write (viewer only)
SELECT authz.check_access('gdrive', 'user', 'bob', 'can_write', 'doc', 'design_spec');
-- => false

-- Charlie can read (group member → viewer on root → parent chain → can_read)
SELECT authz.check_access('gdrive', 'user', 'charlie', 'can_read', 'doc', 'design_spec');
-- => true

-- What can Alice do on the design spec?
SELECT * FROM authz.list_actions('gdrive', 'user', 'alice', 'doc', 'design_spec');
-- => can_read, can_share, can_write

-- Which docs can Bob read?
SELECT * FROM authz.list_objects('gdrive', 'user', 'bob', 'can_read', 'doc');
-- => design_spec

-- Paginated results (useful at scale)
SELECT * FROM authz.list_objects('gdrive', 'user', 'bob', 'can_read', 'doc',
    p_limit => 10, p_offset => 0);

-- Who can read the design spec? (also supports pagination)
SELECT * FROM authz.list_subjects('gdrive', 'user', 'can_read', 'doc', 'design_spec');
-- => alice, bob, charlie
```

### Debugging with explain_access

When a check returns an unexpected result, use `explain_access` to see the
engine's step-by-step evaluation trace:

```sql
SELECT authz.explain_access('gdrive', 'user', 'charlie', 'can_read', 'doc', 'design_spec');
```

This returns a JSONB document with each rule evaluated, which tuples were found
or missed, and how the final decision was reached. Pass `p_successful_only => true`
to see only the paths that granted access. Invaluable for debugging complex models
with multiple TTU and computed rules.

---

## 8. Conditions (ABAC)

### Representing expiration — which tool?

"Access until some point in time" can be modeled four ways; pick by how much
flexibility you actually need:

| Option | Use when | Trade-offs |
|---|---|---|
| **`expires_at` on the tuple** (native) | The plain case: "grant until T" | **Server time** decides (a caller cannot stretch its own window); enforced structurally on every check *and* search path; expired rows are cleanup-able (`cleanup_expired_tuples`, audited) and re-grants refresh/reactivate; time-travel judges expiry as of the asked moment. No recurring/relative windows. |
| **Condition** (SQL/CEL, this section) | Rich windows: business hours, recurring schedules, "N hours after grant", combined with IP/attributes | Fully flexible — but the **caller supplies** `current_time` in the request context (a trust decision: your PEP must be honest), the row stays in place when the window closes, and searches evaluate the expression per candidate. |
| **Application-side revocation** (delete the tuple at T, e.g. via a scheduler/outbox) | You want an explicit, auditable *revocation event* at T, or downstream consumers (watch/changefeed) must see the removal | Requires external machinery and is only as timely as it runs; between T and the delete, the grant still holds. |
| **Contextual tuples** ([§9](#9-contextual-tuples)) | The grant should live no longer than a single request | Nothing stored at all — the extreme end of "expiring". |

> ⚠ **Re-granting without `expires_at` makes a grant permanent.** `write_tuple`
> and the batch writers treat an omitted `expires_at` as "no expiry" and
> **clear** any existing expiry on the row (the upsert overwrites it). Generic
> synchronization / upsert code that doesn't carry the expiry forward will
> silently turn an expiring grant into a permanent one. If you re-grant, either
> pass the intended `expires_at` explicitly, or read the current value first
> (read-modify-write). Explicit per-write mutation semantics
> (preserve / set / clear) are a roadmap item.

Rule of thumb: reach for **`expires_at`** first; move to a **condition** only
when the window is more complex than "until T"; add **scheduled deletion** on
top of either when consumers need an explicit revocation event in the
changefeed. The demo walks the contrast in
[`examples/models/demo/demo.sql`](../examples/models/demo/demo.sql)
(sections 4 and 4z).

**Live expiry is judged per statement.** A live check/search compares
`expires_at` against `statement_timestamp()` (migration 0007), so expiry takes
effect at the start of each authorization statement — fresh per request (the
front door runs one statement per request) and consistent within a single
`list_*`. It is NOT frozen at transaction start, so a long-lived direct-SQL
transaction still sees a grant expire between its statements.

**Migration note — expiry and time travel.** The audit trail records
*transaction time*: `performed_at` is when **this system** learned a fact,
not when the fact was true in the real world. Two consequences for
migrations: importing a tuple whose `expires_at` already passed is rejected
as dead-on-arrival — it could never grant at any queryable moment, live or
historical (time-travel compares `expires_at` against the asked time, and
every queryable moment lies after the import); and importing historical
grants does **not** backfill `audit_check_access` for the pre-migration era.
Migrating systems should import only currently-live grants and treat the
old system's records as the historical source for anything earlier.


Conditions add **attribute-based access control** to the tuple model. A condition
is a named SQL boolean expression evaluated at check time, allowing access to
depend on runtime context (e.g., current time, IP address, feature flags).

### Defining a Condition

```sql
INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
    (authz._s('gdrive'), 'during_business_hours',
     $expr$($1->>'hour')::int BETWEEN 9 AND 17$expr$,
     '{"hour": "integer"}'::jsonb);
```

- `expression`: A SQL boolean expression where `$1` is the request-time context
  (JSONB passed by the caller) and `$2` is the tuple-stored context (JSONB
  stored alongside the tuple).
- `required_context`: the keys the expression needs, split into `request`
  (supplied at check time) and `stored` (saved with the tuple). Enforced:
  `write_tuple` rejects a conditional tuple whose stored context lacks a
  declared key, and a check whose request context lacks a declared key
  reports it (`condition_missing_keys` in `explain_access`,
  `missing_context` in `check_access_detailed`) — see
  [Missing context](#missing-context).
- `time_source` (`p_time_source` on `create_condition*`, default `server`):
  which clock `current_time` comes from. **`server`** (the default): the
  engine sets `current_time` from its own clock before evaluating this
  condition and ignores any caller value — statement time on live paths; on
  time-travel paths `current_time` is `p_at` for every condition, as before.
  Business hours, grant windows and anything a caller could be tempted to
  backdate are safe without the author knowing the option exists.
  **`caller`**: the request context supplies it — the enforcement point
  asserts a time. Choose it explicitly when the caller legitimately asks
  about another moment: tests and demos that pin the clock, "would this be
  allowed at T" asked live. The choice is part of the policy: a change is
  versioned in `conditions_audit`, the registry exports and propagates it,
  `describe_model` renders `# condition <name> (sql, server time)` /
  `(sql, caller time)`, and a denied step in `explain_access` names the
  clock. Conditions created before this option exists stay `caller`, so an
  upgrade changes no decision.

  ```sql
  -- business hours by the server's clock (the default)
  SELECT authz.create_condition_sql('gdrive', 'office_hours',
      $$ extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17 $$,
      '{"request": ["current_time"]}');
  -- a grant window the caller is allowed to ask about "as of" a time it supplies
  SELECT authz.create_condition_sql('gdrive', 'grant_window',
      $$ ($1->>'current_time')::timestamptz < ($2->>'until')::timestamptz $$,
      '{"request": ["current_time"], "stored": ["until"]}', p_time_source => 'caller');
  ```

### Writing Conditional Tuples

```sql
-- Bob can view, but only during business hours
SELECT authz.write_tuple('gdrive', 'user', 'bob', 'viewer', 'doc', 'secret_report',
    p_condition => 'during_business_hours');

-- Time-limited access with stored context
SELECT authz.write_tuple('gdrive', 'user', 'contractor', 'viewer', 'doc', 'project_plan',
    p_condition => 'time_window',
    p_condition_context => '{"grant_time": "2026-03-01T00:00:00Z", "grant_duration": "P30D"}'::jsonb);
```

### Checking with Context

Pass request-time context using `check_access_with_context`:

```sql
SELECT authz.check_access_with_context('gdrive', 'user', 'bob', 'viewer', 'doc', 'secret_report',
    '{"hour": 14}'::jsonb);
-- => true (2 PM is within business hours)

SELECT authz.check_access_with_context('gdrive', 'user', 'bob', 'viewer', 'doc', 'secret_report',
    '{"hour": 22}'::jsonb);
-- => false (10 PM is outside business hours)
```

The plain `check_access` (no context) treats conditional tuples as non-matching.
Unconditional tuples (no condition) are unaffected by the presence or absence
of context.

**When to use conditions:**
- Time-limited access (e.g., temporary contractor permissions)
- Business-hour restrictions
- Geographic or IP-based constraints
- Feature flags or license checks at the tuple level

### Other condition examples

```sql
-- IP allowlist: $1 has the client IP, $2 has the allowed CIDR range.
-- The regexp strips the IPv4-mapped IPv6 prefix (see the note below).
SELECT authz.create_condition_sql('demo', 'ip_in_range',
 $$regexp_replace(host(($1->>'client_ip')::inet), '^::ffff:', '')::inet
   <<= ($2->>'allowed_cidr')::cidr$$);

-- Office hours only: $1 has the current time, no stored context needed
SELECT authz.create_condition_sql('demo', 'office_hours',
 $$extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17$$);

-- Usage quota: $1 has the current usage count, $2 has the max allowed
SELECT authz.create_condition_sql('demo', 'under_quota',
 $$($1->>'usage_count')::int < ($2->>'max_allowed')::int$$);
```

> **CIDR conditions and IPv4-mapped IPv6 addresses.** Dual-stack listeners
> (Go's `net/http` included) often report an IPv4 client as the mapped IPv6
> form `::ffff:10.0.0.1`. PostgreSQL's `inet` keeps that as an IPv6 value
> (`family()` = 6), so `'::ffff:10.0.0.1'::inet <<= '10.0.0.0/8'` is **false**
> and a plain `<<=` allowlist silently denies (or, in an exclusion, silently
> fails to block) such clients. Normalise the address first, as the
> `ip_in_range` example does: `regexp_replace(host(ip), '^::ffff:', '')::inet`
> turns a mapped address into its IPv4 form and leaves plain IPv4 and real
> IPv6 addresses unchanged (RFC 4291 §2.5.5.2). Alternatively the PEP can
> unmap before it builds the request context.

### Missing context

A condition that cannot be evaluated because a required key (declared in
`required_context`) is absent never *grants*, on either side of the model:

- On a **granting** path the conditional tuple does not match (a
  `condition_denied` step with `condition_missing_keys`).
- On a **subtracted** path (`BUT NOT banned`, with `banned` a conditional
  tuple) the tuple is **assumed to match** — an unevaluable ban still bans
  (a `condition_assumed` step). Nested exclusions flip again, so "cannot
  evaluate" always resolves toward deny.

`check_access` therefore answers `false` in both cases;
`check_access_detailed` reports `state: "conditional"` with the keys in
`missing_context` when supplying them could change the answer, and `deny`
when it could not. (OpenFGA reaches the same fail-closed outcome by rejecting
the whole check with a *missing parameters* error.)

### Condition languages (`lang`)

Conditions carry a `lang` column selecting the expression language. `'sql'` is
the built-in default shown above — a SQL boolean over `$1` (request context) and
`$2` (stored context), evaluated in a zero-privilege sandbox, no dependencies.

`'cel'` is an **optional** language for friendlier ABAC expressions, evaluated by
the [`extensions/pg-cel`](../extensions/pg-cel) Rust/pgrx extension. The two
context bags are exposed as `request.*` and `stored.*`:

```sql
-- Same "not expired" rule, in CEL (requires the pg_cel extension).
SELECT authz.create_condition_cel('demo', 'cel_not_expired',
    'timestamp(request.current_time) < timestamp(stored.expires)',
    '{"request": ["current_time"], "stored": ["expires"]}');
```

Enable CEL by building the extension into the Postgres image and turning it on:

```bash
PGAUTHZ_CEL=1 ./start.sh    # or ./start.sh --cel — builds the pg_cel image
PGAUTHZ_CEL=1 ./init.sh     # runs CREATE EXTENSION pg_cel SCHEMA authz
```

`lang='cel'` writes are rejected until the evaluator is installed, so the default
stack is never left with conditions it can't run. For a runnable walk-through see
[`examples/models/demo/demo_cel.sql`](../examples/models/demo/demo_cel.sql).

**Validation is parse-only.** Both languages are syntax-checked at write time
(SQL test-compile / CEL compile), but undeclared variables, type mismatches, and
value formats are not — those deny at check time. A common CEL gotcha: `duration()`
wants a Go-style string (`"2h"`), not a Postgres interval (`"2 hours"`). Dry-run a
condition against representative context with `validate_condition` to catch such
issues early — it evaluates the real expression and raises on a bad value:

```sql
SELECT authz.validate_condition('demo', 'cel_not_expired',
    '{"expires": "2026-03-11T11:00:00Z"}'::jsonb,         -- stored context
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb);   -- request context
-- => true   (a malformed timestamp/duration in the context would raise here)
```

The engine dispatches languages in one place (`authz._eval_condition_expr`), so
adding cedar/rego later is additive. See
[`extensions/pg-cel/README.md`](../extensions/pg-cel/README.md) for the build and
the SQL-vs-CEL trade-offs (e.g. IP-range conditions stay `lang='sql'`).

---

## 9. Contextual Tuples

Contextual tuples are **ephemeral relationships** that exist only for the
duration of a single access check. They are not stored in the database.

This is useful when access depends on runtime state that shouldn't be
persisted — for example, "the user is currently the on-call engineer" or
"this request comes from an internal network."

```sql
SELECT authz.check_access_with_contextual_tuples(
    'gdrive', 'user', 'dave', 'can_read', 'doc', 'oncall_runbook',
    NULL,  -- no request context
    ARRAY[
        ROW('user', 'dave', NULL, 'viewer', 'doc', 'oncall_runbook')::authz.tuple_input
    ]);
-- => true (dave is treated as a viewer for this check only)
```

The `authz.tuple_input` composite type has fields:
`(user_type, user_id, user_relation, relation, object_type, object_id)`

Contextual tuples participate in all rule evaluation — direct lookups, userset
expansion, and TTU traversal — just like stored tuples, but they leave no
trace in the database or audit log.

---

## 10. Integration Pattern -- Propagating Tuples from Application Databases

When your application creates an object (e.g., a document) and the creating user
should automatically become its owner, the ownership must be propagated to the
authz database as a tuple. Since the application database and the authz database
are typically separate, you cannot wrap both writes in a single transaction.

### Transactional Outbox Pattern

Use the **transactional outbox** pattern to guarantee that every object creation
eventually produces the corresponding authz tuple:

```
Application DB transaction:
  1. INSERT INTO documents (id, title, created_by) VALUES ('doc-123', 'Q1 Report', 'alice');
  2. INSERT INTO outbox (event_type, payload)
     VALUES ('tuple_write', '{"store":"myapp","user_type":"user","user_id":"alice",
              "relation":"owner","object_type":"document","object_id":"doc-123"}');
COMMIT;

Background worker (polls outbox):
  - Reads pending outbox entries
  - Calls authz.write_tuple('myapp', 'user', 'alice', 'owner', 'document', 'doc-123')
  - Marks the outbox entry as processed
```

This gives you **at-least-once** delivery. The `write_tuple` call is idempotent
(`ON CONFLICT DO NOTHING`), so replaying an outbox entry is safe.

### The Access Gap

Between the application commit and the background worker processing, the owner
technically cannot access their own object via authz. In practice this is
milliseconds, but if it matters you have two options:

**Option A: Accept eventual consistency.** Most UIs redirect to the newly created
object after creation. By the time the user performs an action that triggers an
access check, the worker has already processed the outbox entry.

**Option B: Contextual tuple as a bridge.** Right after creation, the application
knows it just created the object, so it can pass ownership as a contextual tuple
for the initial access check:

```sql
-- The app just created doc-123 and knows alice is the owner
SELECT authz.check_access_with_contextual_tuples(
    'myapp', 'user', 'alice', 'can_read', 'document', 'doc-123',
    NULL,
    ARRAY[ROW('user','alice',NULL,'owner','document','doc-123')::authz.tuple_input]
);
```

Once the worker persists the real tuple, the contextual tuple becomes redundant
but harmless.

### Why Not Use Contextual Tuples Exclusively?

It may be tempting to skip persisting ownership tuples entirely and always pass
them as contextual tuples at query time. This works for simple `check_access`
calls but breaks down quickly:

- **`list_objects`** and **`list_subjects`** cannot return owned objects -- there
  is no persisted tuple to scan
- **`explain_access`** won't show the ownership path
- **Audit trail** doesn't capture ownership grants
- **Other services** that check access would all need the same ownership data
- Every caller must know the owner, coupling the authz check to the application
  data model

Contextual tuples are designed for **ephemeral, request-scoped context** -- things
like "the current time is 3pm" for time-based conditions, or "this request
originates from an internal network." Ownership is a durable fact and belongs in
the tuple store.

### Resolving Objects to Application Services

When a query like `list_objects` returns that a user can access `document:doc-123`,
the caller needs to know **which application service holds that document's data**.
The authz system stores authorization relationships, not application data -- so
how does the caller route to the right service?

The key insight is that routing is per **object type** (or namespace), not per
tuple. All documents come from the document service, all invoices from the
accounting service. This means the mapping belongs at the type/namespace level.

**Namespaces as the routing key.** The `types` table already has a `namespace`
column that groups types by domain. This same namespace can serve as a lookup key
for service routing:

```
Types table:                         Application registry (your config):
┌──────────┬─────────────┐           ┌──────────────┬──────────────────────┐
│ name     │ namespace   │           │ namespace    │ service_url          │
├──────────┼─────────────┤           ├──────────────┼──────────────────────┤
│ invoice  │ accounting  │           │ accounting   │ http://accounting/api│
│ receipt  │ accounting  │           │ hr           │ http://hr-service/api│
│ employee │ hr          │           │ documents    │ http://docs-svc/api  │
│ document │ documents   │           └──────────────┴──────────────────────┘
└──────────┴─────────────┘
```

**Where to store the service registry.** This mapping lives in **your
application's configuration**, not in the authz database. The authz system is
concerned with "who can access what," not "where the data lives." Options:

- **Application config / environment variables** -- simplest for small
  deployments. Each service knows its own namespace.
- **Service discovery** (Consul, Kubernetes services) -- namespace maps to a
  service name that resolves via DNS or service mesh.
- **API gateway routing table** -- the gateway maps
  `/{namespace}/{object_id}` to the backing service.

**Example flow -- listing accessible objects with data:**

```
1. Client calls: list_objects('myapp', 'user', 'alice', 'can_read', 'invoice')
   → returns: ['inv-001', 'inv-002', 'inv-003']

2. Client looks up: type 'invoice' → namespace 'accounting'
                     namespace 'accounting' → http://accounting/api

3. Client fetches: GET http://accounting/api/invoices?ids=inv-001,inv-002,inv-003
   → returns invoice data (only for objects the user can access)
```

**Why not store the application URL in tuples?** Adding a service/origin column
to the `tuples` table would:

- Bloat every row (potentially millions) with redundant data -- all invoices
  point to the same service
- Couple the authorization model to deployment topology
- Require updating tuples when services move or URLs change

Since the mapping is always type/namespace → service (not tuple → service), it
belongs in configuration, not in authorization data.

### Namespace-Based Access Control

When multiple applications share a single store, **namespaces** restrict
which application can read or write tuples for which object types. This prevents
one application from accidentally modifying or querying another's authorization data.

- Types with `namespace = NULL` are **unrestricted** — any role can read and write them.
- Types with a non-NULL namespace require the **effective request role** to be a member of a
  granted role. The effective role is the `SET ROLE` identity (what pgauthzd switches to
  per request, from the forwarded `X-PGAuthz-Role`), falling back to the session user for direct connections.
- **Read and write access** is controlled via `authz.namespace_access` using `can_read` and `can_write` flags.

```sql
-- Assign namespaces to types
UPDATE authz.types SET namespace = 'hr'
 WHERE store_id = authz._s('demo')
   AND name IN ('engagement', 'assignment');

UPDATE authz.types SET namespace = 'documents'
 WHERE store_id = authz._s('demo')
   AND name IN ('document', 'upload_request');

-- Grant access per namespace to application roles
INSERT INTO authz.namespace_access (store_id, namespace, db_role, can_read, can_write) VALUES
    (authz._s('demo'), 'hr',        'app_hr',     true, true),
    (authz._s('demo'), 'hr',        'app_portal', true, false),  -- portal can read HR data but not write
    (authz._s('demo'), 'documents', 'app_dms',    true, true);

-- Wire up: DB users get their application role
GRANT app_hr     TO hr_backend_user;
GRANT app_dms    TO dms_backend_user;
GRANT app_portal TO portal_user;
```

Now `hr_backend_user` can read and write tuples for `engagement` and `assignment`,
`dms_backend_user` can read and write tuples for `document` and `upload_request`,
and `portal_user` can read (but not write) HR authorization data.

Write namespace enforcement applies to: `write_tuple`, `delete_tuple`, `write_tuples`,
`delete_tuples`, `delete_user_tuples`.

Read namespace enforcement applies to: `check_access`, `check_access_with_context`,
`check_access_with_contextual_tuples`, `list_objects`, `list_subjects`, `list_actions`,
`explain_access`, `audit_check_access`, `audit_list_actions`.

Namespace read checks apply only to the **top-level object type** being queried.
Internal TTU traversals across type boundaries are not restricted — this ensures
cross-domain models work correctly while still controlling which applications can
initiate queries against which types.

---

## 11. Revoking Access and Maintenance

### Deleting Tuples

Remove a specific tuple to revoke access:

```sql
SELECT authz.delete_tuple('gdrive', 'user', 'bob', 'viewer', 'doc', 'design_spec');
```

Bulk-revoke all tuples for a user across the entire store:

```sql
SELECT authz.delete_user_tuples('gdrive', 'user', 'bob');
```

### Batch Operations

Write or delete multiple tuples in a single call:

```sql
SELECT authz.write_tuples('gdrive', ARRAY[
    ROW('user', 'alice', NULL, 'viewer', 'doc', 'd1')::authz.tuple_input,
    ROW('user', 'bob',   NULL, 'viewer', 'doc', 'd2')::authz.tuple_input
]);
```

### Modifying Model Rules

Remove a single rule by its ID (returned by `model_add_rule` or visible in
`models_view`):

```sql
-- Find the rule ID
SELECT id, object_type, relation, rule_type, computed_relation
  FROM authz.models_view WHERE store = 'gdrive';

-- Remove it
SELECT authz.model_remove_rule('gdrive', 42::smallint);
-- => true (deleted) or false (not found / wrong store)
```

Remove all rules for a specific relation (useful when redefining how a
relation is resolved):

```sql
SELECT authz.model_remove_rules('gdrive', 'doc', 'can_read');
-- => 3 (number of rules deleted)
```

**Zero-downtime rule changes:** Between removing old rules and adding new
ones, access checks for that relation will deny. To avoid this, add the
new rules first with `model_add_rule`, then remove the old ones
individually with `model_remove_rule`:

```sql
-- 1. Add the new rule (safe — existing rules still active)
SELECT authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
    p_computed_relation => 'collaborator');

-- 2. Remove the old rule by ID (now the new rule covers access)
SELECT authz.model_remove_rule('gdrive', 42::smallint);
```

### What Happens to Tuples When Rules Are Removed?

Removing a model rule does **not** delete any tuples. The tuples become **inert**
— they still exist in the `tuples` table but have no effect on access checks
because no rule references them.

This is intentional:

- **Only direct rules have "their own" tuples.** Computed and TTU rules reference
  tuples belonging to other relations — there's nothing to clean up.
- **Tuples may be shared.** A `viewer` tuple might be used by both a direct rule
  on `doc#viewer` and a TTU rule on `folder#can_read`. Removing one rule
  shouldn't destroy data the other depends on.
- **Model evolution.** You may temporarily remove a rule to redefine it. Cascade-
  deleting tuples during that window would be destructive and irreversible.

To clean up orphaned tuples after a rule removal, delete them explicitly:

```sql
-- After removing the direct rule for doc#viewer:
SELECT authz.delete_tuples('gdrive', ARRAY[
    ('user','alice',NULL,'viewer','doc','doc1'),
    ('user','bob',  NULL,'viewer','doc','doc2')
]::authz.tuple_input[]);
```

Use `find_redundant_tuples` (below) to identify tuples that no longer contribute
to any access decision.

### Removing a Type

Removing a whole type is a bigger step than removing a rule: a type owns a
tuple partition, may be the *subject* type of other types' restrictions, and
may be named by gates and recorded events. `model_remove_type` does the whole
job and fails closed on every reference it will not remove on its own:

| Reference | Behaviour |
|---|---|
| Temporal gates on the type, events naming it | Always refused: drop the gates / purge the events first |
| Tuples naming the type as object **or** subject | Refused unless `p_force => true`, which deletes them (expired rows too) through the audited path |
| Rules on the type, restrictions naming it on either side | Removed (logged to `models_audit`) |
| Relations its rules used | Kept — other types may use them |
| The type's tuple partition | Dropped |
| Audit history | Kept under the type's integer id, with a `TYPE_REMOVED` marker; no longer resolvable by name |

```sql
SELECT authz.model_remove_type('gdrive', 'legacy_share', p_force => true);
-- {"type": "legacy_share", "tuples_deleted": 40, "rules_removed": 2, "restrictions_removed": 1, "partition_dropped": true}
```

Because time travel resolves names against the live dictionary, removing a
type makes "could X read legacy_share:1 last month" unanswerable from then
on — the same trade-off as `delete_store` versus `retire_store`. For an
audit-critical store, leave the type registered and delete its tuples. The
registry uses this function for types a new version no longer declares (see
[§16](#16-sharing-one-model-across-stores-model-registry)).

### Finding Redundant Tuples

Over time, models accumulate tuples that are redundant — access is already
granted by another rule (e.g., an explicit `viewer` tuple on a doc whose
parent folder already grants `viewer` via TTU). Use `find_redundant_tuples`
to identify them:

```sql
SELECT * FROM authz.find_redundant_tuples('gdrive');
-- Returns tuples that could be removed without changing any access decisions

-- Scope to a specific object type or relation
SELECT * FROM authz.find_redundant_tuples('gdrive', 'doc', 'viewer');
```

This function is read-only and safe to run on a replica.

---

## 12. Complete SQL

Here is the full model definition in a single DO block — types, relations,
partitions, and model rules:

```sql
DO $$
BEGIN
    -- Create the store
    PERFORM authz.create_store('gdrive', 'Google Drive permission model');

    -- Types (model_register_type also creates the tuple partition)
    PERFORM authz.model_register_type('gdrive', 'user');
    PERFORM authz.model_register_type('gdrive', 'group');
    PERFORM authz.model_register_type('gdrive', 'folder');
    PERFORM authz.model_register_type('gdrive', 'doc', 8);  -- hash sub-partitions for high volume

    -- Relations
    PERFORM authz.model_register_relation('gdrive', 'member');
    PERFORM authz.model_register_relation('gdrive', 'owner');
    PERFORM authz.model_register_relation('gdrive', 'parent');
    PERFORM authz.model_register_relation('gdrive', 'viewer');
    PERFORM authz.model_register_relation('gdrive', 'can_create_file');
    PERFORM authz.model_register_relation('gdrive', 'can_change_owner');
    PERFORM authz.model_register_relation('gdrive', 'can_read');
    PERFORM authz.model_register_relation('gdrive', 'can_share');
    PERFORM authz.model_register_relation('gdrive', 'can_write');

    -- ── type group ─────────────────────────────────────────────
    -- define member: [user]
    PERFORM authz.model_add_rule('gdrive', 'group', 'member', 'direct');

    -- ── type folder ────────────────────────────────────────────
    -- define owner: [user]
    PERFORM authz.model_add_rule('gdrive', 'folder', 'owner', 'direct');
    -- define parent: [folder]
    PERFORM authz.model_add_rule('gdrive', 'folder', 'parent', 'direct');

    -- define viewer: [user, user:*, group#member] or owner or viewer from parent
    PERFORM authz.model_add_rule('gdrive', 'folder', 'viewer', 'direct');
    PERFORM authz.model_add_rule('gdrive', 'folder', 'viewer', 'computed',
        p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('gdrive', 'folder', 'viewer', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'viewer');

    -- define can_create_file: owner
    PERFORM authz.model_add_rule('gdrive', 'folder', 'can_create_file', 'computed',
        p_computed_relation => 'owner');

    -- define can_write: owner or can_write from parent
    PERFORM authz.model_add_rule('gdrive', 'folder', 'can_write', 'computed',
        p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('gdrive', 'folder', 'can_write', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'can_write');

    -- define can_share: owner or can_share from parent
    PERFORM authz.model_add_rule('gdrive', 'folder', 'can_share', 'computed',
        p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('gdrive', 'folder', 'can_share', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'can_share');

    -- ── type doc ───────────────────────────────────────────────
    -- define owner: [user]
    PERFORM authz.model_add_rule('gdrive', 'doc', 'owner', 'direct');
    -- define parent: [folder]
    PERFORM authz.model_add_rule('gdrive', 'doc', 'parent', 'direct');
    -- define viewer: [user, user:*, group#member]
    PERFORM authz.model_add_rule('gdrive', 'doc', 'viewer', 'direct');

    -- define can_change_owner: owner
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_change_owner', 'computed',
        p_computed_relation => 'owner');

    -- define can_read: viewer or owner or viewer from parent
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
        p_computed_relation => 'viewer');
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'computed',
        p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_read', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'viewer');

    -- define can_share: owner or can_share from parent
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_share', 'computed',
        p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_share', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'can_share');

    -- define can_write: owner or can_write from parent
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_write', 'computed',
        p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('gdrive', 'doc', 'can_write', 'ttu',
        p_tupleset_relation => 'parent',
        p_tupleset_computed => 'can_write');
END $$;
```

---

## 13. Importing from OpenFGA

If you already have an OpenFGA model in JSON format, you can import it directly
instead of writing SQL by hand:

```sql
SELECT authz.import_openfga_model('gdrive', '{
  "schema_version": "1.1",
  "type_definitions": [
    {"type": "user", "relations": {}},
    {"type": "group", "relations": {
      "member": {"this": {}}
    }},
    {"type": "folder", "relations": {
      "owner":  {"this": {}},
      "parent": {"this": {}},
      "viewer": {"union": {"child": [
        {"this": {}},
        {"computedUserset": {"relation": "owner"}},
        {"tupleToUserset": {
          "tupleset": {"relation": "parent"},
          "computedUserset": {"relation": "viewer"}
        }}
      ]}},
      "can_create_file": {"computedUserset": {"relation": "owner"}},
      "can_write": {"union": {"child": [
        {"computedUserset": {"relation": "owner"}},
        {"tupleToUserset": {
          "tupleset": {"relation": "parent"},
          "computedUserset": {"relation": "can_write"}
        }}
      ]}},
      "can_share": {"union": {"child": [
        {"computedUserset": {"relation": "owner"}},
        {"tupleToUserset": {
          "tupleset": {"relation": "parent"},
          "computedUserset": {"relation": "can_share"}
        }}
      ]}}
    }},
    {"type": "doc", "relations": {
      "owner":  {"this": {}},
      "parent": {"this": {}},
      "viewer": {"this": {}},
      "can_change_owner": {"computedUserset": {"relation": "owner"}},
      "can_read": {"union": {"child": [
        {"computedUserset": {"relation": "viewer"}},
        {"computedUserset": {"relation": "owner"}},
        {"tupleToUserset": {
          "tupleset": {"relation": "parent"},
          "computedUserset": {"relation": "viewer"}
        }}
      ]}},
      "can_share": {"union": {"child": [
        {"computedUserset": {"relation": "owner"}},
        {"tupleToUserset": {
          "tupleset": {"relation": "parent"},
          "computedUserset": {"relation": "can_share"}
        }}
      ]}},
      "can_write": {"union": {"child": [
        {"computedUserset": {"relation": "owner"}},
        {"tupleToUserset": {
          "tupleset": {"relation": "parent"},
          "computedUserset": {"relation": "can_write"}
        }}
      ]}}
    }}
  ]
}'::jsonb);
```

The import function automatically:
- Creates the store (or reuses an existing one)
- Registers all types and relations
- Creates tuple partitions
- Translates `this` → direct, `computedUserset` → computed,
  `tupleToUserset` → TTU
- Expands `union` into multiple model rules

> **Note:** `import_openfga_model` translates OpenFGA `intersection` and
> `difference` (alias: `exclusion`) natively into rule groups (see
> [Rule Groups — Intersection and Exclusion](#rule-groups--intersection-and-exclusion)):
>
> - `intersection` → one **AND group** containing all children
> - `difference` → **exclusion group(s)**: because base rules within one
>   exclusion group are AND-ed, a union base is expanded into one group
>   per base alternative, each carrying the negated subtract rule(s)
> - operator children of a `union` get their own groups (groups are OR'd)
>
> Operators may nest at most **one level below union**. Deeper nesting
> raises an error — the importer never silently imports a more
> permissive approximation. Re-model such relations manually as shown
> below.

#### Example: how intersection/exclusion map to rule groups

Given this OpenFGA model:

```
type document
  relations
    define member: [user]
    define licensed: [user]
    define blocked: [user]
    define can_view: member and licensed
    define can_comment: member but not blocked
```

`import_openfga_model` translates this into:

- `can_view` → one intersection group: `member` AND `licensed`
- `can_comment` → one exclusion group: `member` base, `blocked` negated

The equivalent manual SQL (useful when re-modeling relations the
importer rejects for deep operator nesting):

```sql
-- can_view = member AND licensed (intersection group)
SELECT authz.model_remove_rules('mystore', 'document', 'can_view');
SELECT authz.model_add_rule('mystore', 'document', 'can_view', 'computed',
    p_computed_relation => 'member',
    p_group_id => 1::smallint, p_group_op => 'intersection');
SELECT authz.model_add_rule('mystore', 'document', 'can_view', 'computed',
    p_computed_relation => 'licensed',
    p_group_id => 1::smallint, p_group_op => 'intersection');

-- can_comment = member BUT NOT blocked (exclusion group;
-- add the base rule before the negated one)
SELECT authz.model_remove_rules('mystore', 'document', 'can_comment');
SELECT authz.model_add_rule('mystore', 'document', 'can_comment', 'computed',
    p_computed_relation => 'member',
    p_group_id => 1::smallint, p_group_op => 'exclusion');
SELECT authz.model_add_rule('mystore', 'document', 'can_comment', 'computed',
    p_computed_relation => 'blocked',
    p_group_id => 1::smallint, p_group_op => 'exclusion', p_negated => true);
```

If the OpenFGA base is a union — e.g.
`define can_read: (viewer or editor) but not blocked` — remember that
base rules within one exclusion group are AND-ed: use one exclusion
group per base alternative as shown in
[Exclusion (BUT NOT)](#exclusion-but-not).

---

## 14. Recursive Hierarchies — Folders & Filesystems

A very common need is a nested container hierarchy — folders that contain
subfolders and documents, where a permission granted on a folder flows **down**
to everything inside it. The demo `folder` type models exactly this:

```
type folder
  relations
    define parent: [folder]                                   # nesting
    define owner:  [internal_user, team#member]
    define editor: [internal_user, team#member]
    define viewer: [internal_user, team#member]
    define can_view: viewer or editor or owner or can_view from parent
    define can_edit: editor or owner or can_edit from parent

type document                                                 # (additions)
    define parent_folder: [folder]
    define can_read: … or can_view from parent_folder
    define can_edit: … or can_edit from parent_folder
```

`can_view from parent` is a [TTU](#tuple-to-userset-ttu) that the engine follows
**recursively** up the `parent` chain, so a grant anywhere on the path is inherited
by every descendant.

### Identity vs. structure — use stable IDs

Model an object as `folder:<stable-id>` (the app's internal folder UUID), **never**
its name or path (`folder:/foo/bar`). Names and paths are application metadata the
engine neither stores nor needs. The payoff:

- **Rename** a folder → **zero** pgauthz writes (the id is unchanged).
- **Move** a folder → **one** tuple update (its `parent`; see below).
- **Create / delete** → one tuple.

### Do you need every intermediate folder?

Not necessarily — it depends on where you keep the hierarchy. The `folder` **type**
is declared once; an individual folder exists *only* as tuples, so "representing a
folder" means writing its `parent` link (and `parent_folder` links for its docs).
There are three approaches:

| Approach | Stored in pgauthz | Structure sync | Reverse queries¹ |
|---|---|---|---|
| **A. Mirror the tree** | grants **+** the `parent` / `parent_folder` chain | create / move / delete (rename-free with stable IDs) | ✅ yes |
| **B. Contextual tuples** | **only grants** | none | ❌ no |
| **C. App resolves ancestors** | **only grants** (no `parent` relation) | none | ❌ no |

¹ Whether `list_objects` ("everything alice can read") and `list_subjects` ("who
can read this doc") traverse the hierarchy.

**A — mirror the tree.** Write the containment chain from each protected resource
up to (and including) any folder where a grant may live — *including grant-less
intermediate folders*, which are the pass-through links the upward walk needs. You
do **not** need sibling folders or unrelated subtrees, and a folder that holds
nothing protected and grants nothing needn't exist. Sync lazily (write the `parent`
tuple on folder-create, `parent_folder` on doc create/move) — don't bulk-import the
filesystem. Only approach A supports reverse/list queries over the hierarchy.

**B — contextual tuples.** Store *only the grants*; keep the tree entirely in your
app. At check time, supply the ancestor chain as
[contextual (ephemeral) tuples](#9-contextual-tuples):

```
check(alice, can_read, document:mydoc,
  contextual: [ mydoc#parent_folder=baz, baz#parent=bar, bar#parent=foo ])
```

The engine runs the same recursive walk over the ephemeral edges + stored grants.
Renames/moves never touch pgauthz. The cost: point checks only — the tree isn't
stored, so reverse/list queries can't traverse it.

**C — app resolves ancestors.** Drop `folder.parent` entirely; have the app
enumerate the path's ancestor folders and `check_access_batch` `can_view` on each.
Simplest model; all hierarchy logic lives in the app.

**Choosing:** need reverse/list queries over the hierarchy → **A**. Only point
checks and want zero structure to sync → **B**. Want the simplest engine model →
**C**.

### The check recurses for you

Regardless of nesting depth, the application sends **one** check on the document id
— it does *not* resolve the path, pass ancestors, or walk the tree (the engine does
that via the tuples/contextual tuples):

```
document.can_read ← can_view from parent_folder → folder:baz.can_view
folder.can_view   ← viewer/editor/owner  OR  can_view from parent → …bar → …foo
                                          → foo.can_view ← viewer(alice) ✓
```

A document stores only its **immediate** `parent_folder`; ancestry is the folder
`parent` chain (like a filesystem where each node knows its parent). Depth is
bounded by the engine's resolution limit (32 hops; ~15–25 nested folders) and is
memoized within a check. For pathologically deep or very hot paths, denormalize
(materialize effective grants) — trading write amplification for shallow reads.

### Moving a subtree is one edge repoint

Because each node points at its *immediate* parent by stable id, moving
`/foo/bar/baz` → `/foo/baz` changes only **baz's own `parent`** — every descendant
(and their `parent_folder` links) is untouched and moves implicitly. Do it
atomically with an optimistic-concurrency precondition via
[`write_tuples_checked`](#batch-operations):

```sql
authz.write_tuples_checked('store',
  p_preconditions := '[{"match":"exists","user_type":"folder","user_id":"bar",
                        "relation":"parent","object_type":"folder","object_id":"baz"}]',
  p_deletes       := '[{"user_type":"folder","user_id":"bar",
                        "relation":"parent","object_type":"folder","object_id":"baz"}]',
  p_writes        := '[{"user_type":"folder","user_id":"foo",
                        "relation":"parent","object_type":"folder","object_id":"baz"}]');
```

Notes:

- **No stale-grant cleanup** — inheritance recomputes on read; baz instantly
  inherits from `foo` and stops inheriting from `bar`.
- **No `child` bookkeeping** — "child" is the implicit reverse of `parent`, derived
  by query; there's no second tuple to keep in sync.
- **Preconditions can be access checks, too.** `"match": "allowed"` (or
  `"denied"`) with `user_type, user_id, relation, object_type, object_id,
  context?` decides the precondition like `check_access_with_context` —
  computed relations, conditions, gates included — so "move only if the
  mover may write the destination folder" is one atomic call with no
  separate check that could race the write.
- **No special "move" primitive is needed.** `write_tuples_checked` *is* the
  atomic multi-tuple update. A folder-aware move op would bake filesystem semantics
  into a deliberately model-agnostic relationship engine — `folder` is just a
  modeling convention. Orchestrate the move in the application.
- The only move that touches many tuples is under a **denormalized** ancestor-list
  model — and `write_tuples_checked` still applies that batch atomically; the write
  amplification is the cost of the denormalization you opted into.

---

## 15. Decision Guide -- Which Relationship Type?

```
Is the relation explicitly assigned by writing a tuple?
  └─ YES → DIRECT
       Examples: owner, member, viewer, parent

Does the relation mean "same as another relation on THIS object"?
  └─ YES → COMPUTED
       Examples: can_read includes owner (owners can read)
                 can_write is an alias for owner
                 internal_collaborator = advisor OR assistant

Does the relation depend on a link to ANOTHER object?
  └─ YES → TTU (Tuple-to-Userset)
       Examples: can_read inherited from parent folder's viewer
                 repo admin delegated from owning org's repo_admin
                 document permissions from containing data space
```

**Summary table:**

| Pattern | Rule Type | OpenFGA Equivalent | Example |
|---------|-----------|-------------------|---------|
| User is explicitly granted a role | Direct | `[user]`, `this` | `user:alice` is `owner` of `doc:spec` |
| Role A implies role B on same object | Computed | `computedUserset` | `owner` implies `can_read` on same doc |
| Role on linked object grants role here | TTU | `tupleToUserset` | `viewer` on parent folder grants `can_read` on doc |
| Group membership grants access | Direct + Userset | `[group#member]` | `group:eng#member` is `viewer` of `folder:shared` |
| Public access (everyone) | Direct + Wildcard | `[user:*]` | `user:*` is `viewer` of `folder:public_docs` |
| Multiple ways to get a role (union) | Multiple rules | `union` | `can_read` = viewer OR owner OR viewer from parent |
| All conditions must hold | Intersection group | `intersection` | `can_view` = member AND licensed |
| Access minus denial | Exclusion group | `exclusion` / `difference` | `can_comment` = member BUT NOT blocked |

### Common Patterns

**Role hierarchy** (computed chain):
```
can_delete → can_write → can_read → viewer
```
Each level is a computed rule pointing to the level above.

**Folder inheritance** (TTU + recursion):
```
folder.viewer from parent  →  folder.viewer from parent  →  ...
```
The engine follows `parent` links recursively up the folder tree. See
[Recursive Hierarchies — Folders & Filesystems](#14-recursive-hierarchies--folders--filesystems)
for the full pattern (which folders to store, moves/renames, contextual-tuple
alternative).

**Organization delegation** (TTU through owner):
```
repo.admin from owner → organization.repo_admin
```
The org's `repo_admin` role propagates to all repos owned by that org.

**Group-based access** (direct + userset expansion):
```
group:engineering#member → viewer → folder:shared
```
Write a tuple with `p_user_relation = 'member'`, and the engine expands
group membership automatically.

**Public access** (wildcard):
```
user:* → viewer → folder:public_docs
```
Write a tuple with `user_id = '*'`. Any user of that type gets the relation
without an individual tuple. Propagates through computed relations and TTU.

## 16. Sharing One Model Across Stores (Model Registry)

Multi-tenant deployments typically run **one store per tenant**: tuples are
isolated by construction (a check in tenant A's store can never traverse
tenant B's tuples), while all tenants share the same *authorization model*.
The model registry turns that shared model into a first-class, versioned
artifact instead of N hand-maintained copies.

The workflow is author → publish → apply:

```sql
-- 1. Author the model in one store (the "authoring" store), using the
--    normal model API from the sections above.
SELECT authz.create_store('model_dev');
-- ... model_register_type / model_register_relation / model_add_rule ...

-- 2. Publish it as the next immutable version of a named model.
SELECT authz.publish_model('saas_core', 'model_dev', 'adds can_export');
-- => 3   (the new version; republishing an UNCHANGED model returns the
--         existing version instead of minting a new one)

-- 3. Roll it out: canary one tenant store first, then the fleet.
SELECT authz.apply_model('tenant_acme', 'saas_core');        -- latest
SELECT * FROM authz.apply_model(                              -- fleet
    ARRAY['tenant_beta', 'tenant_gamma'], 'saas_core', 3);
```

`apply_model` works on a brand-new store (it creates all types with their
tuple partitions) and on a store already running an older version — it
performs an exact diff through the regular model API, so model validation
stays engaged and every change lands in `models_audit` for time-travel.
After syncing it re-exports the store and verifies the checksum against the
registry version: an apply either converges exactly or aborts (single
transaction — a failed apply changes nothing).

What a definition contains: types (with namespace, description, labels),
relations, rules, type restrictions, and conditions. What it deliberately
does NOT contain: tuples (per-tenant data) and `namespace_access` role
grants (deployment-specific). Hash-partition sizing (`hash_modulus`) is
recorded for creating new stores but excluded from checksums — a big tenant
with more sub-partitions is not "drifted".

Two guard rails to know about:

- **Types are never removed automatically.** A store with a type that the
  definition lacks fails the apply — a type owns a tuple partition, so its
  removal stays a manual, deliberate act.
- **Stale relations are only removed when unreferenced.** If tuples still
  reference a relation that the new version dropped, the apply aborts and
  names the relation — delete those tuples first. (Rules being removed is
  fine: the affected tuples simply stop granting, which is normal model
  semantics.)

Detecting state across the fleet:

```sql
SELECT * FROM authz.model_status('tenant_acme');
-- => model_name, model_version, applied_at/by, in_sync, checksums.
--    in_sync = false means the store's live model no longer matches the
--    version it applied (someone hand-edited it) — re-apply to repair.

SELECT * FROM authz.model_rollout_status('saas_core');
-- => one row per store bound to the model: its version, the registry's
--    latest version, and whether it is still in sync.

SELECT * FROM authz.list_model_versions('saas_core');
```

`publish_model` / `apply_model` require `authz_admin`; the status/export
functions are available to `authz_reader` (like `describe_model`). Stores
never touched by `apply_model` are "unmanaged" — nothing changes for them,
and `model_status` reports NULL model fields plus their live checksum so
tooling can still fingerprint hand-rolled models.

**Zero-downtime note:** within one `apply_model`, stale rules are deleted
and new ones added in the *same transaction*, so concurrent checks never
observe the intermediate state — the "add new rules before removing old
ones" dance from [§11](#11-revoking-access-and-maintenance) is only needed
when editing a model by hand.

**Fleet-apply scope and scale.** The array variant runs all stores in **one
transaction**: a failure on any store rolls back the whole call, and nothing
is left half-rolled-out. That atomicity is exactly right for small fleets
(tens of stores) — and exactly wrong for large ones, where a single call
means a long-running transaction, broad locks, and an all-or-nothing failure
domain across hundreds of tenants. For large fleets, drive the rollout from
an **external orchestrator**: canary with a single-store `apply_model`, then
apply in bounded batches (pinning the version number so a concurrent publish
can't split the fleet), using `model_rollout_status` as the persisted
progress/retry view — any store that failed or was skipped simply shows the
old version and is retried individually.

**Rolling back is a forward operation.** Versions are immutable, and
`apply_model('store', 'name', <older version>)` re-applies an older
definition — but that is a *new rollout*, not an undo, and it inherits the
same guard rails: types added by the newer version are removed by the
rollback only while nothing references them (`model_remove_type` without
force), and relations that tenant tuples have referenced in the meantime
block their own removal. Data written under the newer model can
make the older model unreachable without cleanup. Plan model evolution the
way you plan schema migrations — **expand → migrate → contract**: ship
additive versions first (new relations/rules alongside the old), migrate
tuples, and only then publish the version that removes the old shape.

**Plan before you apply.** `plan_model_apply` is the read-only dry-run of
`apply_model` — same store, same version resolution, but it *reports* instead
of changing anything:

```sql
SELECT jsonb_pretty(authz.plan_model_apply('tenant_acme', 'saas_core', 3));
-- {
--   "store": "tenant_acme", "model": "saas_core", "version": 3,
--   "no_op": false,            -- live model already matches? nothing to do
--   "can_apply": false,        -- false ⇒ apply_model would raise; see blockers
--   "current": {"model_name": "saas_core", "model_version": 2, "in_sync": true},
--   "blockers": [
--     {"kind": "relation_referenced_by_tuples", "name": "legacy_viewer", "tuples": 41}
--   ],
--   "changes": {
--     "types":             {"add": ["folder"], "update": []},
--     "relations":         {"add": ["can_export"], "remove": ["legacy_viewer"]},
--     "rules":             {"add": [...], "remove": [...]},
--     "type_restrictions": {"add": [...], "remove": [...]},
--     "conditions":        {"add": [], "update": ["biz_hours"], "remove": []}
--   },
--   "rollback": {            -- could you re-apply the CURRENT version (2) after this?
--     "to_version": 2,
--     "possible": false,     -- v3 adds a type; rolling back must remove it (only while unreferenced)
--     "type_removals_required": ["folder"],
--     "relations_requiring_removal": ["can_export"]
--   }
-- }
```

Blocker kinds map one-to-one to `apply_model`'s guard rails:
`type_referenced` (the store has a type the definition lacks **and** tuples,
a gate or recorded events still name it — an unreferenced extra type is
removed by apply via `model_remove_type`), `relation_referenced_by_tuples`
(delete those tuples first), and `cel_evaluator_missing` (the definition
carries CEL conditions but the store's database has no evaluator installed).
The plan diffs the same canonical name-based exports the checksums hash, so
"empty changes" and "no_op" agree with `model_status` by construction. It is
advisory: tuple-reference blockers reflect the moment of planning, and
`apply_model` re-checks everything transactionally — the plan predicts, the
apply enforces. `plan_model_apply` is reader-callable (like `model_status`),
so CI/CD pipelines can gate a rollout on `can_apply` and on
`rollback.possible` without admin credentials.

## 17. Temporal Gates (History-Dependent Rules)

Temporal gates are **centrally managed, history-dependent veto rules over
trusted recorded actions**. They are ideal for quotas, freshness, prior
approval, lockout, separation of duties and agent guardrails. They are **not a
workflow engine** and **not a substitute for reliable PEP event recording**.
Dogwood-inspired, not Dogwood-compatible: four fixed primitives, `all_of`,
veto-only — no `since`/`until`, no nested quantifiers, no policy code.

Everything above answers a point-in-time question: *given the graph and the
request context, may X do Y on Z?* Temporal gates add a second axis — *given
what X has already done* — over the **action log** (`authz.events`, the
per-principal record of actions your application reports after they ran; see
[ADR 0012](adr/0012-action-log.md) and the README's `record_event`). A gate is a
declarative set of clauses attached to an `(object_type, relation)`; the engine
evaluates it **after** the graph allows, for the checked principal, and any
failing clause denies. Gates never grant.

```sql
-- Declare the action vocabulary (an action is a relation of the store).
SELECT authz.model_register_relation('bank', 'approve_sale');

SELECT authz.add_gate('bank', 'account', 'transfer', 'velocity_backstop', '{
  "description": "transfer velocity backstop",
  "all_of": [
    {"count_within": {"window": "1h", "kind": "request", "max": 5, "plus": 1}},
    {"sum_within":   {"window": "1h", "kind": "response", "field": "input.amount",
                      "plus": "$request.input.amount", "max": 5000}},
    {"formerly_within": {"window": "1h", "action": "approve_sale", "kind": "response",
                         "match": {"input.stock": "$request.input.stock", "output.approved": true},
                         "recorded_by": ["svc:approvals"]}}
  ]}');
```

With that gate, `check_access_with_context('bank', 'user', 'alice', 'transfer',
'account', 'acc-1', '{"input": {"amount": 1200, "stock": "ACME"}}')` allows
only if the graph allows **and** this is at most alice's 5th transfer request
in the last hour **and** her completed transfers plus this one stay within 5000
**and** an approval service recorded an approved `approve_sale` for `ACME`
within the hour.

### The grammar

A gate object has `all_of` (1–16 clauses, AND), an optional `description`,
and an optional `mode`: `enforce` (default), `shadow`, or `off` (see
[Rolling a gate out](#rolling-a-gate-out-shadow-mode)). Each clause is an object with exactly one key — the
primitive — and a body:

| Key | `formerly_within` | `count_within` | `count_distinct_within` | `sum_within` | Value |
|---|---|---|---|---|---|
| `window` | one of window / calendar | ● | ● | ● | fixed-length interval text: `10m`, `1h`, `2 days`, `PT30M`, `P1W` (no months/years) |
| `calendar` + `tz` | ✓ | ✓ | ✓ | ✓ | `hour` / `day` / `week` / `month` / `year` with an IANA zone: the bucket containing now |
| `scope` | ✓ | ✓ | ✓ | ✓ | `subject` (default): the principal's events on any object; `object`: only its events on the **checked** object — "3 downloads of *this* file", "the submitter of *this* object may not approve it" |
| `action` | ✓ | ✓ | ✓ | ✓ | a relation name of the store; default: the gate's own relation |
| `kind` | ✓ | ✓ | ✓ | ✓ | `request` (default) / `response` / `denied` |
| `match` | ✓ | ✓ | ✓ | ✓ | `{"dotted.path": value}` — containment on the event payload; values are JSON literals or `"$request.<path>"` references (JSON type kept); `"$$x"` is the literal string `$x` |
| `recorded_by` | ✓ | ✓ | ✓ | ✓ | non-empty allowlist matched exactly against `events.recorded_by` |
| `key` | – | – | ● | – | `object_id` / `object_type` / `payload.<path>` |
| `field` | – | – | – | ● | payload path summed (must be a JSON number on every matched event) |
| `plus` | – | ✓ | ✓ | ✓ | number or `$request.<path>`, added to the count/sum before comparing — `"plus": 1` counts the request being decided, so `max: 5, plus: 1` means at most 5 actions *including* this one |
| `max` / `min` | – | at least one | at least one | at least one | number or `$request.<path>`; **inclusive** |

Unknown keys are rejected — a typo must not silently weaken a gate. Sliding
windows are half-open (`occurred_at > now − window AND ≤ now`); calendar
windows are `[bucket start, now]`. `formerly_within` is an existence test;
"must not have happened" is `count_within` with `max: 0`. All comparisons use
the **database clock** at evaluation time over the events' `occurred_at`.

### What a failing clause means

| Situation | Result | `explain_access` step reason | `check_access_detailed` |
|---|---|---|---|
| `$request.<path>` absent or `null` | fail | `gate_missing_context` (+ `missing_keys`) | may be `conditional` — if supplying the key could flip the decision |
| `$request` threshold present but not numeric | fail | `gate_bad_request_value` | `deny` |
| a matched event's `field` missing / non-numeric | fail | `gate_payload_not_numeric` | `deny` (skipping rows would let a malformed recorder relax a cap) |
| any other evaluation error | fail | `gate_error` | `deny` |
| clause holds / fails with complete context | pass / fail | `gate_passed` / `gate_denied` | `allow` / `deny` |

`decision.reason` is `gate_denied` when the graph allowed but a gate vetoed.
Gate steps in the trace carry the gate name, clause, window, **observed value
and threshold only** — never matched payloads or object ids, so an approval
for another stock cannot leak through explain.

### Where gates apply — and where they do not

- Every decision entry point: `check_access*`, batch checks, contextual-tuple
  checks (the ephemeral tuples affect the graph; gates apply as usual),
  `explain_access`, `check_access_detailed`, and enumeration — `list_objects`
  returns an empty page when the subject's gates deny, `list_subjects`
  filters each candidate, `list_actions` omits gated relations. A subject a
  check would deny never appears in a listing.
- **Only the question asked.** A gate on `group#member` does not fire while
  the walk resolves `doc#viewer` through `group:eng#member`. Gates hang on
  one seam above the graph walk (`authz._decide`), which a lint step in the
  test suite enforces for every entry point.
- **Scope.** By default a clause counts the principal's events on any
  object (`key: object_id` then counts distinct objects across them). With
  `scope: object` it counts only the events on the object being checked, so
  the same gate bounds each document separately, and separation of duties
  is one clause: `{"count_within": {"window": "30d", "action": "submit",
  "scope": "object", "max": 0}}` on `doc#approve` denies whoever submitted
  *that* document. Object-scoped clauses make `list_objects` evaluate the
  gate per candidate object instead of once per subject.
- **Time-travel** (`audit_check_access`, `audit_list_actions`) evaluates the
  gate definitions as of `p_at` (gate history lives in `model_gates_audit`)
  over the events that had been *recorded* by then.
- **Registry**: gates are part of `export_model` (a `gates` array) and
  propagate with `publish_model` / `apply_model`; `plan_model_apply` diffs
  them; the checksum ignores an empty array, so gate-free stores are
  unaffected. `describe_model` renders gates as `#` comment lines under the
  relation.

### Rolling a gate out: shadow mode

A gate can be introduced on a live relation without changing a single
decision. `"mode": "shadow"` evaluates the gate exactly as enforcement would
— same windows, same events, same cost — but a failing clause never denies:

```sql
SELECT authz.add_gate('bank', 'account', 'transfer', 'velocity_backstop', '{
  "mode": "shadow",
  "all_of": [{"count_within": {"window": "1h", "max": 5, "plus": 1}}]}');
```

What you see while it runs in shadow:

- `explain_access` traces the step with its real outcome (`gate_denied`,
  observed, threshold) and `"shadow": true`; `decision.reason` stays the
  graph's reason. The summary marks the step `○` instead of `✗`.
- `check_access_detailed` never turns `conditional` because of a shadow gate
  (its missing `$request` keys are excluded from `missing_context`).
- `reserve_event` allows, records the `request`, and returns the shadowed
  clause outcome in `gates` so the PEP can log what would have happened.
- Every would-be denial writes one structured line to the PostgreSQL server
  log: `gate_shadow store=… gate=… clause=… relation=… subject=… object=…
  reason=… observed=… threshold=…`. That is replica-safe — the check path
  still never writes — and is what log shipping already collects.
- `list_*` return their unfiltered results; `describe_model` renders the
  gate as `# gate velocity_backstop (shadow): …`.

Watch the log and the traces, tune the thresholds with `add_gate` (each
change is versioned in `model_gates_audit` like any model change), then drop
the `mode` key to enforce. The mode travels with the spec through the model
registry, so a fleet can be moved from shadow to enforce with one
`publish_model` / `apply_model`.

`"mode": "off"` is the third per-gate value: the gate stays defined and
versioned but is skipped entirely — no clauses evaluated, no trace steps —
for pausing one gate without losing its definition. An `off` (or shadow)
gate still counts toward the retention requirement reported by
`gate_windows`, since re-enabling it after a purge would under-count; drop a
gate to lift that requirement.

Two database-wide switches complement the per-gate mode, as the GUC
`authz.gates_mode` (`SET` per session, or `ALTER DATABASE authz SET …`):
`shadow` puts **every** gate into shadow (an initial rollout, or a suspected
false-deny incident), `off` skips gate evaluation entirely (the emergency
kill switch — no steps, no cost). The default and any unrecognised value is
`enforce`. Time-travel and enumeration follow the switch like every other
path, since they all go through the same evaluator.

### Payload schemas: the model owns the projection

A gate over `input.amount` is only as good as the recorders' agreement on
what `input.amount` is. Declare it: a relation (the action vocabulary) may
carry a payload schema, enforced by `record_event` and cross-checked by
`add_gate`:

```sql
SELECT authz.model_set_payload_schema('bank', 'transfer', '{
  "required": {"input.amount": "number", "input.currency": "string"},
  "optional": {"input.memo": "string"},
  "kinds":    {"response": {"required": {"output.status": "string"}}},
  "additional": true
}');
```

- `required` / `optional` map dotted payload paths to JSON types (`string`,
  `number`, `boolean`, `object`, `array`, `any`) and apply to every kind;
  `kinds.<request|response|denied>` adds paths for one kind (a `response`
  carries `output.*`, a `request` does not).
- `record_event` rejects a payload that lacks a required path or carries a
  declared path with the wrong type (`invalid_parameter_value`, 400 over
  HTTP; the batch is atomic). `additional: false` closes the shape: every
  payload leaf must be declared, or lie under a declared `object` / `any`
  path.
- `add_gate` refuses a clause that reads an undeclared path for its kind —
  `sum_within.field` (which must be declared `number` or `any`),
  `count_distinct_within` `payload.<path>` keys, `match` paths (dotted or
  nested; the leaf paths are checked) — so a gate
  cannot count on a field no recorder is obliged to send. Actions without a
  schema stay unrestricted.
- Schemas are part of the model: `export_model` emits `payload_schema` on a
  relation only when set (existing definitions and checksums do not move),
  `apply_model` propagates it, `describe_model` renders `# payload schema
  <relation>: {...}`. `NULL` clears it. Schemas apply going forward; already
  recorded events are not re-validated.

### What belongs in a gate

A rule belongs in a gate when it is a **permission** question a security or
compliance owner wants to define, version, audit and enforce centrally,
independent of which code path performs the action: separation of duties,
prior approval, step-up freshness ("an MFA event in the last 15 minutes"),
lockout after repeated denials (`kind: denied`), quotas, exfiltration brakes,
agent guardrails ("may write a file only if it read it in this session").

A rule belongs in the application when it decides an **outcome** — which
account to debit, what fee applies, whether to retry — or needs richer
signals than "what did this principal do" (fraud scoring). Four rules keep
the line visible: gates are veto-only and non-programmable (four fixed
primitives, AND, containment); the PEP records a **minimal payload
projection** (`input.amount`, `input.stock`), never its domain object; every
limit has **one owner** (a gate replaces an application check, or is
documented as a backstop); and **the PEP owns the truth** — the engine bounds
*recorded* actions, so feeding the log reliably (idempotency keys,
dead-lettering unknown actions) is part of adopting gates. A gate cannot
prevent two concurrent checks from both seeing `count = 4`; a hard bound needs
the explicit reserve below.

### The strict tier: `reserve_event`

A check plus a later `record_event` leaves a window in which two concurrent
requests both see `count = 4` and both proceed. When a cap must hold exactly,
the PEP calls `reserve_event` **because it is about to act** — never as a
side effect of asking:

```sql
SELECT authz.reserve_event('bank', 'user', 'alice', 'transfer', 'account', 'acc-1',
    p_payload         => '{"input": {"amount": 1200}}',
    p_request_context => '{"input": {"amount": 1200, "stock": "ACME"}}');
-- → {"allowed": true, "seq": 42, "kind": "request", "reason": "allowed",
--    "gates": [{"gate": "velocity_backstop", "clause": "0:count_within", "result": true,
--               "reason": "gate_passed", "observed": 3, "threshold": 5, ...}, ...]}
```

Under an advisory lock per `(store, subject)` — the unit every gate counts —
the engine takes the **full decision** (graph and gates, exactly as
`check_access` would) and, if allowed, records the `request` event in the
same transaction; a refusal records a `denied` event (the reserve *is* the
attempt; pass `p_record_denied => false` to leave no trace). N parallel
reserves against a cap of K yield exactly K allows. The PEP then performs
the action and records the `response` as usual. `reason` is `allowed`,
`gate_denied` or `graph_denied`; `gates` lists per-clause outcomes.
Idempotency follows `record_event` (`p_event_id` requires `p_occurred_at`; a
re-delivery returns the decision with `seq` null). Over HTTP:
`POST /pgauthz/v1/events/reserve` on the `full` profile, with the same
`RECORDER_ROLE` gate and subject rules as a check.

Two things to know: write caps with `"plus": 1` so the request being reserved
counts (`max: 5, plus: 1` = at most 5 in total); and a *sliding-window*
lockout gate (`count_within` over `kind: denied`) is extended by every refused
reserve — the usual login-lockout behaviour — while calendar windows are not.
