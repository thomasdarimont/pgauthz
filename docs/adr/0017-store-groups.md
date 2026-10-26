# ADR 0017 — Store groups: tenancy, delegated administration and group issuers

- **Status:** Accepted (2026-10-26; phases 1, 2 and 3 implemented, 4 open)
- **Date:** 2026-10-26
- **Deciders:** maintainers
- **Relates to:** [0016](0016-issuer-bindings-and-admin-api.md) (issuer
  bindings and the admin API — this ADR replaces its "a binding cannot add
  trust" rule for *group* issuers), [0014](0014-subject-assertion-policy.md),
  `pgauthzd/README.md` → Admin API, `console/README.md` → How the access
  works, `docs/MODEL_DESIGN.md` → the model registry

## Context

A tenant is implied today, never named: an issuer binding reaches the
stores whose names match its patterns (`tenant_a_.*`), the admin API's
tenant scope is "the stores my issuer is bound to", and the console's
platform admin reaches every store through `store:X platform
platform:default`. That carries a SaaS deployment some way, but three
things cannot be said:

- *Who may add trust for whom.* ADR 0016 keeps identity providers in the
  environment because a row that adds an issuer is root for every store
  its tokens reach; the console answers "a binding cannot add trust". A
  tenant that brings its own identity provider therefore needs an
  operator and a deploy.
- *Who administers a tenant.* There is no object a person can be admin
  *of* short of the whole platform; a tenant admin is a person with store
  roles on each of the tenant's stores, granted one by one.
- *Whose models a store may run.* The registry is one flat namespace of
  model names; any admin who may apply a registry version may apply any.

## Decision

**A store group is a named set of stores that shares administration,
trust and models.** It is an engine object (`authz.store_groups`, a
nullable `group` on each store), managed over the admin API and the
console; the console's own access model gets the matching `group` type.

1. **A `default` group, and ungrouped as a choice.** The migration creates
   a platform-owned `default` group and puts every existing store into it,
   so an upgraded deployment has one tidy group its platform admins
   already administer; the console creates new stores in `default` unless
   the form names another group. A store may still be detached: an
   ungrouped store behaves as a group of one — its own administrative
   unit, and everything below that says "the group's stores" reads "the
   store" for it — for the isolated store that must share nothing.
2. **Administration is delegated per group.** `group:<name>` carries
   `admin`, `issuer_admin` and `can_create_store`, `can_manage_issuers`,
   `can_manage_access`, `can_view` the way `platform:default` does;
   `store.group` links a store to its group the way `store.platform` links
   it to the platform, so a group admin reaches every store of the group
   and a platform admin reaches every group. People, teams and service
   accounts hold group roles like store roles, from the same Access tab.
3. **Issuers attach to a group or to the platform.** A platform issuer is
   the environment's, as in ADR 0016, and reaches whatever its `stores`
   binding says. A *group issuer* is a database row that names the group
   instead of store patterns and carries its own trust anchor (`jwks_url`
   or discovery, the audiences): its tokens reach the group's stores and
   nothing else, by construction. A group admin adds, narrows, pauses and
   removes the group's issuers; the platform's issuers stay out of their
   reach. Because the reach is bounded by the group, group issuers need no
   platform-wide "anchors from the database" switch; the ADR 0016 rule
   stays for platform issuers. A group issuer may carry delegated admin
   rules only (`decide`, ADR 0016 addendum): the console store decides
   what its people and pipelines may manage, the row grants trust and
   nothing more.
4. **The admin API's scope is the group.** A credential's reach — a static
   rule's, a delegated one's — is the union of the groups it holds
   something on, resolved against membership at request time, so a store
   joining a group is covered without a restart. The regex store scope of
   ADR 0016 remains for platform issuers from the environment.
5. **Models cross groups only by relationship.** A registry model belongs
   to the group that published it (the platform's models to the platform).
   A store may apply its own group's models and the platform's; applying
   another group's model needs a relationship from that group: `group:A
   model_consumer group:B` (A lets B run A's models — a shared core model
   maintained by one team, applied by many), granted by A's admins and
   visible to both. The registry's plan, apply and rollout honour it; the
   checksum and drift mechanics are unchanged. The `default` group's
   models are the platform's models of today, so nothing a current
   deployment applies changes meaning. A model published from an
   ungrouped store is recorded as that store's, but stays open like the
   platform's: isolation is a group's property, and a deployment that
   never creates a group keeps the registry it always had.

## Consequences

- A SaaS deployment names its tenants: one group per tenant, the tenant's
  identity provider as the group's issuer, the tenant's admins as group
  admins, the tenant's pipelines as service accounts with group or store
  roles. Onboarding a tenant is console work for a platform admin, and
  everything after that is the tenant's own.
- Trust is scoped before it is granted: the worst a group admin can do by
  adding an identity provider is open the group's own stores to it.
- The console gains a Groups section under Platform, a group page (Stores,
  Issuers, Models, Access), the group on each store, and a group field on
  store creation; the sign-in chooser of a multi-provider console
  (follow-up) is one entry per group issuer.
- Engine: `authz.store_groups`, `authz.stores.group`, `group` and anchor
  fields on `authz.issuer_bindings`, `authz.store_group_relations`, and
  the registry rows carrying their owning group; one migration each.
- The environment keeps working as the bootstrap and break-glass:
  platform issuers, `ADMIN_ROLE`, static admin rules.

## Phases

1. Groups in the engine and the console: membership, group roles, the
   console model's `group` type, the admin API's group scope. Trust does
   not move.
2. Group issuers: anchor fields on the binding row, discovery from the
   issuer URL, validation and audit as for bindings, managed by group
   admins in the console and over the admin API.
3. Model ownership and `model_consumer` relationships in the registry.
4. The console's sign-in chooser over group issuers.

## Alternatives considered

- **Anchors from the database behind a platform-wide opt-in**
  (`ISSUERS_ANCHORS_FROM_DB`): unlocks the same error, but every row is
  platform-wide trust and only platform admins may write it; tenants still
  need the operator. Superseded by groups, where the bound reach makes the
  switch unnecessary.
- **Groups as naming convention** (prefix patterns, as today): no object
  to be admin of, no place for a tenant's issuer, no model ownership.
- **Groups only in the console store** (tuples, no engine object): pgauthzd
  could not resolve a group issuer's reach without reading the console
  store on every token; membership belongs where trust is decided.
- **Mandatory groups**: simpler to reason about, but an isolated store
  would need a group of its own by name; the group-of-one reading gives
  it the same without the ceremony, while the `default` group keeps the
  common case tidy.

## Non-goals

- Nested groups. One level: platform, groups, stores.
- Sharing tuples between stores. Groups share administration, trust and
  models; each store's graph stays its own (store layering, if ever,
  is a separate decision).
- Moving platform issuers into the database.
