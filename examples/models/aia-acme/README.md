# ACME (Authorization in Action, ch. 9 + appendix A) → pgauthz

The Cedar example from Phillip Windley's *Authorization in Action* (Manning),
re-modelled as a pgauthz store: `model.sql`, `seed.sql` (appendix A.5 entities
plus a few extras), `tests.sql` (the book's four `is-authorized` calls and the
chapter-9 patterns, 36 checks, loaded by `tests/test.sh`), `demo.sql`.

The book's entity store is "a relationship graph" (§9.4); Cedar reads it as
attributes and `in` hierarchies. pgauthz *is* the graph, so the translation is
mostly: attribute → relation, policy → rule, `forbid` → required relation.

## Schema

| Cedar (§9.2.1) | pgauthz | Note |
|---|---|---|
| `entity Employee in [Team] { manager: Employee, department, on_call, clearance? }` | `type employee` / `define manager: [employee]`; `team#employee_member: [employee]` | `department`, `on_call`, `clearance` are never used by a policy → not modelled. Subject of a `manager` tuple = the manager, object = the report. |
| `entity Customer in [Team]` | `type customer`; `team#customer_member: [customer]` | Two member relations keep Cedar's `principal is Employee` / `is Customer` scopes: a customer in an employee readers team gets nothing. |
| `entity Team { name }` | `type team` | `name` is display data, not authz data. |
| `entity Document { owner, classification, delegatable, employee_readers_team, customer_readers_team }` | `owner: [employee]`, `classification: [classification]`, `delegatable: [employee:*]`, `employee_readers: [team#employee_member]`, `customer_readers: [team#customer_member]` | `classification` is reified as an object (`classification:legal`) so a membership rule becomes one tuple; `delegatable` is a flag tuple (`employee:*`). |
| `context.device.managed: Bool` | condition `managed_device` on the wildcard tuple `employee:* managed_device document:*` | request context keeps the book's shape `{"device": {"managed": true}}`. |
| `context.time.{hour,weekday}` | condition `business_hours` on the wildcard tuple `employee:* business_hours document:*` | §9.1 states "stricter constraints outside business hours" as prose only; pinned down here as *only the owner edits off-hours* (Mon–Fri 09–17). |
| actions `doc:view/edit/share` | `view`, `edit`, `share` | Cedar's `appliesTo` principal types are enforced by which paths exist per subject type. |

## Policies

| # | Cedar (verbatim intent) | pgauthz rule(s) |
|---|---|---|
| 9.3.1 / A.4.1 | customer view: `principal in resource.customer_readers_team` | `view ← customer_readers` (userset `team#customer_member`) |
| 9.3.1 / A.4.1 | employee view: `principal in resource.employee_readers_team \|\| resource.owner.manager == principal` | `employee_reach ← employee_readers \| owner_manager`; `owner_manager ← manager from owner` (TTU replaces attribute traversal) |
| 9.3.2 / A.4.2 | owner can do all (view, edit, share) | `owner` appears in `employee_can_view`, `employee_can_edit`, `employee_can_share` |
| 9.3.3 / 9.5.3 | manager of owner: view + edit | `owner_manager` in `employee_reach` (view) and `employee_can_edit` |
| 9.5.1 / A.4.3 | share if `resource.delegatable == true && principal in employee_readers_team` | `employee_can_share ← owner \| (delegatable AND employee_readers)` — intersection group of the flag and the userset |
| 9.5.2 | `principal in Team::"team:legal"`, view+edit, `when classification == "Legal"` | `classification#reviewer: [team#employee_member]`; `document#reviewer ← reviewer from classification`; `reviewer` in `employee_reach` and `employee_can_edit`. One tuple: `team:legal#employee_member reviewer classification:legal`. |
| 9.5.4 | mixed: edit if manager-of-owner or (legal and Legal) | falls out of the two rows above |
| 9.1 (prose) | stricter constraints outside business hours | `edit ← (owner AND managed_device) \| (employee_can_edit AND managed_device AND business_hours)`: managers, legal reviewers and temporary editors edit only Mon–Fri 09–17; view and share unchanged (so appendix A, which sends no time, still holds). A second conditional wildcard tuple, same idiom as the device rule. Had the book meant a *rate* ("at most N edits after hours"), it would be a `count_within` temporal gate instead. |
| 9.6 / A.4.4 | `forbid(principal is Employee, action, resource is Document) when { context.device.managed == false }` | every employee path is intersected with `managed_device`: `view ← … \| (employee_can_view AND managed_device)`, `edit ← employee_can_edit AND managed_device`, `share ← (employee_can_share AND managed_device) BUT NOT share_locked`. Customers' paths carry no device term (outside the forbid's scope). |
| 9.7.1 | template `permit(principal == ?principal, action == doc:view, resource in ?resource)` | a direct tuple on `employee_viewer: [employee]` / `customer_viewer: [customer]` — templates are tuples |
| 9.7.2 | override: forbid view on workspace unless owner | `restricted: [employee:*]` flag; `employee_can_view ← owner \| (employee_reach BUT NOT restricted)` |
| 9.7.2 | override: a customer forbids all sharing, even by owners | `share_locked: [employee:*]` flag subtracted in `share` |
| 9.7.2 | override: contractors get temporary edit rights | `editor: [employee]` tuple with `expires_at` (server-time expiry, no condition needed) |

## Deliberate divergences

- **Missing context fails closed.** Cedar evaluates the device `forbid` only
  when `context.device.managed` exists; a missing attribute makes that policy
  error and be skipped (permit wins) unless the request is schema-validated.
  Here the condition cannot hold, so an employee without context is denied and
  `check_access_detailed` reports `state: conditional, missing_context:
  [request.device]` — the PEP sees what it forgot. Customers are unaffected
  (appendix A.6.2 sends no context and is allowed, as in the book).
- **`forbid` is intersection, not subtraction.** A Cedar `forbid` on context
  is "a required relation" in ReBAC: `AND managed_device` rather than `BUT
  NOT unmanaged`. The subtraction form with a `managed == false` condition
  would reproduce Cedar's fail-open on missing context; rejected on purpose.
- **Classification as an object, not a string attribute.** The book stores
  `classification: "confidential"|"Legal"` as document metadata and matches it
  in the policy text. Reifying it means "legal reviews Legal" is data (one
  tuple) and adding a classification never touches the model. The demo does
  not model `confidential` semantics because no policy reads it.
- **No `Any` principal.** Cedar's `principal is …` scopes are reproduced by
  giving each subject type its own paths; `view` is the only action reachable
  by customers.

## What the example shows that Cedar cannot

`list_objects('aia_acme', 'employee', 'bob', 'view', 'document', ctx)` and
`list_subjects(...)` answer "which documents / who" over the same rules,
including the device condition, the restricted override and the readers
usersets — Cedar needs partial evaluation + an external filter for this.
`explain_access` names the `managed_device` condition as the reason for an
unmanaged denial (Cedar's `determiningPolicies` equivalent, with the path).

## Not modelled (candidates)

- Chapter 13's C³ tenancy (platform vs tenant PDPs, the four case studies) —
  maps onto the model registry (one published model, per-tenant stores) and
  per-issuer store binding; separate exercise.
- `Folder` (§9.2.3 mentions it) — the gdrive example already covers it.
