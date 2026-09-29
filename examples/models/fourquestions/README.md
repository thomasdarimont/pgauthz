# Four questions — the pitch's example, runnable

> *"Share this folder with the marketing team, except Bob; give external
> reviewers read-only until next Friday, but only once they have accepted the NDA;
> cap downloads at three a day; and any payment over 10k needs two distinct
> approvers."*

One sentence, four kinds of rule. Each classic model answers one of the
questions; this example answers all four in one store:

| Question | Model | Here |
|---|---|---|
| Who are you? | RBAC | a role is a relationship: `team:marketing#member` |
| How are you related to this thing? | ReBAC | `editor` on the folder, inherited by every doc; `can_read = editor BUT NOT blocked` for Bob |
| What is true right now? | ABAC | `expires_at` on the reviewer tuple ("until next Friday") |
| What has already happened? | temporal gates | NDA accepted first · three downloads a day · two distinct approvers, not yourself |

Files: `model.sql` (types, relations, rules, three gates, a payload schema),
`seed.sql` (the team, the folder, two reviewers, two payments, one recorded
NDA acceptance), `demo.sql` (walkthrough with expected results), `tests.sql`
(37 assertions, run by `tests/test.sh`).

```bash
source env.sh
psql_file "$PG_DB" examples/models/fourquestions/model.sql
psql_file "$PG_DB" examples/models/fourquestions/seed.sql
psql_file "$PG_DB" examples/models/fourquestions/demo.sql
```

## The rules, one by one

| Clause | Mechanism | Where |
|---|---|---|
| share with marketing | one userset tuple `team:marketing#member → editor → folder:campaign`; docs inherit through `parent` | seed |
| except Bob | `user:bob → blocked → folder:campaign`; `can_edit` / `can_read` are exclusion groups | model + seed |
| reviewers, read-only, until next Friday | `reviewer` tuples with `p_expires_at` (a week from load: the sentence is spoken on a Friday); enforced on every check, search and time-travel path | seed |
| only once they accepted the NDA | gate `nda_first` on `doc#review`: `formerly_within` an `accept_nda` response recorded by `svc:review-portal` in the last 30 days (reviewers re-acknowledge monthly) | model |
| three downloads a day | gate `three_a_day` on `doc#download`: `count_within` over a UTC calendar day, `max: 3, plus: 1` | model |
| over 10k needs two distinct approvers | gate `four_eyes` on `payment#execute_large`: `count_distinct_within` over `approval_received` events on *this* payment keyed by `payload.input.approver`, `min: 2`; plus `count_within` over the **same events** with `match: {input.approver: $request.self}` and `max: 0`, so none of the approvals may be the executor's own | model |

**Where the store approximates the sentence.** The sentence is spoken on a
Friday, so *until next Friday* is a week from load in the seed. Two clauses
are met in spirit, not letter, and the difference is worth knowing before
you copy the model: *once they have accepted the NDA* is an acceptance
recorded within the last 30 days, a re-acknowledgement policy rather than a
one-time signature (the gate window also has to fit the event retention the
test fixtures assume); and *any payment over 10k* is the payments service
asking `execute_large` for such amounts — the store never sees the amount,
it enforces the approvals.

## Two modelling decisions worth copying

**A gate hangs on the question asked.** The NDA requirement applies to
external reviewers only, so reviewers are checked on `review` (what the
review portal asks) and employees on `can_read`. Putting the gate on a
shared `can_read` would demand an NDA from the marketing team; putting
`review` *inside* `can_read` would not fire the gate at all, because gates
are evaluated for the relation checked, never during sub-resolution.

**Risk tiers are distinct actions.** "Over 10k" is `execute_large`, a
separate action from `execute`, and the payments service asks the one that
matches the amount. Gates are AND-only vetoes; "small, or large and
approved" is not a gate expression. This is the same advice as `view` /
`edit` / `share` instead of `doc:all`: keep the policy-level actions
fine-grained and let the application bundle them.

**Approvals are recorded on the requester's behalf, and separation of
duties reads the same events.** A gate counts the checked principal's own
events, so "two other people approved this" is recorded by the trusted
payments service as `approval_received` events for the requester, with the
approver in the payload. A payload schema makes `input.approver` mandatory
and the gate's `recorded_by` allowlist pins the recorder. "Not yourself" is
a second clause over those same events: `count_within` with `match:
{input.approver: $request.self}` and `max: 0`. The PEP passes the caller's
id as `self` in the request context (it is the same trusted service that
records the approvals); a check without it fails closed
(`gate_missing_context`), so a forgotten key can never widen the rule. An
earlier draft counted the executor's own `approve` events instead — that
only works if the recorder logs both an `approve` and an `approval_received`
for every approval, a convention the gate could not verify; reading one set
of events removes the gap. (A built-in `$subject` reference would remove the
context convention too; it is not in the gate grammar today.)

## What the tests pin

Team access and Bob's exclusion (reason `excluded`); the NDA gate denying
(`gate_denied`), ignoring an acceptance recorded by anyone but the portal,
unlocking once the portal records it, and never touching the team path;
`list_subjects` agreeing with the checks; a reviewer tuple expiring; the
download cap per principal and `list_objects` returning nothing for a capped
subject; the four-eyes gate refusing zero, one, and the same approver twice,
allowing two distinct approvers per payment, failing closed when `self` is
missing from the context, `reserve_event` recording the request, the
separation-of-duties clause vetoing an executor who is among the approvers,
approvals belonging to the requester they were recorded for;
the payload schema rejecting an approval without an approver; and
`describe_model` rendering the facets and the three gates.
