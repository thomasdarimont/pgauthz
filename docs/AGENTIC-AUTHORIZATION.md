# Authorizing AI agents with pgauthz

**In one paragraph:** an AI agent is a principal whose next action is not
known in advance, so authorization moves from a gate at the edge into the
agent's loop: every tool call is a check, the answer to "what may I do here"
comes from the same engine before the agent plans, what the agent *did* is
recorded so history-dependent rules can veto the next step, and authority
handed to subagents is data the engine evaluates, never trust between
processes. pgauthz already has the primitives for each of these — this guide
shows which one to use for what, with the runnable
[`examples/models/agents/`](../examples/models/agents/) as the worked example.
It follows the patterns of *Authorization in Action* (Windley), chapters
17–18, without depending on the book.

Contents: [1 The loop](#1-the-policy-aware-loop) · [2 Planning](#2-constraint-aware-planning-ask-before-acting) ·
[3 Task scope](#3-task-scope) · [4 Sequencing and rate guardrails](#4-sequencing-and-rate-guardrails) ·
[5 Delegation](#5-delegation-and-subagents) · [6 The control plane](#6-childproofing-the-control-plane) ·
[7 RAG](#7-retrieval-augmented-generation-authorize-before-retrieval) · [8 Logging and replay](#8-what-to-log-and-how-to-replay) ·
[9 What ReBAC does not do](#9-what-this-model-does-not-do)

Vocabulary: every authorization decision has the same four parts — the
**PARC** model (*Authorization in Action* §4.3.1): a **P**rincipal is
trying to perform an **A**ction on a **R**esource, but only if the right
**C**onditions are met. For an agent, the **agent** is the principal
(`agent:acme_assist`), a **tool call** is the action (`documents_read` for
the MCP tool `documents.read`), the tool's target is the resource, and the
conditions are everything else the decision depends on — in pgauthz the
relationships in the graph, tuple conditions evaluated against the request
context (task, device, time), temporal gates over recorded history, and the
delegation the agent acts under.
The **PEP** (policy enforcement point) — the MCP server, tool router or
gateway in front of the agent — is the component that builds that request
and calls pgauthzd, the PDP (policy decision point). The model never
decides; it proposes.

## 1. The policy-aware loop

Every tool invocation passes through the PEP, which builds a request from
the agent's identity, the tool, the target and the task context and asks
pgauthzd before executing. A denial is not an error page; it is input to
the agent's next planning step.

```
plan → build the PARC request (principal, action, resource, conditions) → POST /access/v1/evaluation → permit? execute : replan
```

Over AuthZEN (the PEP holds the agent's token or a service token bound to
the store):

```bash
curl -s -X POST http://pgauthzd:8080/stores/agents/access/v1/evaluation \
  -H "Authorization: Bearer $AGENT_JWT" -H "Content-Type: application/json" \
  -H "X-PGAuthz-Detail: true" -d '{
  "subject":  {"type": "agent", "id": "acme_assist"},
  "action":   {"name": "documents_read"},
  "resource": {"type": "customer_doc", "id": "globex-plan"}}'
# {"decision": false, "context": {"state": "deny", "reason": "intersection_unsatisfied", ...}}
```

Ask for the **detailed decision** (`X-PGAuthz-Detail: true` on AuthZEN,
`"detail": true` on the native `/pgauthz/v1/check`): the `state` is
`allow`, `deny` or `conditional`, and `reason` says *which* boundary held —
`gate_denied` (a history rule, §4), `intersection_unsatisfied` (out of task
scope, §3), a missing-context list for `conditional` (§2). Feed that to the
planner instead of a bare "no"; it is the difference between an agent that
retries blindly and one that revises its plan.

The same decision in SQL, for a co-located PEP:

```sql
SELECT authz.check_access_detailed('agents', 'agent', 'acme_assist',
                                   'documents_read', 'customer_doc', 'globex-plan');
```

Model the tools as relations on the resource types they touch, one relation
per tool, and let the schema say who may hold each (type restrictions). The
agents example does this for `documents_read/search/summarize`, `run`,
`send_email`, `pay`.

## 2. Constraint-aware planning: ask before acting

A reactive loop discovers boundaries by failing. Let the agent ask first:

| Question the planner has | Call | Returns |
|---|---|---|
| "Which tools may I use on this resource?" | `list_actions` / AuthZEN `search/action` | the permitted relations, as a set |
| "Which resources may I `documents_read`?" | `list_objects` / AuthZEN `search/resource` | ids (paged, keyset cursor) — or the `*` wildcard row when a type-wide grant applies |
| "Who else may act on this?" | `list_subjects` / AuthZEN `search/subject` | subject ids |
| "What context would make this pass?" | detailed check → `state: conditional`, `missing_context` | the request keys a condition or gate needs |

```bash
curl -s -X POST http://pgauthzd:8080/stores/agents/access/v1/search/action \
  -H "Authorization: Bearer $AGENT_JWT" -d '{
  "subject":  {"type": "agent", "id": "acme_assist"},
  "resource": {"type": "customer_doc", "id": "custco-briefing"}}'
# {"results": [{"action": {"name": "documents_read"}}, {"action": {"name": "documents_search"}},
#              {"action": {"name": "documents_summarize"}}]}
```

Where a policy-language PDP answers this with a *residual* (a partially
evaluated policy the caller must translate into a query), pgauthz answers
with the **set itself**, computed by the same rules, gates included: a gated
tool disappears from `search/action` until its gate would pass. Guidance and
enforcement cannot drift because they are the same evaluation — the agents
example asserts it (`ag_plan_equals_checks`).

Two operational notes:

- `list_actions` returns every relation the principal holds on the object,
  helper relations included. Give tools their own relations and write
  intermediate hops as tuple-to-userset rules *inside* the tool relation
  (the example's `documents_read` does) so the planner's list is exactly
  the tool names.
- The search endpoints enumerate the graph, so they sit behind
  `SEARCH_REQUIRED_ROLE` (and explain behind `EXPLAIN_REQUIRED_ROLE`). The
  **PEP** holds that role; the agent's own token should not.

## 3. Task scope

"The agent may work on documents of the customer this task is about" is
the boundary every agent policy needs and the one a static role cannot
express. Make the task a relationship:

```
type customer
  relations
    define agent_reader: [agent#reach]           # allowed on this customer at all
    define task_scope:   [agent]                 # the customer the CURRENT task is about
    define agent_scope:  agent_reader and task_scope
type customer_doc
  relations
    define customer: [customer]
    define documents_read: member from customer or agent_scope from customer
```

Two ways to supply `task_scope`, both used in the example:

- **Stored, expiring**: the PEP writes `agent:acme_assist task_scope
  customer:CustCo` with `expires_at` = the task deadline when the task
  starts, deletes it when the task ends. Works for every call type,
  including the planning searches, and survives restarts.
- **Contextual, per request**: pass it as a contextual tuple on the check
  (`contextual_tuples` on `/pgauthz/v1/check`, or
  `check_access_with_contextual_tuples_jsonb` in SQL). Nothing is stored; the
  scope lives exactly as long as the request. Needs the contextual-reader
  capability on the connection role, and the list/search calls do not take
  contextual tuples — use the stored form when the planner must see the
  scope.

An agent allowed on two customers (`agent_reader` on both) still reaches
only the task's customer; the detailed decision for the other one says
`intersection_unsatisfied`.

## 4. Sequencing and rate guardrails

"Send email only after a summary was produced", "at most 20 tool calls per
hour", "no payment to a partner that broke three promises this month" are
rules about **history**, and the check path never writes: the PEP records
what happened, after it happened, and temporal gates
([MODEL_DESIGN §17](MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules))
veto the next action on that record.

```bash
# after the summarize tool ran (kind: response — completed, not attempted)
curl -s -X POST http://pgauthzd:8080/stores/agents/pgauthz/v1/events \
  -H "Authorization: Bearer $PEP_JWT" -d '{"events": [
  {"subject_type": "agent", "subject_id": "acme_assist", "action": "documents_summarize",
   "object_type": "customer_doc", "object_id": "custco-briefing", "kind": "response"}]}'
```

```sql
-- the sequencing rule: email only within an hour of a summary
SELECT authz.add_gate('agents', 'mailbox', 'send_email', 'summary_first', '{
  "all_of": [{"formerly_within": {"window": "1h", "action": "documents_summarize", "kind": "response"}}]}');
-- a rate rule: at most 20 tool calls per hour, this one included
SELECT authz.add_gate('agents', 'customer_doc', 'documents_read', 'tool_budget', '{
  "all_of": [{"count_within": {"window": "1h", "kind": "request", "max": 20, "plus": 1}}]}');
```

What this buys over a stage flag in the prompt or the request context: the
state cannot be forged by the model (the recorder is the PEP, see below), it
is the same for every PEP instance, it is visible to the planner
(`search/action` omits `send_email` until the gate would pass) and to
`explain_access`, and it can be rolled out in `mode: shadow` first.

Rules of the road:

- **The recorder is the PEP, never the agent.** `RECORDER_ROLE` is a PEP
  credential ([ADR 0012 §3](adr/0012-action-log.md#3-trust-model-for-recorded-events)):
  an agent that could record its own events could move its own gates.
- Record `response` after the tool completed, `denied` when the PEP refused;
  count `response` for quotas, `request` for attempt budgets.
- When a cap must hold exactly under concurrency (N parallel subagents
  against a budget of K), the PEP calls `POST /pgauthz/v1/events/reserve`
  instead of check-then-record: decision and `request` record happen under
  a per-subject lock.
- Gates count the **checked principal's** events. "Pay only after a manager
  approved" is therefore not a gate — the manager's approval is a
  relationship (`user:carol approved reimbursement:r1`) and the rule an
  intersection. Gates are also per relation, not per principal type; put
  humans on a separate relation if they must not be sequenced.
- A gate answers "may this happen now, given what happened?" — never "what
  should happen next". The planner owns the workflow.

## 5. Delegation and subagents

A primary agent that fans work out to subagents must not hand them more
than it has, and what it hands out must go away when its own authority
does. Write delegation as tuples, and route the delegate's access **through
the delegator's grant**:

```
type agent
  relations
    define delegate: [agent]                       # subject = subagent, object = delegator, expires
    define reach:    [agent] or reach from delegate   # the agent itself + its delegates, transitively
type customer
  relations
    define agent_reader: [agent#reach]             # grants go to an agent's REACH, never to the agent
    define task_scope:   [agent]
    define agent_scope:  agent_reader and task_scope
```

A delegation record `{delegator: acme_assist, delegate: research_agent,
scope: CustCo, expires: +4h}` becomes two expiring tuples — the `delegate`
link and the delegate's own `task_scope` — written atomically under a
precondition that the delegator holds the scope:

```bash
curl -s -X POST http://pgauthzd:8080/stores/agents/pgauthz/v1/write-checked \
  -H "Authorization: Bearer $PEP_JWT" -d '{
  "preconditions": [{"match": "allowed", "user_type": "agent", "user_id": "acme_assist",
                     "relation": "agent_scope", "object_type": "customer", "object_id": "CustCo"}],
  "writes": [
    {"user_type": "agent", "user_id": "research_agent", "relation": "delegate",
     "object_type": "agent", "object_id": "acme_assist", "expires_at": "2026-10-01T18:00:00Z"},
    {"user_type": "agent", "user_id": "research_agent", "relation": "task_scope",
     "object_type": "customer", "object_id": "CustCo", "expires_at": "2026-10-01T18:00:00Z"}]}'
```

Properties, each proven by a test in the example:

- **Attenuation at evaluation time.** The delegate reads through the
  delegator's `reach` grant, so it holds exactly what the delegator still
  holds *and* what it was explicitly given (`task_scope`). Revoke the
  delegator's grant and the delegate loses access in the same instant;
  widen the delegate's scope to something the delegator lacks and nothing
  happens.
- **Chains** work to any depth (`reach from delegate` is transitive) and cut
  at any link; each link expires on its own.
- **Attenuation at issuance**, on top: the `"match": "allowed"` precondition
  runs a full check inside the write's transaction, so an over-broad
  delegation is refused before it exists. Check it against the
  *intersection* relation (`agent_scope`), not the inherited one — a reach
  delegate inherits everything its delegator holds; the narrowing lives in
  `task_scope`.
- **The convention is enforced by the model**: the type restriction on
  `agent_reader` only admits `agent#reach`, so a grant written straight to
  an agent — which would bypass the chain — is rejected at write time.
- Revocation is one delete; "only the named delegate may use it" is
  structural, the tuple names the subject.

Cross-domain delegation (a partner's agent acting under a credential your
system issued) is the same on the resource side: pgauthzd trusts the
partner's issuer per `JWT_ISSUERS` with a store binding, the partner agent is
a principal, its authority is tuples with `expires_at`, and the outcomes of
what it did are recorded events a reputation gate reads (§4 — the example's
`broken_promises`).

## 6. Childproofing the control plane

Separate the tools an agent uses to do work from the ones that define the
work: running an automation is operational; creating, updating or deleting
one, editing policies, granting roles are control plane. In ReBAC the
control plane is protected by **absence**, not by a deny rule:

```
type automation
  relations
    define run:    [agent, user]
    define create: [user]          # no agent path exists
    define update: [user]
    define delete: [user]
```

There is no rule an agent could satisfy, and the type restriction refuses
to store `agent:x create automation:y` at all. The same principle at the
deployment level:

- Agent PEPs talk to a **decision-only** pgauthzd (read-only DB role);
  only the writer instance (`full` profile, `WRITER_ROLE`) may change tuples,
  and the model, gates and roles need `authz_admin` — a role no agent
  process holds.
- The recorder role is a PEP credential (§4). The `authz_contextual_reader`
  capability (§3) likewise belongs to the PEP's connection, never to a role
  an agent-facing client can reach.
- In production, gate the search and explain endpoints behind roles and set
  `DEPLOYMENT_ENVIRONMENT=production` so the daemon refuses to start with
  them open ([PRODUCTION.md](PRODUCTION.md)).

## 7. Retrieval-augmented generation: authorize before retrieval

In a RAG pipeline the retrieval step is the last place access control can
be enforced reliably — once a chunk is in the prompt, the model can leak,
summarize or be steered by it. Two designs, both served by the same rules
that govern direct access:

**Filter, then search.** Ask the engine for the set of authorized resource
ids and pass it to the vector store as a metadata filter:

```sql
SELECT object_id, is_wildcard
  FROM authz.list_objects('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc');
```

Branch on `is_wildcard`: a `*` row means a type-wide grant — search
without an id filter (still restricted to the type). Otherwise filter on
the returned ids (use the keyset cursor for large sets). Each chunk carries
its document id as metadata, nothing else about authorization.

**Search, then batch-check.** Ask the vector store for the top-k candidate
*ids and scores only*, authorize them in one call, then fetch content for
the permitted ones:

```bash
curl -s -X POST http://pgauthzd:8080/stores/agents/pgauthz/v1/check-batch \
  -H "Authorization: Bearer $PEP_JWT" -d '{"checks": [
  {"subject": {"type": "agent", "id": "acme_assist"}, "action": {"name": "documents_read"},
   "resource": {"type": "customer_doc", "id": "custco-briefing"}},
  {"subject": {"type": "agent", "id": "acme_assist"}, "action": {"name": "documents_read"},
   "resource": {"type": "customer_doc", "id": "globex-plan"}}]}'
```

Use the first when the authorized set is small or the wildcard is common,
the second when semantic search narrows to a few dozen candidates. Never
retrieve content before the decision — filtering afterwards keeps
unauthorized text out of the model but has already exposed it to the
application. When the application data and the engine share a database,
the filter is a JOIN in the same query (README, *Authorization as a JOIN*).

The same task scope (§3) applies: the agent's retrieval is bounded to the
task's customer without any extra plumbing, because `documents_read` is
the same relation the loop checks.

## 8. What to log, and how to replay

Three records exist, for three questions:

| Question | Record | Where |
|---|---|---|
| What did the agent *do*? | the action log (`record_event`, kind request/response/denied) | `list_events` (auditor) |
| How did the *graph* change (delegations, scopes)? | the audit trail | `audit_list_user`, `audit_list_object`, `watch_changes` |
| Why was a call allowed or denied, *then*? | replay: `audit_check_access(..., p_at)` re-decides with the tuples, model and gates in effect at that time; `explain_access` for the live trace | SQL |

A decision log for the daemon — every decision with reason and gate
outcome, for the "intent vs observed behaviour" loop — is planned
(pgauthzd, opt-in); until then the AuthZEN detail context and the metrics
(`pgauthzd_check_decisions_total`, `pgauthzd_gate_clauses_total`) are what an observability
pipeline gets.

When an AI assistant helps you *understand* a policy ("why was this
denied?"), ground it in `explain_access` output and concrete requests, not
in a prose reading of the model: the trace is the authoritative
explanation, the assistant's narrative is not.

## 9. What this model does not do

- **No subject-side traversal in the rule language.** "B may do X only while
  A may" cannot be written as a rule that starts at B; it is written from
  the object side with the reach userset (§5). Adding subject-side rules was
  considered and rejected: it would break OpenFGA compatibility of the
  model and change the evaluator's cost model, for a convenience the
  userset already provides.
- **Gates are per relation and count the checked principal's events** (§4):
  no per-type exemption, no counting someone else's approvals.
- **Search results are sets, not residuals.** For an unbounded resource set
  ("any row where customer = X") the answer is the `*` wildcard row or a
  JOIN in the application database, not a symbolic constraint.
- **The model never sees a decision it can influence.** Prompts are not a
  security boundary here; every tool call is decided by the engine from
  tuples, conditions, gates and the PEP-supplied context.

Further reading: [`examples/models/agents/README.md`](../examples/models/agents/README.md)
(the mapping table against the book's patterns and the tests that prove
each property), [MODEL_DESIGN §17](MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules)
(gate grammar), [ADR 0012](adr/0012-action-log.md) (the action log's trust
model), [DEVELOPMENT.md](DEVELOPMENT.md) (HTTP surfaces, conditional
writes, recording).
