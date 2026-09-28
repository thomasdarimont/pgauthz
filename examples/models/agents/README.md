# Agents — authorization for AI agents on pgauthz

Chapter 18 and appendix C of *Authorization in Action* (Windley) describe how
ACME governs AI agents with Cedar: a policy-aware loop, constraint-aware
planning with policy residuals, a childproofed control plane, delegation as
data, and reputation across domains. This example runs the same scenario
(ACME Assist, its research subagent, CustCo's documents, the PayCo partner)
on a pgauthz store: `model.sql`, `seed.sql`, `tests.sql` (34 checks, loaded
by `tests/test.sh`), `demo.sql`.

Tool names are relations (`documents.read` → `documents_read`); the agent is
the principal, the tool's target is the resource. The PEP in front of the
agent (an MCP server, a tool router) calls pgauthzd's AuthZEN or native API
for every tool call and records what happened afterwards.

## The mapping

| Book | Cedar | pgauthz |
|---|---|---|
| 18.3 policy-aware loop | `is_authorized(agent, tool, resource, context)` before each tool call; deny = replan | `check_access` / AuthZEN `evaluation`; the denial carries a reason (`check_access_detailed`, `explain_access`) the planner can use. |
| 18.3.2 task boundary | `permit … when { resource.customerId == context.customerId }` | `customer#task_scope: [agent]` — the customer the agent's **current task** is about. Stored with `expires_at` for the task's lifetime (the PEP writes it at task start), or passed as a **contextual tuple** for one request. `documents_read = member from customer OR (agent_reader from customer AND task_scope from customer)`: an agent allowed on two customers still reaches only the task's customer. |
| 18.4 constraint-aware planning | typed partial evaluation → residual → `permitted_actions` list | `list_actions('agents','agent','acme_assist','customer_doc','custco-briefing')` returns the set directly; `list_objects` answers "which resources for this action". Guidance ≡ enforcement: the test asserts the listed set equals the per-action checks that pass. Over HTTP: AuthZEN `search/action`, `search/resource`. |
| 18.4 sidebar sequencing | `permit send_email when summary_status == "complete"` (a stage flag in context) | a temporal gate on `mailbox#send_email`: `formerly_within{window: 1h, action: documents_summarize, kind: response}`. The action log **is** the task state; nothing rides in the prompt or the context. The planner sees it too: `list_actions` omits `send_email` until a summary was recorded. |
| 18.5 childproofing the control plane | `forbid(principal is Agent, action in [automation.create, …])` | `automation#create/update/delete: [user]` — no agent path exists, and the type restriction makes even *writing* such a grant an error. Absence instead of a forbid. |
| 18.6 delegation as data | `{delegator, delegate, delegatedActions, resourceScope, expires}` evaluated as context by guardrail + permit policies | two expiring tuples: a `delegate` link (`research_agent delegate agent:acme_assist`) and the delegate's own `task_scope` (the explicit narrowing). Grants are written to the delegator's **reach** userset (`agent:acme_assist#reach agent_reader customer:CustCo`; `reach = [agent] or reach from delegate`, so chains work), and the type restriction refuses a direct grant to an agent. The delegate therefore reads only what the delegator **still holds** AND what it was given: attenuation at evaluation time, revoking the delegator revokes the whole subtree, cutting a middle link cuts its subtree. On top, the delegation write runs under a precondition that the delegator's reach holds the scope (`write_tuples_checked`), so an over-broad delegation is refused early (18.6.5). |
| 18.7 promises and reputation | partner's policy checks `context.delegation.constraints`; a reputation database records outcomes | ACME's agent records the outcome of each delegated payment (`pay`, kind `response`, payload `output.promise_kept` — declared as the action's payload schema, so every recorder must send it). Gate on `partner_agent#delegate_pay`: `count_within{window: 30d, scope: object, action: pay, kind: response, match: {output.promise_kept: false}, max: 2}` — the third broken promise in 30 days stops delegation to *that* partner, automatically and reversibly. The verifiable credential that carries the delegation across domains is out of scope (pgauthzd trusts issuers per `JWT_ISSUERS`). |

## What is different from the book, and why

- **Attenuation is structural, not proven.** Clawdrey's OVID-ME proves
  "child mandate ⊆ parent authority" with an SMT solver before minting a
  token; the book's Cedar policies re-check the delegation record on every
  call. Here the delegate's access *goes through* the delegator's grant: a
  ReBAC check walks from the object, so the delegator's authority must be
  reachable from the object side — which is why grants are written to the
  agent's `reach` userset rather than to the agent. The convention costs one
  self tuple per agent (`agent:X reach agent:X`) and is enforced by the type
  restriction on `agent_reader`. The issuance precondition is an early,
  atomic refusal on top; it can only match the delegator's reach tuple today,
  and a planned `"match": "allowed"` precondition would let a sub-delegator
  (whose right is computed through the chain) be checked the same way.
- **Gates are per relation, not per principal type.** `summary_first` vetoes
  the mailbox owner too (the test shows it). Put humans on their own relation
  if they must be exempt.
- **Multi-party approval is a relationship, not an event.** The book's
  "pay only after a manager approved" reads an `approvals` list from context.
  A gate counts the *checked principal's* events, so a manager's approval is
  not something the agent recorded — model it as a tuple
  (`user:manager approved reimbursement:r1`) and intersect: `pay = [agent]
  AND approved_by_manager`.
- **`list_actions` lists every relation the principal holds**, helper
  relations included. The model therefore writes the task-scope hops as TTUs
  inside `documents_read` rather than as named helper relations, so the
  planner's list is exactly the tool names.
- **Expiry is judged per statement.** A tuple that expires mid-transaction
  is still live until the next statement — every HTTP request is one, so
  this only matters in SQL scripts (see the `pg_sleep` in `tests.sql`).
- **No subject-side traversal in the rule language.** "May the delegate do X
  only while its delegator may" cannot be written as a rule that starts at
  the subject; the reach-userset convention above is the ReBAC way to say it
  from the object side, and it is what keeps the model OpenFGA-compatible.

## Try it

```bash
DB=$(docker compose ps -q authz-db)
cat examples/models/agents/model.sql examples/models/agents/seed.sql | docker exec -i "$DB" psql -U authz -d authz
docker exec -i "$DB" psql -U authz -d authz < examples/models/agents/demo.sql
```
