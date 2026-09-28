-- ============================================================================
-- Agents — authorization for AI agents (Authorization in Action, ch. 18 +
-- appendix C) on pgauthz
-- ============================================================================
--
-- The book's patterns, as a store:
--
--   18.3  policy-aware loop        every tool call is a check: principal = the
--                                  agent, action = the tool, resource = the
--                                  target. Denial is feedback to the planner.
--   18.3.2 task boundary           "resource.customerId == context.customerId"
--                                  is a task_scope tuple: stored with expires_at
--                                  for the task's lifetime, or injected as a
--                                  contextual tuple for one request. Docs are
--                                  readable only while the task is about their
--                                  customer.
--   18.4  constraint-aware planning list_actions / list_objects ARE the "policy
--                                  residual": the set of permitted actions on a
--                                  resource, the set of reachable resources.
--   18.4  sequencing               send_email only after a summary was recorded:
--                                  a formerly_within gate over the action log.
--   18.5  control plane            automation.create/update/delete have no agent
--                                  path at all — not a forbid, an absence; the
--                                  type restriction even rejects the tuple.
--   18.6  delegation as data       {delegator, delegate, actions, scope, expires}
--                                  = a `delegate` link (expires_at) + the
--                                  delegate's own task_scope. Grants are
--                                  written to the delegator's REACH userset
--                                  (itself + its delegates, transitively), so
--                                  a delegate reads only what the delegator
--                                  STILL holds AND what it was explicitly
--                                  given — attenuation at evaluation time,
--                                  revoking the delegator revokes the subtree;
--                                  plus an issuance precondition.
--   18.7  partner reputation       ACME's agent records the outcome of every
--                                  delegated payment; a count_within gate over
--                                  broken promises stops further delegation.
--
--   type user
--   type team
--     relations
--       define member: [user]
--   type agent
--     relations
--       define operator: [user]                    # the human the agent acts for
--       define delegate: [agent]                   # subject = the subagent, object = its delegator (expires)
--       define reach: [agent] or reach from delegate   # the agent itself + its delegates, transitively
--   type customer
--     relations
--       define member: [user, team#member]         # humans on the account
--       define agent_reader: [agent#reach]         # grants go to an agent's REACH, never to the agent
--                                                  #   (type restriction enforces the convention)
--       define task_scope: [agent]                 # the customer the agent's CURRENT task is about;
--                                                  #   for a delegate: the scope it was explicitly given
--       define agent_scope: agent_reader and task_scope   # an agent's effective authority here:
--                                                  #   allowed (via its reach) AND within its task
--   type customer_doc
--     relations
--       define customer: [customer]
--       define documents_read: member from customer or agent_scope from customer
--       define documents_search: documents_read
--       define documents_summarize: documents_read
--   type automation
--     relations
--       define run: [agent, user]                  # operational
--       define create: [user]                      # control plane: no agent path
--       define update: [user]
--       define delete: [user]
--   type mailbox
--     relations
--       define owner: [user]
--       define send_email: [agent] or owner
--       # gate summary_first: formerly_within{window: "1h", action: "documents_summarize", kind: "response"}
--   type partner_agent
--     relations
--       define pay: [agent]                        # the delegated action whose OUTCOMES are recorded
--       define delegate_pay: [agent]
--       # gate broken_promises: count_within{window: "30d", scope: "object", action: "pay",
--       #                                    kind: "response", match: {"output": {"promise_kept": false}}, max: 2}

DO $$
BEGIN
    PERFORM authz.delete_store('agents', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;
SELECT authz.create_store('agents', 'AI agents: policy-aware loop, planning, sequencing, delegation (Authorization in Action ch. 18)');

DO $$
BEGIN
    PERFORM authz.model_register_type('agents', 'user');
    PERFORM authz.model_register_type('agents', 'team');
    PERFORM authz.model_register_type('agents', 'agent');
    PERFORM authz.model_register_type('agents', 'customer');
    PERFORM authz.model_register_type('agents', 'customer_doc');
    PERFORM authz.model_register_type('agents', 'automation');
    PERFORM authz.model_register_type('agents', 'mailbox');
    PERFORM authz.model_register_type('agents', 'partner_agent');

    -- The vocabulary. Tool names are relations (documents.search → documents_search).
    PERFORM authz.model_register_relation('agents', 'member',              'humans on a team / customer account');
    PERFORM authz.model_register_relation('agents', 'operator',            'the human an agent acts on behalf of');
    PERFORM authz.model_register_relation('agents', 'delegate',            'subject is a subagent of the object agent (delegation link, expires)');
    PERFORM authz.model_register_relation('agents', 'reach',               'the agent itself and, transitively, its delegates — grants are written to agent#reach');
    PERFORM authz.model_register_relation('agents', 'agent_reader',        'agents (via their reach) allowed on a customer''s documents');
    PERFORM authz.model_register_relation('agents', 'task_scope',          'the customer the agent''s current task is about (stored with expires_at, or contextual)');
    PERFORM authz.model_register_relation('agents', 'agent_scope',         'an agent''s effective authority on a customer: agent_reader (via reach) AND task_scope');
    PERFORM authz.model_register_relation('agents', 'customer',            'customer_doc → customer');
    PERFORM authz.model_register_relation('agents', 'documents_read',      'tool documents.read');
    PERFORM authz.model_register_relation('agents', 'documents_search',    'tool documents.search');
    PERFORM authz.model_register_relation('agents', 'documents_summarize', 'tool documents.summarize');
    PERFORM authz.model_register_relation('agents', 'run',                 'tool automation.run (operational)');
    PERFORM authz.model_register_relation('agents', 'create',              'automation.create (control plane)');
    PERFORM authz.model_register_relation('agents', 'update',              'automation.update (control plane)');
    PERFORM authz.model_register_relation('agents', 'delete',              'automation.delete (control plane)');
    PERFORM authz.model_register_relation('agents', 'owner',               'mailbox owner');
    PERFORM authz.model_register_relation('agents', 'send_email',          'tool email.send — gated: a summary must have been recorded first');
    PERFORM authz.model_register_relation('agents', 'pay',                 'the delegated payment the partner performs; outcomes recorded as events');
    PERFORM authz.model_register_relation('agents', 'delegate_pay',        'may ACME''s agent delegate a payment to this partner? — gated on reputation');

    -- Type restrictions: who may hold what. NOTE what is absent: no agent on
    -- automation.create/update/delete — the control plane has no agent path,
    -- and write_tuple refuses such a tuple outright (18.5 "childproofing").
    PERFORM authz.model_add_type_restriction('agents', 'team', 'member', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'agent', 'operator', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'agent', 'delegate', 'agent');
    PERFORM authz.model_add_type_restriction('agents', 'agent', 'reach', 'agent');
    PERFORM authz.model_add_type_restriction('agents', 'customer', 'member', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'customer', 'member', 'team', p_allowed_user_relation => 'member');
    -- ONLY reach usersets may hold a scope grant: a direct grant to an agent
    -- would bypass the delegation chain, so the model refuses to store one.
    PERFORM authz.model_add_type_restriction('agents', 'customer', 'agent_reader', 'agent', p_allowed_user_relation => 'reach');
    PERFORM authz.model_add_type_restriction('agents', 'customer', 'task_scope', 'agent');
    PERFORM authz.model_add_type_restriction('agents', 'customer_doc', 'customer', 'customer');
    PERFORM authz.model_add_type_restriction('agents', 'automation', 'run', 'agent');
    PERFORM authz.model_add_type_restriction('agents', 'automation', 'run', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'automation', 'create', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'automation', 'update', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'automation', 'delete', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'mailbox', 'owner', 'user');
    PERFORM authz.model_add_type_restriction('agents', 'mailbox', 'send_email', 'agent');
    PERFORM authz.model_add_type_restriction('agents', 'partner_agent', 'pay', 'agent');
    PERFORM authz.model_add_type_restriction('agents', 'partner_agent', 'delegate_pay', 'agent');

    -- Direct relations
    PERFORM authz.model_add_rule('agents', 'team', 'member', 'direct');
    PERFORM authz.model_add_rule('agents', 'agent', 'operator', 'direct');
    PERFORM authz.model_add_rule('agents', 'agent', 'delegate', 'direct');
    -- reach: the agent itself (a self tuple written at registration) plus the
    -- reach of every delegate — a TTU through the `delegate` link, so chains
    -- of any depth work and each link is revocable / expiring on its own.
    PERFORM authz.model_add_rule('agents', 'agent', 'reach', 'direct');
    PERFORM authz.model_add_rule('agents', 'agent', 'reach', 'ttu',
        p_tupleset_relation => 'delegate', p_tupleset_computed => 'reach');
    PERFORM authz.model_add_rule('agents', 'customer', 'member', 'direct');
    PERFORM authz.model_add_rule('agents', 'customer', 'agent_reader', 'direct');
    PERFORM authz.model_add_rule('agents', 'customer', 'task_scope', 'direct');
    -- agent_scope: what an agent may actually do on this customer — allowed
    -- through its (delegator's) reach AND within its own task. This is the
    -- relation a sub-delegation is checked against ("may I pass this on?").
    PERFORM authz.model_add_rule('agents', 'customer', 'agent_scope', 'computed', p_computed_relation => 'agent_reader',
        p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('agents', 'customer', 'agent_scope', 'computed', p_computed_relation => 'task_scope',
        p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('agents', 'customer_doc', 'customer', 'direct');
    PERFORM authz.model_add_rule('agents', 'automation', 'run', 'direct');
    PERFORM authz.model_add_rule('agents', 'automation', 'create', 'direct');
    PERFORM authz.model_add_rule('agents', 'automation', 'update', 'direct');
    PERFORM authz.model_add_rule('agents', 'automation', 'delete', 'direct');
    PERFORM authz.model_add_rule('agents', 'mailbox', 'owner', 'direct');
    PERFORM authz.model_add_rule('agents', 'mailbox', 'send_email', 'direct');
    PERFORM authz.model_add_rule('agents', 'mailbox', 'send_email', 'computed', p_computed_relation => 'owner');
    PERFORM authz.model_add_rule('agents', 'partner_agent', 'pay', 'direct');
    PERFORM authz.model_add_rule('agents', 'partner_agent', 'delegate_pay', 'direct');

    -- customer_doc: humans through the account; agents only within their task
    -- (18.3.2: "every action must remain within the scope of the current customer").
    -- Both hops are TTUs directly on documents_read (no helper relations on the
    -- doc), so list_actions returns only the tool names a planner cares about —
    -- every relation a principal holds is an "action" to list_actions.
    PERFORM authz.model_add_rule('agents', 'customer_doc', 'documents_read', 'ttu',
        p_tupleset_relation => 'customer', p_tupleset_computed => 'member');
    PERFORM authz.model_add_rule('agents', 'customer_doc', 'documents_read', 'ttu',
        p_tupleset_relation => 'customer', p_tupleset_computed => 'agent_scope');
    PERFORM authz.model_add_rule('agents', 'customer_doc', 'documents_search', 'computed', p_computed_relation => 'documents_read');
    PERFORM authz.model_add_rule('agents', 'customer_doc', 'documents_summarize', 'computed', p_computed_relation => 'documents_read');

    -- Outcomes of delegated payments carry a declared shape (payload schema):
    -- the reputation gate below reads output.promise_kept, so every recorder
    -- must send it — and add_gate refuses the gate if it were undeclared.
    PERFORM authz.model_set_payload_schema('agents', 'pay',
        '{"kinds": {"response": {"required": {"output.promise_kept": "boolean"}}}}');
END;
$$;

-- ── Temporal gates (ADR 0012) ───────────────────────────────────────────
-- Gates are veto-only backstops over what the PEP RECORDED. They answer
-- "may this happen now, given what already happened?" — never what to do
-- next. The agent's planner owns the workflow; the gate owns the boundary.

-- 18.4 sidebar, "sequencing": an agent may send email only after it has
-- summarized something in the last hour (a documents.summarize RESPONSE was
-- recorded for this principal). No stage flag in context, no prompt
-- discipline: the action log is the task state.
SELECT authz.add_gate('agents', 'mailbox', 'send_email', 'summary_first', '{
  "description": "email only after a summary was produced in the last hour",
  "all_of": [{"formerly_within": {"window": "1h", "action": "documents_summarize", "kind": "response"}}]}');

-- 18.7, reputation: ACME's agent records the outcome of each payment it
-- delegated to the partner (kind = response, output.promise_kept). More than
-- two broken promises in 30 days and the partner may no longer be delegated
-- to — per partner (scope: object), automatically, and reversibly as the
-- window slides.
SELECT authz.add_gate('agents', 'partner_agent', 'delegate_pay', 'broken_promises', '{
  "description": "stop delegating to a partner that broke more than 2 promises in 30 days",
  "all_of": [{"count_within": {"window": "30d", "scope": "object", "action": "pay", "kind": "response",
                               "match": {"output": {"promise_kept": false}}, "max": 2}}]}');
