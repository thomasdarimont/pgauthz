# examples/agentic — a human delegates to an agent: Keycloak token exchange + a pgauthz task

A runnable, end-to-end version of the delegation story in
[AGENTIC-AUTHORIZATION.md](../../docs/AGENTIC-AUTHORIZATION.md): **alice**
lets the **ACME Assist** agent act on her behalf, the agent gets a real
OAuth token that says so, and pgauthz decides what the agent may do while it
does — **only for the task the agent was given, and only until that task is
completed.** When the agent needs more mid-task, the PEP asks alice **out of
band** (Keycloak CIBA) and widens the task only once her approval arrives.

Two layers do two different jobs, and the demo keeps them apart on purpose:

| | Layer 1 — the issuer (Keycloak) | Layer 2 — the graph (pgauthz) |
|---|---|---|
| Question | **Who** may act **for whom**? | **What** may the actor do **while** it does? |
| Mechanism | [Token-exchange delegation](https://www.keycloak.org/securing-apps/token-exchange#_token-exchange-delegation): consent → `may_act` on the user's token → the agent exchanges it for a **delegated token** (`sub` = alice, `act.client_id` = the agent). Renewed consent mid-task via [CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html): the PEP asks, alice answers on her device, Keycloak mints a fresh token | The agent is the **principal** (`agent:acme_assist`); its authority is tuples in the `agents` store: its own grants (`agent_reader`), the **task** (`task_scope`, expiring), subagents (`delegate` → `reach`). Widening the task is one more checked write — after the human said yes |
| Scope | One hop. A delegated token cannot be exchanged again; a wrong actor is refused | Any depth. Subagents read *through* the agent's reach; the PEP's task bundle expires or is deleted as one unit |
| Ends when | The token expires (minutes) | The **task** ends — the PEP closes it, or the deadline passes — even while the token is still valid |

The link between the layers is one setting on pgauthzd and OPA:
`ACTOR_CLAIM=act.client_id` + `ACTOR_SUBJECT_TYPE=agent`. A token whose `act`
claim names an actor is checked **as that actor**, with the token's own subject
kept as `on_behalf_of` (decision log, hook actor). Without it, a delegated
token would be checked as alice — the confused-deputy failure where the agent
quietly inherits everything the user may do.

## Run it

```bash
./keycloak/config/generate-mkcerts.sh                          # once (mkcert *.pgauthz.test)
./start.sh --keycloak                                          # stack + Keycloak with the delegation features on
(cd keycloak/terraform && terraform init && terraform apply)   # realm + acme-app / acme_assist / acme-other-agent
./tests/test.sh                                                # loads the `agents` store (or ./bootstrap.sh)
# /etc/hosts: 127.0.0.1 pgauthz.test id.pgauthz.test admin.pgauthz.test api.pgauthz.test

examples/agentic/delegation-demo.sh            # scripted: curl drives the login + consent forms;
                                               # alice's device declines, then approves the step-up
examples/agentic/delegation-demo.sh --browser  # you are alice: open the consent URL yourself,
                                               # answer the step-up request on the terminal
examples/agentic/delegation-demo.sh --verbose  # echo every HTTP call
examples/agentic/delegation-demo.sh --keep     # leave the task open and poke around
```

Needs `curl`, `jq`, `python3`, and `terraform` (for the client secrets; or
export `ACME_APP_SECRET`, `ACME_ASSIST_SECRET`, `ACME_OTHER_AGENT_SECRET`).
The script plays alice's device for the step-up: it listens on `:18555`
(`CIBA_AE_PORT`), where `compose-keycloak.yml` points Keycloak's CIBA
authentication channel (`host.docker.internal`).

## What you will see

```
==> 1. alice logs in to acme-app and consents to 'acme_assist may act on your behalf'
    alice's token:  sub=alice  azp=acme-app  aud=["acme_assist","authz-api"]
                    scope="openid profile delegation:client:acme_assist"
                    may_act={"sub":"<acme_assist's service-account id>","client_id":"acme_assist"}
==> 3. … and exchanges alice's token + its actor token for a DELEGATED token
    delegated token: sub=alice  azp=acme_assist  aud=["authz-api"]  subject_type=user
                     act={"sub":"…","client_id":"acme_assist"}
                     refresh_token: none (transient session)
==> 4. No task is open. A valid delegated token alone grants the agent nothing:
    agent:acme_assist (delegated token)   documents_read   customer_doc:custco-briefing → DENY
    user:alice (her own token)            documents_read   customer_doc:custco-briefing → ALLOW
==> 5. The PEP opens a task for acme_assist: 'brief alice on CustCo', deadline in 10 minutes
    → {"written":4}
==> 6. During the task — the same delegated token, now checked against an OPEN task:
    agent:acme_assist (delegated token)   documents_read   customer_doc:custco-briefing   ALLOW
    agent:acme_assist (delegated token)   documents_read   customer_doc:globex-plan       DENY   ← not in THIS task
    agent:acme_assist (delegated token)   create           automation:nightly-report      DENY   ← no agent path
    user:alice (her own token)            create           automation:nightly-report      ALLOW  ← not inherited
    agent:research_agent (asserted by its PEP) documents_read customer_doc:custco-briefing ALLOW  ← through the agent's reach
==> 7. Mid-task the agent needs more — step-up consent, OUT OF BAND (Keycloak CIBA)
    agent:acme_assist (delegated token)   documents_read   customer_doc:globex-plan   DENY  state=deny reason=intersection_unsatisfied
    POST …/ext/ciba/auth  client=acme-app  login_hint=alice  scope='openid delegation:client:acme_assist'  binding_message=widen-task-10839
      ┌─ alice's device ──────────────────────────────────────────
      │ acme_assist asks to ALSO work on customer Globex for this task
      │ task: brief alice on CustCo   code: widen-task-10839   requested by: acme-app
      │ consent required: true   scope: openid delegation:client:acme_assist profile roles email
      └─ [Approve]  [Decline]
    → alice DECLINES → token endpoint: access_denied: not authorized → nothing changed: globex-plan DENY
    the agent asks again … → alice APPROVES → a FRESH token: sub=alice may_act={"client_id":"acme_assist"}
    only NOW does the PEP widen the task: write-checked, precondition alice member Globex → {"written":1}
    agent:acme_assist (new delegated token)    documents_read   customer_doc:globex-plan   ALLOW  ← the task now covers Globex
    agent:acme_assist (first delegated token)  documents_read   customer_doc:globex-plan   ALLOW  ← the graph decides, not the token
    agent:research_agent (asserted by its PEP) documents_read   customer_doc:globex-plan   DENY   ← its own task_scope is still CustCo
==> 8. What the issuer refuses: acme-other-agent's exchange → invalid_request; re-exchange → invalid_request
==> 9. The task is done — the PEP closes it: ONE conditional delete of the bundle → {"deleted":5}
==> 10. After the task — the SAME delegated token (still valid for 1700s):
    agent:acme_assist (delegated token)   documents_read   customer_doc:custco-briefing   DENY
    agent:acme_assist (delegated token)   documents_read   customer_doc:globex-plan       DENY   ← the step-up ended with the task
    agent:research_agent (…)              documents_read   customer_doc:custco-briefing   DENY
    user:alice (her own token)            documents_read   customer_doc:custco-briefing   ALLOW
==> 11. Time travel — was agent:acme_assist allowed … before? f   while open? t   after? f
```

## How it works, step by step

**1. Consent (Keycloak).** `acme-app` starts a Device Authorization Grant with
`scope=openid profile delegation:client:acme_assist`. The parameterized scope
asks Keycloak to let the `acme_assist` client act for the user who logs in.
Keycloak checks that `acme_assist` holds the fine-grained admin permission
`delegate` on Users (set up by Terraform), shows alice a consent screen
("Allow acme_assist to act on your behalf?") — consent is mandatory for
delegation scopes and never stored — and mints her token with a `may_act`
claim and `acme_assist` in `aud`. The script drives the login and consent
forms with curl; `--browser` lets you do it by hand.

**2–3. The delegated token.** `acme_assist` gets its own actor token
(`client_credentials`) and sends both to the token endpoint
(`grant_type=…token-exchange`, `subject_token` = alice's, `actor_token` = its
own). The result is issued *to the agent*, *about alice*: `sub` stays alice,
`act.client_id` is `acme_assist`, the audience and claims come from the
**actor client's** mappers (`authz-api`, `subject_type=user`), and there is no
refresh token. This is the credential the agent presents to pgauthzd.

**pgauthzd's view.** With `ACTOR_CLAIM=act.client_id`, the principal of every
request made with that token is `agent:acme_assist`, and `user:alice` is
carried as `on_behalf_of`. OPA (when the OPA overlay is in the path) derives
the same subject from the token in `authn.rego`, and policy hooks see
`input.actor.on_behalf_of`. The engine never sees the token: it answers for
`agent:acme_assist` from the graph, exactly as it would for any other agent.

**4. No task, no access.** A delegated token proves that alice *let* the
agent act — it says nothing about what the agent is working on. The
`agents` model (`examples/models/agents/`) grants an agent's documents
through `customer#agent_scope = agent_reader AND task_scope`; without a
`task_scope` tuple the intersection is empty and every check denies.

**5. The task is a bundle of expiring tuples**, written by the **PEP** — the
agent runtime (here: `acme-app`'s service account, which holds `authz_writer`),
never the agent itself — in one `write-checked` call:

```jsonc
// POST /stores/agents/pgauthz/v1/write-checked   (pgauthzd-full, the PEP's token)
"preconditions": [{"match": "allowed", "user_type": "user", "user_id": "alice",
                   "relation": "member", "object_type": "customer", "object_id": "CustCo"}],
"writes": [
  {"user_type": "user",  "user_id": "alice",          "relation": "operator",   "object_type": "agent",    "object_id": "acme_assist", "expires_at": "<deadline>"},
  {"user_type": "agent", "user_id": "acme_assist",    "relation": "task_scope", "object_type": "customer", "object_id": "CustCo",      "expires_at": "<deadline>"},
  {"user_type": "agent", "user_id": "research_agent", "relation": "delegate",   "object_type": "agent",    "object_id": "acme_assist", "expires_at": "<deadline>"},
  {"user_type": "agent", "user_id": "research_agent", "relation": "task_scope", "object_type": "customer", "object_id": "CustCo",      "expires_at": "<deadline>"}]
```

- The **precondition** ties the task to the person the agent acts for: a
  task can only be opened on a customer alice herself may reach. It is a full
  access check inside the write's transaction, so a task that would exceed
  the delegator is refused before it exists.
- `operator` turns the token's assertion into a graph fact the PEP can verify
  (`user:alice operator agent:acme_assist` → allow) and the audit trail
  records.
- `task_scope` is **what** the task is about: the agent may work on Globex in
  general (`agent_reader`), but not in this task.
- The **subagent** gets a `delegate` link into the agent's reach plus its own
  narrowing `task_scope`. It needs no Keycloak token: its PEP asserts it on
  the trusted callback listener (step 6 shows `research_agent` reading CustCo
  through the agent's reach, and not Globex).
- Every tuple carries the task **deadline** as `expires_at`: if the PEP
  crashes and never closes the task, the authority still ends.

**6. During the task** the agent reads CustCo documents and nothing else.
`automation:nightly-report create` is the control-plane check: alice may, the
agent may not — a delegated token does not hand the agent the user's rights.
`search/action` answers the planner's question ("what may I do here?") from
the same graph, and the explain trace shows the path
`documents_read ← agent_scope ← agent_reader(acme_assist#reach) ∧ task_scope`.

**7. Step-up consent, out of band (CIBA).** Mid-task the planner wants
Globex's plan. The check denies, and the rich decision (`X-PGAuthz-Detail`,
`check_access_detailed`) says *why*: `intersection_unsatisfied` — the agent
is an `agent_reader` of Globex, the `task_scope` half is missing. That is the
cue to **ask, not retry**. The PEP must not widen the task on its own, so it
turns to Keycloak's [backchannel authentication
endpoint](https://www.keycloak.org/securing-apps/oidc-layers#_backchannel_authentication_endpoint):
`POST …/ext/ciba/auth` as `acme-app` with `login_hint=alice`, the same
`delegation:client:acme_assist` scope, a `binding_message` (a short code
alice can compare on her device — ≤ 50 plain characters, no spaces) and,
as extra parameters, what the agent is asking for and for which task.
Keycloak hands the request to the **authentication entity** over its HTTP
authentication channel — the component that actually reaches the user (a
push notification, a banking app). In the demo that entity is alice's
device, played by the script: a tiny HTTP server that spools what Keycloak
sent (`login_hint`, `scope`, `is_consent_required: true`, `binding_message`,
the extra fields) and answers `201`. Alice's decision goes back on Keycloak's
callback endpoint (`…/ext/ciba/auth/callback`, bearer = the token the request
carried): `CANCELLED` ends the PEP's poll with `access_denied` — no token,
no write, the task is what it was. `SUCCEED` means authenticated **and**
consented (the delegation scope included), and the poll
(`grant_type=urn:openid:params:grant-type:ciba`, `auth_req_id`) returns a
fresh token for alice with `may_act` — the renewed consent, naming the
agent, which the agent exchanges exactly as in step 3. Only then does the
PEP widen the task: one more `write-checked`, precondition alice herself is
a member of Globex, one `task_scope` tuple with the same deadline. Both
delegated tokens now read Globex (same principal, same task — the graph
decides, not the token); the subagent still does not (its own `task_scope`
was CustCo). The widening is on record twice: Keycloak's event log has the
consent, the audit trail has the PEP's write with `performed_by` and expiry.
With `--browser`, you answer the device prompt yourself; declining leaves the
rest of the demo running on the narrow task.

**8. What Keycloak refuses** on its own: an actor without the `delegate`
permission (`acme-other-agent`) cannot exchange alice's token, and a
delegated token cannot be exchanged again (no transitive delegation at the
token layer — chains live in the graph, where they can be cut and expire per
link). A login that asks for `delegation:client:acme-other-agent` succeeds
but silently drops the scope: no consent screen, no `may_act`.

**9–10. The task is completed → the PEP closes it** with one conditional
delete of the same bundle, the widened scope included (precondition: the task
is still open). The delegated token is unchanged and still valid for many
minutes, yet every check for the agent — and for the subagent, whose link
was in the bundle — now denies, while alice's own access is untouched.
Nothing had to be revoked at Keycloak.

**11. Replay.** `authz.audit_check_access` reconstructs the decision at any
instant: denied before the task, allowed while it was open, denied after —
and the audit trail says who opened and closed it (`performed_by` = the PEP's
service account) and with which expiry.

## Configuration this example adds

| Where | What |
|---|---|
| `compose-keycloak.yml` → `keycloak` | `KC_FEATURES=token-exchange-delegation,parameterized-scopes` (both **preview** in Keycloak 26.8); the CIBA HTTP authentication channel URI (`KC_SPI_CIBA_AUTH_CHANNEL__CIBA_HTTP_AUTH_CHANNEL__HTTP_AUTHENTICATION_CHANNEL_URI`, default `http://host.docker.internal:18555/ciba` = the demo script; override with `CIBA_AUTH_CHANNEL_URI`) and the `host.docker.internal` host mapping |
| `compose-keycloak.yml` → `opa`, `pgauthzd-opa`, `pgauthzd-full` | `ACTOR_CLAIM=act.client_id`, `ACTOR_SUBJECT_TYPE=agent` — the same two values wherever the subject is derived from the token |
| `keycloak/terraform/client.agentic.tf` | `acme-app` (consent, device grant, **CIBA grant** via the `oidc.ciba.grant.enabled` client attribute, service account with `authz_writer`/`authz_recorder` = the PEP), `acme_assist` (service account + standard token exchange), `acme-other-agent`, and the FGAP v2 permission `delegate-all-users-to-acme_assist` (`delegate` scope on Users → client policy for `acme_assist`); `admin_permissions_enabled` on the realm |
| `keycloak/terraform/realm.tf` | the realm's CIBA policy, spelled out (poll mode, 120 s request lifetime, 5 s poll interval, `login_hint` as the user hint) |
| `examples/models/agents/` | unchanged — the model already has `operator`, `task_scope`, `delegate`/`reach`, `agent_scope`. The script adds one demo fixture for the step-up (alice on Globex's account team, so a second customer *she* may reach exists) and removes it at the end |

The Keycloak client is named `acme_assist`, like the agent in the seed, so
`act.client_id` maps to `agent:acme_assist` without a lookup table. If your
client ids cannot double as principal ids, map them at the PEP or add a
hardcoded claim mapper on the actor client and point `ACTOR_CLAIM` at it.

## Where to take it next

- **A real authentication entity.** The script stands in for alice's device.
  In a deployment the CIBA channel URI points at your consent app, which
  pushes the request to the user, shows the `binding_message` and the extra
  parameters, and posts `SUCCEED`/`CANCELLED` to Keycloak's callback. Switch
  the realm's CIBA policy to `ping` mode and the PEP stops polling: Keycloak
  calls the client's notification endpoint when the answer is in. The
  initial consent (step 1) can use the same channel instead of the device
  grant — then alice never needs a browser.
- **Admin delegation** (`delegation:user:<admin>`) is the same flow with a
  human actor; `ACTOR_CLAIM=act.sub` and a `user`-typed actor would carry it.
- **Record what the agent did** (`record_event` / `reserve_event`, the
  action log) so temporal gates — "summarize before you email", spend caps,
  lockouts — apply to the agent's *history*, not only its grants: see
  [AGENTIC-AUTHORIZATION §4](../../docs/AGENTIC-AUTHORIZATION.md#4-sequencing-and-rate-guardrails)
  and `examples/models/agents/demo.sql`.

## Related

- [AGENTIC-AUTHORIZATION.md](../../docs/AGENTIC-AUTHORIZATION.md) — the
  patterns (loop, planning, task scope, gates, delegation, control plane, RAG)
- [`examples/models/agents/`](../models/agents/README.md) — the model, seed
  and SQL tests this demo runs on
- [`examples/keycloak/`](../keycloak/README.md) — plain user tokens through
  the same front door; [`keycloak/README.md`](../../keycloak/README.md) — the
  bundled issuer
- [`pgauthzd/README.md`](../../pgauthzd/README.md) — `ACTOR_CLAIM` /
  `ACTOR_SUBJECT_TYPE` and the rest of the daemon's configuration
