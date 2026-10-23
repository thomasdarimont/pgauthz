# Example models

The [`examples/models/`](.) directory contains ready-to-load
authorization models. They are **not** part of the deployable engine —
`init.sh` installs only the schema and functions, and you load an example on
top of it when you want one. Each model is independent; load any combination
into the same database (every store is isolated). (Runnable setup examples like
the watch/changefeed consumer live alongside under
[`examples/watch/`](../watch).)

| Example | Models | Files |
|---|---|---|
| `examples/models/helloworld/` | The smallest useful model (documents with editors/viewers, computed `can_read`/`can_write`) — the README's [complete example](../../README.md#a-complete-example) as loadable files | `model.sql`, `seed.sql`, `demo.sql`, `scenarios.authz.yaml` |
| `examples/models/demo/` | Professional-services engagements: internal/client users, teams, data spaces, documents, conditions, audit | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql`, `scenarios.authz.yaml` |
| `examples/models/gdrive/` | Google-Drive-style hierarchical folders and documents (deep TTU nesting), plus temporal gates on `doc.download` (daily quota + per-file limit over the action log) | `model.sql`, `seed.sql`, `demo.sql`, `tests.sql`, `scenarios.authz.yaml` |
| `examples/models/github/` | GitHub repo roles (`admin → maintainer → writer → triager → reader`), imported from an OpenFGA JSON model | `model.sql`, `seed.sql`, `demo.sql`, `scenarios.authz.yaml` |
| `examples/models/aia-acme/` | The ACME "Customer Collaboration" example from the book *Authorization in Action* (Cedar, ch. 9 + appendix A) re-modelled as ReBAC: Cedar attributes become relations, the `team:legal` membership rule becomes one tuple on a reified `classification` object, `delegatable` and the overrides become flag tuples with intersection/exclusion groups, and the global "managed device" `forbid` becomes a conditional object-wildcard tuple that every employee path must intersect (fail-closed on missing context). Policy-by-policy mapping in its `README.md` | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql`, `scenarios.authz.yaml` |
| `examples/models/agents/` | Authorization for **AI agents** (*Authorization in Action* ch. 18 / appendix C): every tool call is a check with the agent as principal; task scope as an expiring or contextual tuple; constraint-aware planning with `list_actions` / `list_objects` instead of policy residuals; sequencing ("email only after a summary") and partner reputation as temporal gates over the action log; a control plane with no agent path; delegation as data with evaluation-time attenuation (grants to an agent's `reach` userset, so a delegate holds only what its delegator still holds, revocation cascades) plus an issuance precondition. Mapping and caveats in its `README.md` | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql`, `scenarios.authz.yaml` |
| `examples/models/fourquestions/` | The pitch's sentence as one store — *share with the marketing team, except Bob; external reviewers read-only until next Friday, but only once they accepted the NDA; three downloads a day; payments over 10k need two distinct approvers*: a userset grant, an exclusion, an expiring tuple, and three temporal gates (`formerly_within` on a trusted recorder, a calendar-day `count_within`, `count_distinct_within` keyed on the approver plus a separation-of-duties clause). README explains why the NDA gate hangs on `review` and why the amount tier is its own action | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql`, `README.md`, `scenarios.authz.yaml` |
| `examples/models/authzen-cert/` | The **AuthZEN certification fixture** ([openid/authzen #433](https://github.com/openid/authzen/issues/433)): users alice/bob, records record-1/record-2, actions read/write/delete, modelled so that pgauthzd answers the OpenID conformance suite's plans — Core and Properties level — from `/stores/authzen_cert/access/v1`. Shows attributes-as-data (bob's admin role as an object-wildcard tuple, record-2's archived status as a flag tuple) next to a request property read by a condition (`action.properties.soft`); `tests.sql` pins the validated decisions and searches against the engine | `model.sql`, `seed.sql`, `tests.sql` |
| `examples/models/todo/` | AuthZEN interop "todo" model: list/item roles, ownership, and an **intersection** (delete needs manage-on-parent *and* ownership; admin/evil_genius bypass) — ported from [openfga/authzen-interop](https://github.com/openfga/authzen-interop/tree/main/todo) with tests from its assertions | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql`, `scenarios.authz.yaml` |

In each: `model.sql` defines the types/relations/rules (creates the store),
`seed.sql` loads sample tuples, `demo.sql` runs a showcase of example
queries, and `tests.sql` (demo, todo, gdrive, aia-acme, agents, fourquestions, authzen-cert) asserts expected decisions.
`scenarios.authz.yaml` is the model's story as a **test fixture** (the
`tests.authz.yaml` format of [pgauthzctl](../../pgauthzctl/README.md#test-fixtures-testsauthzyaml)):
its own tuples plus named scenarios with assertions, hermetic — a run creates
an ephemeral store with the model, writes only the fixture's tuples and
decides there. Two ways to run one against a store carrying the model:
paste it into the console's Store → Test → **Scenarios** editor and Run, or
`pgauthzctl model test examples/models/gdrive/scenarios.authz.yaml --store gdrive`.
Gates read the action log, empty in the ephemeral store, so the fixtures say
which permissions a gate holds back (agents, fourquestions).

## Loading an example

The engine must be installed first (`./init.sh`, or `./bootstrap.sh` which
also loads the demo). Then pipe the model and seed into the database:

```bash
DB=$(docker compose ps -q authz-db)

# Load the gdrive example (model + sample tuples)
cat examples/models/gdrive/model.sql examples/models/gdrive/seed.sql \
  | docker exec -i "$DB" psql -U authz -d authz

# Run its showcase queries
docker exec -i "$DB" psql -U authz -d authz < examples/models/gdrive/demo.sql
```

`./bootstrap.sh` loads the `demo` example automatically (it is also the
fixture for the test suite and the OPA/AuthZEN integration tests, whose
default store is `demo`).
