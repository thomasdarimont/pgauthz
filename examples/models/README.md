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
| `examples/models/helloworld/` | The smallest useful model (documents with editors/viewers, computed `can_read`/`can_write`) — the README's [complete example](../../README.md#a-complete-example) as loadable files | `model.sql`, `seed.sql`, `demo.sql` |
| `examples/models/demo/` | Professional-services engagements: internal/client users, teams, data spaces, documents, conditions, audit | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql` |
| `examples/models/gdrive/` | Google-Drive-style hierarchical folders and documents (deep TTU nesting), plus temporal gates on `doc.download` (daily quota + per-file limit over the action log) | `model.sql`, `seed.sql`, `demo.sql`, `tests.sql` |
| `examples/models/github/` | GitHub repo roles (`admin → maintainer → writer → triager → reader`), imported from an OpenFGA JSON model | `model.sql`, `seed.sql`, `demo.sql` |
| `examples/models/aia-acme/` | The ACME "Customer Collaboration" example from the book *Authorization in Action* (Cedar, ch. 9 + appendix A) re-modelled as ReBAC: Cedar attributes become relations, the `team:legal` membership rule becomes one tuple on a reified `classification` object, `delegatable` and the overrides become flag tuples with intersection/exclusion groups, and the global "managed device" `forbid` becomes a conditional object-wildcard tuple that every employee path must intersect (fail-closed on missing context). Policy-by-policy mapping in its `README.md` | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql` |
| `examples/models/agents/` | Authorization for **AI agents** (*Authorization in Action* ch. 18 / appendix C): every tool call is a check with the agent as principal; task scope as an expiring or contextual tuple; constraint-aware planning with `list_actions` / `list_objects` instead of policy residuals; sequencing ("email only after a summary") and partner reputation as temporal gates over the action log; a control plane with no agent path; delegation as data with evaluation-time attenuation (grants to an agent's `reach` userset, so a delegate holds only what its delegator still holds, revocation cascades) plus an issuance precondition. Mapping and caveats in its `README.md` | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql` |
| `examples/models/todo/` | AuthZEN interop "todo" model: list/item roles, ownership, and an **intersection** (delete needs manage-on-parent *and* ownership; admin/evil_genius bypass) — ported from [openfga/authzen-interop](https://github.com/openfga/authzen-interop/tree/main/todo) with tests from its assertions | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql` |

In each: `model.sql` defines the types/relations/rules (creates the store),
`seed.sql` loads sample tuples, `demo.sql` runs a showcase of example
queries, and `tests.sql` (demo, todo, gdrive, aia-acme, agents) asserts expected decisions.

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
