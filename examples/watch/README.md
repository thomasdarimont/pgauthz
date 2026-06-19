# Watch API demo (pg_notify + `watch_changes`)

A tiny consumer that streams tuple changes in real time: it `LISTEN`s on the
`authz_changes` channel (the doorbell the audit trigger emits via `pg_notify`)
and, on each wake-up, pulls the new changes with `authz.watch_changes`.

```
write_tuple ──▶ trigger writes tuples_audit ──▶ NOTIFY authz_changes (doorbell)
                                                        │
    consumer: LISTEN authz_changes ◀────────────────────┘
             on wake → authz.watch_changes(store, cursor) → print, advance cursor
```

The notify is **only a doorbell** — the `(performed_at, seq)` cursor is the
source of truth, so no change is lost if a notification is missed, and a restart
resumes from the last processed cursor.

## Run it

From the repo root:

```bash
./start.sh && ./init.sh                       # bring up + load the engine

# load the 'demo' store (init.sh doesn't load examples):
cat examples/demo/model.sql examples/demo/seed.sql | \
  docker compose -f compose.yml -f compose-authzen.yml \
    exec -T authz-db psql -U authz -d authz

# start the consumer and watch its logs:
docker compose -f compose.yml -f compose-authzen.yml -f examples/watch/compose.yml \
  up watch-consumer
```

In another terminal, make changes and watch them stream:

```bash
# a small helper so the long command isn't repeated (works in bash and zsh —
# don't use DC="..." then $DC, zsh won't word-split it):
dc() { docker compose -f compose.yml -f compose-authzen.yml "$@"; }

# single grant
dc exec -T authz-db psql -U authz -d authz -c \
  "SELECT authz.write_tuple('demo','internal_user','grace','viewer','document','doc_payroll_001');"

# revoke
dc exec -T authz-db psql -U authz -d authz -c \
  "SELECT authz.delete_tuple('demo','internal_user','grace','viewer','document','doc_payroll_001');"

# a 50-tuple batch in ONE transaction → ONE doorbell (notify is deduped per txn)
dc exec -T authz-db psql -U authz -d authz -c \
  "SELECT authz.write_tuples_jsonb('demo', (SELECT jsonb_agg(jsonb_build_object(
     'user_type','internal_user','user_id','u'||g,'relation','viewer',
     'object_type','document','object_id','doc_payroll_001')) FROM generate_series(1,50) g));"
```

Consumer output looks like:

```
[watch] LISTEN authz_changes | store=demo types=all namespaces=all start=now
[watch] doorbell (notifies=1)
    INSERT internal_user:grace --viewer--> document:doc_payroll_001   (seq=1234, by=authz)
[watch] doorbell (notifies=1)
    DELETE internal_user:grace --viewer--> document:doc_payroll_001   (seq=1235, by=authz)
```

## Filtering — one watch, many types

You don't need a watch per type. Pass arrays (comma-separated env → SQL arrays):

```yaml
# in examples/watch/compose.yml, on the watch-consumer service:
WATCH_OBJECT_TYPES: "document,folder"   # only these object types
WATCH_NAMESPACES:   "docs"              # only these namespaces
WATCH_RELATIONS:    "viewer"            # only these relations
```

Equivalent SQL — e.g. "in the `acme` store, when `viewer` on a `document`/`folder`
changes within the `dms` namespace":

```sql
SELECT * FROM authz.watch_changes(
    'acme',
    p_object_types => ARRAY['document','folder'],   -- NULL = all
    p_namespaces   => ARRAY['dms'],                 -- NULL = all
    p_relations    => ARRAY['viewer']);             -- NULL = all
```

Each filter is a set (matched with OR within it) and they combine with AND.
Note the feed reports the **raw tuple that changed**, not derived permission
impact — `relations => ['viewer']` means "viewer tuples changed", not "anything
that could change viewer-derived access".

### Many watches over one connection

A single flat watch can't express *distinct* combinations — e.g. "`viewer` on
`folder`/`docs` in `foo`" **and** "`can_manage` on `contract` in `bar`" — because
the filters would AND into a cartesian product. Define one watch per combination
instead; they share one `LISTEN` connection, each with its own cursor. Set
`WATCH_SPECS` to a JSON array:

```jsonc
WATCH_SPECS='[
  {"name":"docs","object_types":["folder","docs"],"namespaces":["foo"],"relations":["viewer"]},
  {"name":"contracts","object_types":["contract"],"namespaces":["bar"],"relations":["can_manage"]}
]'
```

Output is tagged per watch:

```
    [docs]      INSERT internal_user:alice --viewer--> folder:f1   (seq=42, by=...)
    [contracts] DELETE internal_user:bob   --can_manage--> contract:c9   (seq=43, by=...)
```

Other knobs: `WATCH_FROM_BEGINNING=true` replays the whole audit log on start;
`WATCH_STORE` selects the store.

## Notes

- **Stability lag.** The consumer uses `p_lag => '0 seconds'` for demo
  immediacy. In production a small lag (or one ≥ the writer's `statement_timeout`
  for a hard no-skip guarantee) trades latency for safety — see
  `db/engine/watch.sql`. For strict exactly-once streaming, use logical
  replication on `tuples_audit` instead.
- **Privilege.** The consumer `SET ROLE authz_auditor` (the watch functions are
  granted to the auditor). Give your real consumer a login role that is a member
  of `authz_auditor`, not a superuser.
