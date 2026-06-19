#!/usr/bin/env python3
"""Watch-API demo consumer.

LISTENs on the `authz_changes` channel (the pg_notify doorbell the audit trigger
emits) and pulls changes via authz.watch_changes — the SpiceDB "Watch" analog.
The notify is only a doorbell; the (performed_at, seq) cursor is the source of
truth, so nothing is lost if a notification is missed.

Supports ONE or MANY watches over a single LISTEN connection — each watch has
its own filters and its own independent cursor.

Env:
  DATABASE_URL          required
  WATCH_STORE           store (default demo)
  WATCH_FROM_BEGINNING  "true" to replay the whole audit log

  Single watch (optional comma-separated filters; unset = all):
    WATCH_OBJECT_TYPES, WATCH_NAMESPACES, WATCH_RELATIONS

  Or many watches via WATCH_SPECS (JSON array), one block per combination, e.g.:
    WATCH_SPECS='[
      {"name":"docs","object_types":["folder","docs"],"namespaces":["foo"],"relations":["viewer"]},
      {"name":"contracts","object_types":["contract"],"namespaces":["bar"],"relations":["can_manage"]}
    ]'
"""
import json
import os
import select
import psycopg2

STORE = os.environ.get("WATCH_STORE", "demo")
FROM_BEGINNING = os.environ.get("WATCH_FROM_BEGINNING", "false").lower() in ("1", "true", "yes")
csv = lambda k: [s.strip() for s in os.environ.get(k, "").split(",") if s.strip()] or None


def load_specs():
    raw = os.environ.get("WATCH_SPECS", "").strip()
    specs = json.loads(raw) if raw else [{
        "name": "watch", "object_types": csv("WATCH_OBJECT_TYPES"),
        "namespaces": csv("WATCH_NAMESPACES"), "relations": csv("WATCH_RELATIONS")}]
    for i, s in enumerate(specs):
        s.setdefault("name", f"watch{i}")
        for k in ("object_types", "namespaces", "relations"):
            s.setdefault(k, None)       # None -> SQL NULL -> "all"
        s["at"], s["seq"] = None, 0     # independent cursor
    return specs


conn = psycopg2.connect(os.environ["DATABASE_URL"])
conn.autocommit = True
cur = conn.cursor()
cur.execute("SET ROLE authz_auditor")   # least privilege: the watcher is an auditor
cur.execute("LISTEN authz_changes")

WATCHES = load_specs()
if not FROM_BEGINNING:
    cur.execute("SELECT at, seq FROM authz.watch_cursor(%s)", (STORE,))
    row = cur.fetchone()
    start = (row[0], row[1] or 0) if row else (None, 0)
    for w in WATCHES:
        w["at"], w["seq"] = start

for w in WATCHES:
    print(f"[watch:{w['name']}] store={STORE} types={w['object_types'] or 'all'} "
          f"namespaces={w['namespaces'] or 'all'} relations={w['relations'] or 'all'} "
          f"start={'beginning' if FROM_BEGINNING else 'now'}", flush=True)


def drain(w):
    """Pull every change after this watch's cursor, print it, advance the cursor."""
    cur.execute(
        "SELECT seq, performed_at, action, user_type, user_id, user_relation, "
        "relation, object_type, object_id, performed_by "
        "FROM authz.watch_changes(%s, COALESCE(%s, '-infinity'::timestamptz), %s, "
        "p_lag => '0 seconds', p_object_types => %s, p_namespaces => %s, p_relations => %s) "
        "ORDER BY performed_at, seq",
        (STORE, w["at"], w["seq"], w["object_types"], w["namespaces"], w["relations"]))
    for seq, at, action, ut, uid, urel, rel, ot, oid, by in cur.fetchall():
        subj = f"{ut}:{uid}" + (f"#{urel}" if urel else "")
        print(f"    [{w['name']}] {action:<6} {subj} --{rel}--> {ot}:{oid}   (seq={seq}, by={by})", flush=True)
        w["at"], w["seq"] = at, seq


for w in WATCHES:
    drain(w)                            # emit anything pending
while True:
    # Block up to 5s for a doorbell; poll anyway on timeout as a backstop.
    if select.select([conn], [], [], 5.0) != ([], [], []):
        conn.poll()
        n = len(conn.notifies)
        conn.notifies.clear()
        print(f"[watch] doorbell (notifies={n})", flush=True)
    for w in WATCHES:
        drain(w)
