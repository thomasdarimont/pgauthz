#!/usr/bin/env python3
"""Action-log ingestion consumer (ADR 0012).

Reads events from a Redis Stream via a consumer group and records them in
pgauthz — the reference OUTBOX → queue → pgauthz path. The engine promises
idempotency (a re-delivered event_id + occurred_at is a duplicate, never a
second row) and atomic batches (one bad element rejects the batch); this
consumer supplies the other half of "reliable feeding":

  * at-least-once: messages are acknowledged only after pgauthz confirmed them;
    pending entries of a dead consumer are re-claimed on start (XAUTOCLAIM);
  * content rejections (undeclared action, bad payload, recorder allowlist,
    namespace — 4xx / SQLSTATE 22xxx, 23xxx, 54000, P0001) are DEAD-LETTERED
    with the reason and acknowledged: they will never succeed by retrying, and
    dropping them would silently weaken every gate that counts them;
  * transport / server errors are retried with exponential backoff, unacked;
  * a batch that fails as a whole is retried element by element so one bad
    message cannot block its neighbours;
  * metrics (Prometheus) for consumed / recorded / duplicates / dead-lettered
    by reason / retries / batch latency / INGESTION LAG (now − occurred_at) —
    lag and dead letters are how a lost or late `response` shows up.

Message contract (one JSON object per message, the flat record_events_jsonb
shape): subject_type, subject_id, action (a declared relation of the store),
optional object_type/object_id, kind (request|response|denied), payload,
occurred_at (REQUIRED — the moment the action completed, set by the producer,
never at publish time) and event_id (the producer's request id + kind; the
stream message id is the fallback). Two sinks: "sql" records through
authz.record_events_jsonb as a dedicated recorder role; "http" POSTs to
pgauthzd's /pgauthz/v1/events with a RECORDER_ROLE token.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone

import redis
from prometheus_client import Counter, Gauge, Histogram, start_http_server

BROKER_URL = os.environ["BROKER_URL"]
STREAM = os.environ.get("EVENTS_STREAM", "pgauthz.events")
DLQ = os.environ.get("EVENTS_DLQ", STREAM + ".dlq")
GROUP = os.environ.get("EVENTS_GROUP", "pgauthz")
CONSUMER = os.environ.get("EVENTS_CONSUMER", f"consumer-{os.getpid()}")
STORE = os.environ.get("EVENTS_STORE", "demo")
SINK = os.environ.get("EVENTS_SINK", "sql")
RECORDED_BY = os.environ.get("RECORDED_BY", "svc:events-consumer")
BATCH = int(os.environ.get("BATCH_SIZE", "100"))
BLOCK_MS = int(os.environ.get("BLOCK_MS", "2000"))
CLAIM_IDLE_MS = int(os.environ.get("CLAIM_IDLE_MS", "60000"))

consumed = Counter("pgauthz_events_consumer_consumed_total", "Messages read from the stream")
recorded = Counter("pgauthz_events_consumer_recorded_total", "Events pgauthz recorded (new rows)")
duplicates = Counter("pgauthz_events_consumer_duplicates_total", "Events pgauthz reported as re-deliveries")
dead_lettered = Counter("pgauthz_events_consumer_dead_lettered_total", "Messages moved to the DLQ", ["reason"])
retries = Counter("pgauthz_events_consumer_retries_total", "Batches retried after a transport/server error")
batch_seconds = Histogram("pgauthz_events_consumer_batch_seconds", "Sink round-trip per batch")
lag_seconds = Histogram("pgauthz_events_consumer_ingestion_lag_seconds",
                        "now - occurred_at at record time (a late or lost response shows up here)",
                        buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3600, 21600, 86400))
pending = Gauge("pgauthz_events_consumer_pending", "Delivered but unacknowledged entries in the group")

REQUIRED = ("subject_type", "subject_id", "action", "occurred_at")
ALLOWED = REQUIRED + ("object_type", "object_id", "kind", "payload", "event_id")


class Rejected(Exception):
    """A content rejection: retrying cannot succeed → dead-letter."""


class Transient(Exception):
    """A transport/server error: retry with backoff."""


# ── sinks ─────────────────────────────────────────────────────────────────────
class SQLSink:
    def __init__(self):
        import psycopg2
        self.psycopg2 = psycopg2
        self.conn = None

    def _connect(self):
        if self.conn is None or self.conn.closed:
            self.conn = self.psycopg2.connect(os.environ["DATABASE_URL"])
            self.conn.autocommit = True

    def record(self, events):
        try:
            self._connect()
            with self.conn.cursor() as cur:
                cur.execute("SELECT authz.record_events_jsonb(%s, %s::jsonb, %s)",
                            (STORE, json.dumps(events), RECORDED_BY))
                return cur.fetchone()[0]
        except self.psycopg2.Error as e:
            code = e.pgcode or ""
            # The same classification pgauthzd applies (mapEngineError): content
            # rejections are the caller's problem, everything else is transient.
            if code.startswith(("22", "23")) or code in ("54000", "P0001", "42501"):
                raise Rejected(f"{code} {e.pgerror.strip().splitlines()[0] if e.pgerror else e}") from e
            self.conn = None
            raise Transient(str(e).strip().splitlines()[0]) from e


class HTTPSink:
    def __init__(self):
        import requests
        self.requests = requests
        self.url = os.environ["PGAUTHZD_URL"].rstrip("/") + f"/stores/{STORE}/pgauthz/v1/events"
        self.headers = {"Content-Type": "application/json",
                        "Authorization": "Bearer " + os.environ["EVENTS_TOKEN"]}

    def record(self, events):
        try:
            r = self.requests.post(self.url, headers=self.headers, timeout=10,
                                   json={"events": events, "consistency": "applied"})
        except self.requests.RequestException as e:
            raise Transient(str(e)) from e
        if r.status_code == 200:
            return r.json()
        if 400 <= r.status_code < 500 and r.status_code not in (401, 408, 429):
            raise Rejected(f"HTTP {r.status_code} {r.text.strip()[:300]}")
        raise Transient(f"HTTP {r.status_code} {r.text.strip()[:300]}")


# ── message handling ──────────────────────────────────────────────────────────
def parse(msg_id, fields):
    raw = fields.get(b"event") or fields.get(b"data")
    if raw is None:
        raise Rejected("message has no 'event' field")
    try:
        ev = json.loads(raw)
    except ValueError as e:
        raise Rejected(f"invalid JSON: {e}") from e
    if not isinstance(ev, dict):
        raise Rejected("event is not a JSON object")
    for k in ev:
        if k not in ALLOWED:
            raise Rejected(f"unknown key {k!r}")
    for k in REQUIRED:
        if not ev.get(k):
            raise Rejected(f"missing {k!r} (occurred_at must be the producer's completion time)")
    ev.setdefault("kind", "response")
    ev.setdefault("event_id", msg_id.decode())   # fallback: the stream id is unique and stable across re-delivery
    return ev


def lag_of(ev):
    try:
        t = datetime.fromisoformat(ev["occurred_at"].replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - t).total_seconds())
    except (ValueError, KeyError, TypeError):
        return None


def dead_letter(r, msg_id, fields, reason):
    r.xadd(DLQ, {**{k.decode(): v for k, v in fields.items()},
                 "reason": reason[:500], "source_id": msg_id.decode(),
                 "dead_lettered_at": datetime.now(timezone.utc).isoformat()})
    r.xack(STREAM, GROUP, msg_id)
    dead_lettered.labels(reason=reason.split(" ")[0][:40]).inc()
    print(f"[events] DLQ {msg_id.decode()}: {reason}", flush=True)


def record_batch(sink, r, entries):
    """entries: list of (msg_id, fields). Returns when every entry is acked or dead-lettered."""
    parsed, bad = [], []
    for msg_id, fields in entries:
        try:
            parsed.append((msg_id, fields, parse(msg_id, fields)))
        except Rejected as e:
            bad.append((msg_id, fields, str(e)))
    for msg_id, fields, reason in bad:
        dead_letter(r, msg_id, fields, reason)
    if not parsed:
        return
    events = [ev for _, _, ev in parsed]
    backoff = 0.5
    while True:
        try:
            with batch_seconds.time():
                result = sink.record(events)
            break
        except Rejected:
            # One element poisoned the atomic batch: isolate it by retrying singly.
            if len(parsed) == 1:
                msg_id, fields, _ = parsed[0]
                dead_letter(r, msg_id, fields, str(sys.exc_info()[1]))
                return
            for item in parsed:
                record_batch(sink, r, [(item[0], item[1])])
            return
        except Transient as e:
            retries.inc()
            print(f"[events] transient error, retrying in {backoff:.1f}s: {e}", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
    n_rec = int(result.get("recorded", 0))
    n_dup = int(result.get("duplicates", 0))
    recorded.inc(n_rec)
    duplicates.inc(n_dup)
    for _, _, ev in parsed:
        lag = lag_of(ev)
        if lag is not None:
            lag_seconds.observe(lag)
    r.xack(STREAM, GROUP, *[msg_id for msg_id, _, _ in parsed])
    print(f"[events] batch of {len(parsed)}: recorded={n_rec} duplicates={n_dup}", flush=True)


def main():
    start_http_server(int(os.environ.get("METRICS_PORT", "9110")))
    r = redis.Redis.from_url(BROKER_URL)
    try:
        r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise
    sink = SQLSink() if SINK == "sql" else HTTPSink()
    print(f"[events] consumer={CONSUMER} group={GROUP} stream={STREAM} dlq={DLQ} store={STORE} sink={SINK}", flush=True)

    # Recover entries a previous consumer took but never acknowledged.
    claimed = r.xautoclaim(STREAM, GROUP, CONSUMER, min_idle_time=CLAIM_IDLE_MS, count=BATCH)
    entries = claimed[1] if isinstance(claimed, (list, tuple)) and len(claimed) > 1 else []
    if entries:
        print(f"[events] re-claimed {len(entries)} pending entries", flush=True)
        consumed.inc(len(entries))
        record_batch(sink, r, entries)

    while True:
        resp = r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, count=BATCH, block=BLOCK_MS)
        try:
            pending.set(r.xpending(STREAM, GROUP)["pending"])
        except Exception:
            pass
        if not resp:
            continue
        for _, entries in resp:
            consumed.inc(len(entries))
            record_batch(sink, r, entries)


if __name__ == "__main__":
    main()
