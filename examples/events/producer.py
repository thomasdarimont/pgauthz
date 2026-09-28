#!/usr/bin/env python3
"""Publish sample action-log events to the stream the consumer reads.

Models the OUTBOX side: the application writes one message per completed
action with occurred_at = the completion time and event_id = its own request
id + kind, so re-publishing the same message is a no-op downstream.

  producer.py --count 20                                  # alice completed 20 downloads
  producer.py --count 1 --action no_such_action           # undeclared action → DLQ
  producer.py --count 1 --kind request --payload '{"input": {"bytes": 1}}'
"""
import argparse
import json
import os
import uuid
from datetime import datetime, timezone

import redis

ap = argparse.ArgumentParser()
ap.add_argument("--count", type=int, default=1)
ap.add_argument("--subject-type", default="internal_user")
ap.add_argument("--subject", default="alice")
ap.add_argument("--action", default="can_read")
ap.add_argument("--object-type", default="document")
ap.add_argument("--object", default="doc_payroll_001")
ap.add_argument("--kind", default="response")
ap.add_argument("--payload", default='{"output": {"bytes": 1048576}}')
ap.add_argument("--replay", default=None,
                help="re-publish the SAME message: fixed event_id AND a fixed occurred_at (the outbox row's "
                     "completion time — here the current hour mark stands in for it). Demonstrates idempotency.")
args = ap.parse_args()

r = redis.Redis.from_url(os.environ["BROKER_URL"])
stream = os.environ.get("EVENTS_STREAM", "pgauthz.events")
for i in range(args.count):
    req_id = args.replay or uuid.uuid4().hex[:12]
    ev = {
        "subject_type": args.subject_type, "subject_id": args.subject,
        "action": args.action, "object_type": args.object_type, "object_id": args.object,
        "kind": args.kind, "payload": json.loads(args.payload),
        # The completion time, set by the producer. A re-publish of the same
        # message MUST carry the same occurred_at: with event_id it is the
        # idempotency key (the engine refuses event_id without occurred_at).
        "occurred_at": (datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
                        if args.replay else datetime.now(timezone.utc)).isoformat(),
        "event_id": f"{req_id}/{args.kind}",
    }
    msg_id = r.xadd(stream, {"event": json.dumps(ev)})
    print(f"published {msg_id.decode()} event_id={ev['event_id']} {ev['action']} {ev['kind']}")
