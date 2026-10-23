-- The browser suite's decision-log lines for :store, in the CONSOLE database
-- (the postgres sink's table, decisionlog.decisions — the same shape
-- pgauthzd creates; created here when the sink never ran). Loaded by
-- tests/test-console-ui.sh through the console-db service, deleted after.
--
-- 30 lines over the last 30 minutes, one per minute, newest first in the
-- tab: alice allowed can_share on doc:a (12), bob denied can_share on doc:a
-- (10, no_matching_rule), carol conditional on doc:b (5, condition_denied),
-- dave with an engine error on doc:b (3). Clients alternate docs-app /
-- mail-app; every line carries a trace id derived from its minute.
\set ON_ERROR_STOP on
CREATE SCHEMA IF NOT EXISTS decisionlog;
CREATE TABLE IF NOT EXISTS decisionlog.decisions (
    id            bigint GENERATED ALWAYS AS IDENTITY,
    ts            timestamptz NOT NULL,
    request_id    text,
    trace_id      text,
    span_id       text,
    listener      text NOT NULL,
    endpoint      text NOT NULL,
    via           text,
    store         text NOT NULL,
    subject_type  text,
    subject_id    text,
    action        text,
    resource_type text,
    resource_id   text,
    decision      boolean,
    state         text,
    reason        text,
    actor         text,
    client        text,
    issuer        text,
    latency_ms    real,
    error         text,
    line          jsonb NOT NULL
) PARTITION BY RANGE (ts);
CREATE TABLE IF NOT EXISTS decisionlog.decisions_default PARTITION OF decisionlog.decisions DEFAULT;
ALTER TABLE decisionlog.decisions ADD COLUMN IF NOT EXISTS trace_id text;
ALTER TABLE decisionlog.decisions ADD COLUMN IF NOT EXISTS span_id text;

DELETE FROM decisionlog.decisions WHERE store = :'store';

INSERT INTO decisionlog.decisions
    (ts, request_id, trace_id, span_id, listener, endpoint, via, store,
     subject_type, subject_id, action, resource_type, resource_id,
     decision, state, reason, actor, client, issuer, latency_ms, error, line)
SELECT now() - (i || ' minutes')::interval,
       'req-' || i,
       lpad(to_hex(i), 32, '0'),
       lpad(to_hex(i), 16, '0'),
       'public', 'check', 'engine', :'store',
       'user', c.subject, c.action, 'doc', c.resource,
       c.decision, c.state, c.reason,
       'user:' || c.subject,
       CASE WHEN i % 2 = 1 THEN 'docs-app' ELSE 'mail-app' END,
       'https://auth.example.com',
       0.5 + i,
       c.err,
       jsonb_build_object('ts', now() - (i || ' minutes')::interval, 'store', :'store', 'endpoint', 'check',
                          'subject', jsonb_build_object('type', 'user', 'id', c.subject),
                          'action', c.action, 'resource', jsonb_build_object('type', 'doc', 'id', c.resource),
                          'context_keys', jsonb_build_array('ip'),
                          'model', jsonb_build_object('checksum', 'sha256:uitest'))
  FROM generate_series(1, 30) AS i
  CROSS JOIN LATERAL (
      SELECT CASE WHEN i <= 12 THEN 'alice' WHEN i <= 22 THEN 'bob' WHEN i <= 27 THEN 'carol' ELSE 'dave' END AS subject,
             'can_share' AS action,
             CASE WHEN i <= 22 THEN 'a' ELSE 'b' END AS resource,
             CASE WHEN i <= 12 THEN true WHEN i <= 27 THEN false ELSE NULL END AS decision,
             CASE WHEN i <= 12 THEN 'allow' WHEN i <= 22 THEN 'deny' WHEN i <= 27 THEN 'conditional' ELSE NULL END AS state,
             CASE WHEN i <= 12 THEN 'computed' WHEN i <= 22 THEN 'no_matching_rule' WHEN i <= 27 THEN 'condition_denied' ELSE NULL END AS reason,
             CASE WHEN i > 27 THEN 'engine: statement timeout' END AS err
  ) c;
