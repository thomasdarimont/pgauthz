-- AuthZEN certification fixture — the decisions and searches the OpenID
-- conformance suite validates at the Core level (openid/authzen issue #433,
-- sections 1.4, 2.2, 3.2 and 4), asserted directly against the engine. Uses
-- the shared test helpers (tests/sql/tests_helpers.sql); run via tests/test.sh
-- after model.sql + seed.sql.
--
-- The suite reaches the same store through pgauthzd (/stores/authzen_cert/
-- access/v1/...); these checks pin the fixture itself, so a failing suite run
-- points at the HTTP layer, not the data.

SELECT _test_reset();

DO $$
DECLARE v text;
BEGIN
    -- ── Section 1.4: the validated decisions (Core rules 1–4) ───────────────
    PERFORM _test_assert('az_01_alice_read_record1',  authz.check_access('authzen_cert','user','alice','read', 'record','record-1')::text, 'true');
    PERFORM _test_assert('az_02_alice_write_record1', authz.check_access('authzen_cert','user','alice','write','record','record-1')::text, 'true');
    PERFORM _test_assert('az_03_bob_read_record1',    authz.check_access('authzen_cert','user','bob',  'read', 'record','record-1')::text, 'true');
    PERFORM _test_assert('az_04_bob_write_record1',   authz.check_access('authzen_cert','user','bob',  'write','record','record-1')::text, 'false');

    -- Rule 5 holds by the graph alone (alice only reads the archived record-2);
    -- the remaining Properties rules need request properties, which this
    -- fixture does not model.
    PERFORM _test_assert('az_05_alice_write_record2_archived', authz.check_access('authzen_cert','user','alice','write','record','record-2')::text, 'false');
    PERFORM _test_assert('az_05b_alice_read_record2',          authz.check_access('authzen_cert','user','alice','read', 'record','record-2')::text, 'true');

    -- ── Section 2.2.3: context must not change a fixture decision ───────────
    PERFORM _test_assert('az_06_context_ignored',
        authz.check_access_with_context('authzen_cert','user','alice','read','record','record-1', '{"time":"2025-06-27T18:03-07:00"}'::jsonb)::text, 'true');

    -- ── Section 3.2: batch decisions in request order ───────────────────────
    PERFORM _test_assert('az_07_batch_bob_read_then_write',
        (SELECT jsonb_agg(e->'decision')::text FROM jsonb_array_elements(authz.check_access_batch('authzen_cert',
            '[{"user_type":"user","user_id":"bob","relation":"read","object_type":"record","object_id":"record-1"},
              {"user_type":"user","user_id":"bob","relation":"write","object_type":"record","object_id":"record-1"}]'::jsonb)) e),
        '[true, false]');
    PERFORM _test_assert('az_08_batch_alice_write_active_then_archived',
        (SELECT jsonb_agg(e->'decision')::text FROM jsonb_array_elements(authz.check_access_batch('authzen_cert',
            '[{"user_type":"user","user_id":"alice","relation":"write","object_type":"record","object_id":"record-1"},
              {"user_type":"user","user_id":"alice","relation":"write","object_type":"record","object_id":"record-2"}]'::jsonb)) e),
        '[true, false]');

    -- ── Section 4.2.1: subjects of type user who can read record-1 ──────────
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO v
      FROM authz.list_subjects('authzen_cert', 'user', 'read', 'record', 'record-1');
    PERFORM _test_assert('az_09_subject_search_read_record1', v, 'alice,bob');

    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO v
      FROM authz.list_subjects('authzen_cert', 'user', 'write', 'record', 'record-1');
    PERFORM _test_assert('az_10_subject_search_write_record1', v, 'alice');

    -- ── Section 4.3.1: records alice can read (record-1 required, extras allowed) ──
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO v
      FROM authz.list_objects('authzen_cert', 'user', 'alice', 'read', 'record');
    PERFORM _test_assert('az_11_resource_search_alice_read', v, 'record-1,record-2');

    -- (bob writes record-2 only, through admin ∧ archived — the Properties level below)
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO v
      FROM authz.list_objects('authzen_cert', 'user', 'bob', 'write', 'record');
    PERFORM _test_assert('az_12_resource_search_bob_write', coalesce(v, ''), 'record-2');

    -- ── Section 4.4.1: actions alice holds on record-1 (read, write required) ──
    -- (delete needs the soft property: without context it is not listed — fail closed)
    SELECT string_agg(action, ',' ORDER BY action) INTO v
      FROM authz.list_actions('authzen_cert', 'user', 'alice', 'record', 'record-1')
     WHERE action IN ('read', 'write', 'delete');
    PERFORM _test_assert('az_13_action_search_alice_record1', v, 'read,write');

    SELECT string_agg(action, ',' ORDER BY action) INTO v
      FROM authz.list_actions('authzen_cert', 'user', 'bob', 'record', 'record-1')
     WHERE action IN ('read', 'write', 'delete');
    PERFORM _test_assert('az_14_action_search_bob_record1', v, 'read');

    -- ── Section 4.6.1: an unknown identifier is simply not there ────────────
    SELECT count(*)::text INTO v
      FROM authz.list_actions('authzen_cert', 'user', 'nonexistent-user', 'record', 'record-1');
    PERFORM _test_assert('az_15_unknown_subject_no_actions', v, '0');
    PERFORM _test_assert('az_16_unknown_subject_denied', authz.check_access('authzen_cert','user','nonexistent-user','read','record','record-1')::text, 'false');

    -- ── Properties level: rules 5–8 (openid/authzen #433 §1.4) ──────────────
    -- pgauthzd puts the request's properties into the context under the AuthZEN
    -- request shape; these checks pass that context the way the daemon builds it.
    PERFORM _test_assert('az_18_rule6_admin_writes_archived',
        authz.check_access_with_context('authzen_cert','user','bob','write','record','record-2',
            '{"subject":{"type":"user","id":"bob","properties":{"role":"admin"}},"resource":{"type":"record","id":"record-2","properties":{"status":"archived"}}}'::jsonb)::text, 'true');
    -- entity attributes are data: the decision does not depend on the asserted properties
    PERFORM _test_assert('az_18b_rule6_holds_without_properties',
        authz.check_access('authzen_cert','user','bob','write','record','record-2')::text, 'true');
    PERFORM _test_assert('az_19_rule5_alice_cannot_write_archived',
        authz.check_access_with_context('authzen_cert','user','alice','write','record','record-2',
            '{"subject":{"type":"user","id":"alice"},"resource":{"type":"record","id":"record-2","properties":{"status":"archived"}}}'::jsonb)::text, 'false');
    PERFORM _test_assert('az_19b_rule4_admin_cannot_write_active',
        authz.check_access_with_context('authzen_cert','user','bob','write','record','record-1',
            '{"subject":{"type":"user","id":"bob","properties":{"role":"admin"}},"resource":{"type":"record","id":"record-1","properties":{"status":"active"}}}'::jsonb)::text, 'false');
    PERFORM _test_assert('az_20_rule7_soft_delete_allowed',
        authz.check_access_with_context('authzen_cert','user','alice','delete','record','record-1',
            '{"action":{"name":"delete","properties":{"soft":true}}}'::jsonb)::text, 'true');
    PERFORM _test_assert('az_21_rule8_hard_delete_denied',
        authz.check_access_with_context('authzen_cert','user','alice','delete','record','record-1',
            '{"action":{"name":"delete","properties":{"soft":false}}}'::jsonb)::text, 'false');
    -- no action properties at all: the condition cannot be evaluated → fail closed,
    -- and the rich result says which context would decide it
    PERFORM _test_assert('az_21b_delete_without_soft_fails_closed',
        authz.check_access('authzen_cert','user','alice','delete','record','record-1')::text, 'false');
    PERFORM _test_assert('az_21c_delete_without_soft_is_conditional',
        (authz.check_access_detailed('authzen_cert','user','alice','delete','record','record-1', '{}'::jsonb)->>'state'), 'conditional');
    PERFORM _test_assert('az_21d_bob_cannot_delete_even_soft',
        authz.check_access_with_context('authzen_cert','user','bob','delete','record','record-1',
            '{"action":{"name":"delete","properties":{"soft":true}}}'::jsonb)::text, 'false');

    -- ── Properties level: searches (§4.2.4, §4.3.3, §4.4.3) ─────────────────
    -- who can write the archived record-2 (bob, through admin ∧ archived — the admin
    -- grant is an object-wildcard tuple, the flag is per record)
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO v
      FROM authz.list_subjects('authzen_cert', 'user', 'write', 'record', 'record-2',
           '{"resource":{"type":"record","id":"record-2","properties":{"status":"archived"}}}'::jsonb);
    PERFORM _test_assert('az_22_subject_search_write_archived', v, 'bob');
    -- which records may admin bob write (record-2 only: wildcard admin ∧ per-record flag)
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO v
      FROM authz.list_objects('authzen_cert', 'user', 'bob', 'write', 'record',
           '{"subject":{"type":"user","id":"bob","properties":{"role":"admin"}}}'::jsonb);
    PERFORM _test_assert('az_23_resource_search_admin_write', v, 'record-2');
    -- what may bob do on record-2 (write, via the same path; not read)
    SELECT string_agg(action, ',' ORDER BY action) INTO v
      FROM authz.list_actions('authzen_cert', 'user', 'bob', 'record', 'record-2',
           '{"subject":{"type":"user","id":"bob","properties":{"role":"admin"}},"resource":{"type":"record","id":"record-2","properties":{"status":"archived"}}}'::jsonb)
     WHERE action IN ('read', 'write', 'delete');
    PERFORM _test_assert('az_24_action_search_admin_archived', v, 'write');
    -- with soft requested, alice's actions on record-1 include delete
    SELECT string_agg(action, ',' ORDER BY action) INTO v
      FROM authz.list_actions('authzen_cert', 'user', 'alice', 'record', 'record-1',
           '{"action":{"name":"delete","properties":{"soft":true}}}'::jsonb)
     WHERE action IN ('read', 'write', 'delete');
    PERFORM _test_assert('az_25_action_search_soft_delete_listed', v, 'delete,read,write');

    -- ── Batch with per-item context (§3.2.3): each check carries its own context,
    -- merged over the shared one (the check wins per key) ───────────────────
    PERFORM _test_assert('az_26_batch_per_item_context',
        (SELECT jsonb_agg(e->'decision')::text FROM jsonb_array_elements(authz.check_access_batch('authzen_cert',
            '[{"user_type":"user","user_id":"alice","relation":"delete","object_type":"record","object_id":"record-1",
               "context":{"action":{"properties":{"soft":true}}}},
              {"user_type":"user","user_id":"alice","relation":"delete","object_type":"record","object_id":"record-1",
               "context":{"action":{"properties":{"soft":false}}}},
              {"user_type":"user","user_id":"alice","relation":"delete","object_type":"record","object_id":"record-1"}]'::jsonb,
            '{"action":{"properties":{"soft":true}}}'::jsonb)) e),
        '[true, false, true]');

    -- ── The model reads back as the fixture ─────────────────────────────────
    PERFORM _test_assert_true('az_17_describe_read_rule',
        position('define reader: [user]' in authz.describe_model('authzen_cert')) > 0
        AND position('define read: reader or writer' in authz.describe_model('authzen_cert')) > 0
        AND position('define write: writer or admin and archived' in authz.describe_model('authzen_cert')) > 0
        AND position('define delete: writer and soft_delete' in authz.describe_model('authzen_cert')) > 0, authz.describe_model('authzen_cert'));
END;
$$;

SELECT _test_report('AuthZEN certification fixture');
