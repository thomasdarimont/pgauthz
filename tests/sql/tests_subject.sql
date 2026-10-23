-- Data subject requests (engine/subject.sql, subject_admin.sql): the export
-- of everything a store holds about a subject, and its erasure.
SELECT _test_reset();

DO $$
DECLARE
    s      integer;
    v_doc  jsonb;
    v_res  jsonb;
    v_err  text;
BEGIN
    BEGIN PERFORM authz.delete_store('test_subject', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_subject');
    s := authz._s('test_subject');
    PERFORM authz.model_register_type('test_subject', 'user');
    PERFORM authz.model_register_type('test_subject', 'team');
    PERFORM authz.model_register_type('test_subject', 'doc');
    PERFORM authz.model_register_relation('test_subject', 'member');
    PERFORM authz.model_register_relation('test_subject', 'owner');
    PERFORM authz.model_register_relation('test_subject', 'viewer');
    PERFORM authz.model_register_relation('test_subject', 'can_view');
    PERFORM authz.model_register_relation('test_subject', 'can_read_user');
    PERFORM authz.model_register_relation('test_subject', 'download');
    PERFORM authz.model_add_rule('test_subject', 'team', 'member', 'direct');
    PERFORM authz.model_add_rule('test_subject', 'doc', 'owner', 'direct');
    PERFORM authz.model_add_rule('test_subject', 'doc', 'viewer', 'direct', p_allow_object_wildcard => true);
    PERFORM authz.model_add_rule('test_subject', 'doc', 'can_view', 'computed', 'owner');
    PERFORM authz.model_add_rule('test_subject', 'doc', 'can_view', 'computed', 'viewer');
    PERFORM authz.model_add_rule('test_subject', 'user', 'can_read_user', 'direct');

    -- alice: owns doc a, views doc b directly, views doc c through team eng,
    -- an expired grant on doc d; bob may read alice's profile; alice acted twice
    PERFORM authz.write_tuple('test_subject', 'user', 'alice', 'owner', 'doc', 'a');
    PERFORM authz.write_tuple('test_subject', 'user', 'alice', 'viewer', 'doc', 'b');
    PERFORM authz.write_tuple('test_subject', 'user', 'alice', 'member', 'team', 'eng');
    PERFORM authz.write_tuple('test_subject', 'team', 'eng', 'viewer', 'doc', 'c', p_user_relation => 'member');
    PERFORM authz.write_tuple('test_subject', 'user', 'alice', 'viewer', 'doc', 'd', p_expires_at => now() + interval '1 hour');
    -- age the grant past its expiry (the engine refuses writing one already expired)
    UPDATE authz.tuples SET expires_at = now() - interval '1 hour'
     WHERE store_id = s AND user_id = 'alice' AND object_id = 'd';
    PERFORM authz.write_tuple('test_subject', 'user', 'bob', 'can_read_user', 'user', 'alice');
    PERFORM authz.write_tuple('test_subject', 'user', 'bob', 'owner', 'doc', 'z');
    PERFORM authz.record_event('test_subject', 'user', 'alice', 'download', 'doc', 'a');
    PERFORM authz.record_event('test_subject', 'user', 'alice', 'download', 'doc', 'b');
    PERFORM authz.record_event('test_subject', 'user', 'bob', 'download', 'doc', 'z');

    v_doc := authz.export_subject('test_subject', 'user', 'alice');

    -- ds_01: the direct tuples, the expired one marked
    PERFORM _test_assert('ds_01_direct',
        (SELECT string_agg(e->>'object_type' || ':' || (e->>'object_id') || '#' || (e->>'relation') || CASE WHEN (e->>'expired')::boolean THEN '(expired)' ELSE '' END, ',' ORDER BY e->>'object_type', e->>'object_id')
           FROM jsonb_array_elements(v_doc->'direct') e),
        'doc:a#owner,doc:b#viewer,doc:d#viewer(expired),team:eng#member');
    -- ds_02: who may do what to the subject
    PERFORM _test_assert('ds_02_as_object',
        (SELECT string_agg((e->>'user_type') || ':' || (e->>'user_id') || '#' || (e->>'relation'), ',') FROM jsonb_array_elements(v_doc->'as_object') e),
        'user:bob#can_read_user');
    -- ds_03: effective access resolves computed relations and team membership, not the expired grant
    PERFORM _test_assert('ds_03_effective_can_view',
        (SELECT e->'objects' FROM jsonb_array_elements(v_doc->'effective') e WHERE e->>'object_type' = 'doc' AND e->>'relation' = 'can_view')::text,
        '["a", "b", "c"]');
    PERFORM _test_assert('ds_03b_effective_pairs',
        (SELECT string_agg((e->>'object_type') || '#' || (e->>'relation'), ',' ORDER BY e->>'object_type', e->>'relation') FROM jsonb_array_elements(v_doc->'effective') e),
        'doc#can_view,doc#owner,doc#viewer,team#member');
    -- ds_04: the subject's events only
    PERFORM _test_assert('ds_04_events', jsonb_array_length(v_doc->'events')::text || '|' || (v_doc->'events'->0->>'object_id'), '2|a');
    -- ds_05: the audit trail names the subject on either side: 4 inserts as user, 1 as
    -- object, and the ageing UPDATE above (audited as DELETE + INSERT)
    PERFORM _test_assert('ds_05_audit', jsonb_array_length(v_doc->'audit')::text, '7');
    -- ds_05b: the effective part marks the direct grants
    PERFORM _test_assert('ds_05b_effective_direct',
        (SELECT (e->'direct')::text FROM jsonb_array_elements(v_doc->'effective') e WHERE e->>'object_type' = 'doc' AND e->>'relation' = 'can_view'), 'null');
    -- ds_06: the limit truncates and says so
    v_res := authz.export_subject('test_subject', 'user', 'alice', p_limit => 1);
    PERFORM _test_assert('ds_06_truncated',
        (v_res->>'events_truncated') || '|' || (v_res->>'audit_truncated') || '|' ||
        (SELECT (e->>'truncated') FROM jsonb_array_elements(v_res->'effective') e WHERE e->>'relation' = 'can_view'),
        'true|true|true');
    -- ds_07: restricting the effective listing to relations
    v_res := authz.export_subject('test_subject', 'user', 'alice', p_relations => ARRAY['owner']);
    PERFORM _test_assert('ds_07_relations_filter',
        (SELECT string_agg((e->>'object_type') || '#' || (e->>'relation'), ',') FROM jsonb_array_elements(v_res->'effective') e), 'doc#owner');
    -- ds_07b: the takeout question as rows — every reachable object with its relation,
    -- direct grants marked, narrowed by relation and type, a wildcard as '*'
    PERFORM authz.write_tuple('test_subject', 'user', '*', 'viewer', 'doc', 'public');
    PERFORM _test_assert('ds_07b_list_subject_objects',
        (SELECT string_agg(o.object_type || ':' || o.object_id || '#' || o.relation || CASE WHEN o.direct THEN '!' ELSE '' END, ',' ORDER BY o.object_type, o.relation, o.object_id)
           FROM authz.list_subject_objects('test_subject', 'user', 'alice', ARRAY['can_view', 'owner'], ARRAY['doc']) o),
        'doc:a#can_view,doc:b#can_view,doc:c#can_view,doc:public#can_view,doc:a#owner!');
    -- an OBJECT wildcard (alice may view every doc) is one row, '*', is_wildcard
    PERFORM authz.write_tuple('test_subject', 'user', 'alice', 'viewer', 'doc', '*');
    PERFORM _test_assert('ds_07c_list_subject_objects_wildcard',
        (SELECT (count(*) FILTER (WHERE o.object_id = '*' AND o.is_wildcard AND o.direct))::text || '|' || (count(*) >= 1)::text
           FROM authz.list_subject_objects('test_subject', 'user', 'alice', ARRAY['viewer'], ARRAY['doc']) o),
        '1|true');
    PERFORM authz.delete_tuple('test_subject', 'user', 'alice', 'viewer', 'doc', '*');
    PERFORM _test_assert('ds_07d_list_subject_objects_truncated',
        (SELECT count(*)::text || '|' || bool_or(o.truncated)::text FROM authz.list_subject_objects('test_subject', 'user', 'alice', ARRAY['can_view'], ARRAY['doc'], 2) o),
        '3|true');
    PERFORM _test_assert('ds_07e_export_effective_direct',
        (SELECT (e->'direct')::text FROM jsonb_array_elements(authz.export_subject('test_subject', 'user', 'alice', ARRAY['viewer'])->'effective') e WHERE e->>'object_type' = 'doc'),
        '["b"]');
    PERFORM authz.delete_tuple('test_subject', 'user', '*', 'viewer', 'doc', 'public');
    PERFORM _test_assert('ds_07f_role_tier_reader',
        has_function_privilege('authz_reader', 'authz.list_subject_objects(text, text, text, text[], text[], int)', 'EXECUTE')::text, 'true');

    -- ds_08: an empty subject id is refused
    BEGIN
        PERFORM authz.export_subject('test_subject', 'user', ' ');
        v_err := 'no error';
    EXCEPTION WHEN invalid_parameter_value THEN v_err := 'error'; END;
    PERFORM _test_assert('ds_08_empty_id_refused', v_err, 'error');

    -- ds_09: erasure — tuples on both sides incl. expired, events; the audit kept by default
    v_res := authz.erase_subject('test_subject', 'user', 'alice', p_performed_by => 'dpo');
    PERFORM _test_assert('ds_09_erase_counts',
        (v_res->>'tuples_as_subject') || '|' || (v_res->>'tuples_as_object') || '|' || (v_res->>'events') || '|' || (v_res->>'audit'),
        '4|1|2|0');
    PERFORM _test_assert('ds_10_nothing_left',
        (SELECT jsonb_array_length(d->'direct')::text || '|' || jsonb_array_length(d->'as_object')::text || '|' || jsonb_array_length(d->'effective')::text || '|' || jsonb_array_length(d->'events')::text
           FROM authz.export_subject('test_subject', 'user', 'alice') d),
        '0|0|0|0');
    -- bob keeps his own doc; his grant ABOUT alice went with her (she was its object)
    PERFORM _test_assert('ds_11_others_untouched',
        (SELECT jsonb_array_length(d->'direct')::text || '|' || jsonb_array_length(d->'events')::text FROM authz.export_subject('test_subject', 'user', 'bob') d), '1|1');
    -- the deletes are audited with the actor; the subject's history is still there
    PERFORM _test_assert('ds_12_erasure_audited',
        (SELECT count(*)::text || '|' || max(performed_by) FROM authz.tuples_audit a
          WHERE a.store_id = s AND a.action = 'DELETE' AND a.user_id = 'alice' AND a.performed_by = 'dpo'), '4|dpo');
    -- ds_13: erasing the audit too leaves no row naming the subject
    v_res := authz.erase_subject('test_subject', 'user', 'alice', p_purge_audit => true);
    PERFORM _test_assert('ds_13_audit_purged',
        (v_res->>'audit') || '|' || (SELECT count(*) FROM authz.tuples_audit a WHERE a.store_id = s AND (a.user_id = 'alice' OR a.object_id = 'alice'))::text,
        '14|0');   -- 7 rows of history + the public wildcard write/delete + 5 audited deletes
    -- ds_14: the role tiers — auditors export, only admins erase
    PERFORM _test_assert('ds_14_role_tiers',
        has_function_privilege('authz_auditor', 'authz.export_subject(text, text, text, text[], boolean, boolean, boolean, int)', 'EXECUTE')::text
        || '|' || has_function_privilege('authz_reader', 'authz.export_subject(text, text, text, text[], boolean, boolean, boolean, int)', 'EXECUTE')::text
        || '|' || has_function_privilege('authz_admin', 'authz.erase_subject(text, text, text, boolean, boolean, text)', 'EXECUTE')::text
        || '|' || has_function_privilege('authz_writer', 'authz.erase_subject(text, text, text, boolean, boolean, text)', 'EXECUTE')::text,
        'true|false|true|false');

    PERFORM authz.delete_store('test_subject', p_purge_audit => true);
END $$;

SELECT _test_report('data subject requests');
