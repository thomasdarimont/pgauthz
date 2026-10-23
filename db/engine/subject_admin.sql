-- Data subject requests, the WRITE half (GDPR Art. 17, erasure): remove
-- everything a store holds about one subject — the tuples naming it on
-- either side (incl. expired rows), its recorded actions, and optionally
-- the audit rows that name it. Admin tier: it crosses every namespace and
-- it removes history. Returns the counts.
--
-- Consequences to know (why this is not delete_user_tuples):
--   * the tuple deletes are AUDITED like every write (performed_by =
--     p_performed_by), so the trail records that the subject's rows went —
--     and then, with p_purge_audit, that trail is removed too, inside the
--     same transaction, under the maintenance window the audit triggers
--     honour. Prefer keeping the audit (the default) unless the request is
--     for the history itself; time travel over the subject's grants is
--     exact only while it is kept;
--   * purging the subject's events can only RELAX a temporal gate that
--     counts them (a cap counts fewer actions) — the erasure is deliberate,
--     so there is no cutoff guard here, unlike purge_events;
--   * the decision log of a pgauthzd (ADR 0013/0015) is the daemon's own
--     store: the console erases its sink rows alongside this call.
-- See export_subject (subject.sql) for the read half.

-- _rls_delete_subject_tuples: both sides, incl. expired rows. Runs as
-- authz_rls_bypass; the audit trigger logs each row.
CREATE OR REPLACE FUNCTION authz._rls_delete_subject_tuples(
    p_store_id int,
    p_type_id  int,
    p_user_id  text,
    OUT as_subject int,
    OUT as_object  int
)
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM authz.tuples
     WHERE store_id = p_store_id AND user_type = p_type_id AND user_id = p_user_id;
    GET DIAGNOSTICS as_subject = ROW_COUNT;
    DELETE FROM authz.tuples
     WHERE store_id = p_store_id AND object_type = p_type_id AND object_id = p_user_id;
    GET DIAGNOSTICS as_object = ROW_COUNT;
END;
$$;

CREATE OR REPLACE FUNCTION authz.erase_subject(
    p_store        text,
    p_user_type    text,
    p_user_id      text,
    p_purge_events boolean DEFAULT true,
    p_purge_audit  boolean DEFAULT false,
    p_performed_by text    DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store, true);   -- a retired store can still be erased from
    v_type_id  integer := authz._t(v_store_id, p_user_type);
    v_sub      int;
    v_obj      int;
    v_events   bigint := 0;
    v_audit    bigint := 0;
BEGIN
    IF p_user_id IS NULL OR btrim(p_user_id) = '' THEN
        RAISE EXCEPTION 'p_user_id is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);

    SELECT d.as_subject, d.as_object INTO v_sub, v_obj
      FROM authz._rls_delete_subject_tuples(v_store_id, v_type_id, p_user_id) d;

    IF p_purge_events THEN
        PERFORM set_config('authz.audit_maintenance', 'on', true);
        DELETE FROM authz.events e
         WHERE e.store_id = v_store_id AND e.subject_type = v_type_id AND e.subject_id = p_user_id;
        GET DIAGNOSTICS v_events = ROW_COUNT;
        PERFORM set_config('authz.audit_maintenance', '', true);
    END IF;

    IF p_purge_audit THEN
        PERFORM set_config('authz.audit_maintenance', 'on', true);
        DELETE FROM authz.tuples_audit a
         WHERE a.store_id = v_store_id
           AND ((a.user_type = v_type_id AND a.user_id = p_user_id)
             OR (a.object_type = v_type_id AND a.object_id = p_user_id));
        GET DIAGNOSTICS v_audit = ROW_COUNT;
        PERFORM set_config('authz.audit_maintenance', '', true);
    END IF;

    RETURN jsonb_build_object(
        'store', p_store, 'subject', jsonb_build_object('type', p_user_type, 'id', p_user_id),
        'tuples_as_subject', v_sub, 'tuples_as_object', v_obj,
        'events', v_events, 'audit', v_audit, 'erased_at', now());
END;
$$;
