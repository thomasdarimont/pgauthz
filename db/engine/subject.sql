-- Data subject requests (GDPR Art. 15 access / Art. 20 portability), the
-- READ half: everything a store holds about one subject, as one JSON
-- document. A tenant that receives "give me my data" from a person of
-- theirs has no idea which applications' tuples, actions and history name
-- that person — this answers it for a store in one call:
--
--   direct     the tuples where the subject is the user (its grants and
--              memberships, incl. expired rows RLS hides from decisions)
--   as_object  the tuples whose object is the subject itself (who may do
--              what TO the person, e.g. user:* can_read_user user:alice)
--   effective  what the subject can effectively reach: per (object type,
--              relation) of the model, the objects list_subject_objects
--              resolves (through teams, computed relations, wildcards — '*'
--              when a wildcard grants every object; `direct` names the ones
--              a tuple grants outright), capped per pair by p_limit. THIS
--              is the takeout question: which records of which applications
--              the person relates to — list_subject_objects answers it as
--              rows, for a JOIN against the application's own tables
--   events     the subject's recorded actions (action log, ADR 0012)
--   events_about  actions OTHER principals recorded ON the subject (the
--              subject as the event's object — review #20)
--   audit      every tuple change that named the subject, either side
--
-- Auditor tier (it reveals everything about a person). The WRITE half —
-- erase_subject, Art. 17 — is in subject_admin.sql. The decision log of a
-- pgauthzd (ADR 0013/0015) is the daemon's own store and is exported by the
-- console / the sink's owner, not here.
--
-- Read profile: tuples_audit and events are read as tables (they exist on
-- every install; the audit functions are the audit profile's).

-- _rls_subject_tuples: the tuples naming the subject on either side,
-- INCLUDING expired rows. Runs as authz_rls_bypass; returns rows to the
-- SECURITY DEFINER caller only (EXECUTE is authz_owner's alone).
CREATE OR REPLACE FUNCTION authz._rls_subject_tuples(
    p_store_id int,
    p_type_id  int,
    p_user_id  text
) RETURNS TABLE (
    side              text,
    user_type         int,
    user_id           text,
    user_relation     int,
    relation          int,
    object_type       int,
    object_id         text,
    condition_id      int,
    condition_context jsonb,
    created_at        timestamptz,
    expires_at        timestamptz
)
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN t.user_type = p_type_id AND t.user_id = p_user_id THEN 'subject' ELSE 'object' END,
           t.user_type, t.user_id, t.user_relation, t.relation, t.object_type, t.object_id,
           t.condition_id, t.condition_context, t.created_at, t.expires_at
      FROM authz.tuples t
     WHERE t.store_id = p_store_id
       AND ((t.user_type = p_type_id AND t.user_id = p_user_id)
         OR (t.object_type = p_type_id AND t.object_id = p_user_id));
$$;

-- list_subject_objects: WHICH objects a subject relates to — the takeout
-- question an application answers with a JOIN. One row per (object type,
-- relation, object) the subject can effectively reach through the model
-- (direct grants, team membership, computed relations, parent folders;
-- a wildcard grant is one row with is_wildcard = true and object_id '*'),
-- optionally narrowed to relations (owner, …) and object types; `direct`
-- says a tuple names the subject on that object and relation itself.
--
--   -- every record of the application's tables that alice owns or may read:
--   SELECT d.* FROM app.documents d
--     JOIN authz.list_subject_objects('demo', 'internal_user', 'alice',
--                                     ARRAY['owner', 'can_read'], ARRAY['document']) o
--       ON o.object_id = d.id;
--
-- Reader tier (it tells what one subject may reach, as list_objects does).
-- p_limit caps the objects per (type, relation) pair; the pair's last row
-- carries truncated = true when it hit.
CREATE OR REPLACE FUNCTION authz.list_subject_objects(
    p_store        text,
    p_user_type    text,
    p_user_id      text,
    p_relations    text[] DEFAULT NULL,   -- NULL: every relation the model defines
    p_object_types text[] DEFAULT NULL,   -- NULL: every object type
    p_limit        int    DEFAULT 10000
) RETURNS TABLE (
    object_type text,
    relation    text,
    object_id   text,
    is_wildcard boolean,
    direct      boolean,
    truncated   boolean
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id integer := authz._s(p_store, true);
    v_type_id  integer := authz._t(v_store_id, p_user_type);
    r          record;
BEGIN
    IF p_user_id IS NULL OR btrim(p_user_id) = '' THEN
        RAISE EXCEPTION 'p_user_id is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 THEN
        RAISE EXCEPTION 'p_limit must be >= 1' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR r IN
        SELECT DISTINCT ot.id AS type_id, ot.name AS object_type, rl.id AS rel_id, rl.name AS relation
          FROM authz.models m
          JOIN authz.types     ot ON ot.id = m.object_type
          JOIN authz.relations rl ON rl.id = m.relation
         WHERE m.store_id = v_store_id
           AND (p_relations    IS NULL OR rl.name = ANY (p_relations))
           AND (p_object_types IS NULL OR ot.name = ANY (p_object_types))
         ORDER BY 2, 4
    LOOP
        -- a pair the subject's type cannot hold yields no rows; any other
        -- failure propagates (review #20: an export claiming completeness
        -- must not swallow errors)
            RETURN QUERY
                SELECT r.object_type, r.relation,
                       CASE WHEN o.is_wildcard THEN '*' ELSE o.object_id END,
                       o.is_wildcard,
                       EXISTS (SELECT 1 FROM authz.tuples t
                                WHERE t.store_id = v_store_id AND t.object_type = r.type_id AND t.relation = r.rel_id
                                  AND t.object_id = o.object_id AND t.user_type = v_type_id AND t.user_id = p_user_id
                                  AND t.user_relation IS NULL),
                       o.rn > p_limit
                  FROM (SELECT x.object_id, x.is_wildcard, row_number() OVER (ORDER BY x.is_wildcard DESC, x.object_id) AS rn
                          FROM authz.list_objects(p_store, p_user_type, p_user_id, r.relation, r.object_type, NULL, p_limit + 1) x) o
                 WHERE o.rn <= p_limit + 1
                 ORDER BY o.rn;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION authz.export_subject(
    p_store             text,
    p_user_type         text,
    p_user_id           text,
    p_relations         text[]  DEFAULT NULL,   -- restrict `effective` to these relations (NULL: every relation of the model)
    p_include_effective boolean DEFAULT true,
    p_include_events    boolean DEFAULT true,
    p_include_audit     boolean DEFAULT true,
    p_limit             int     DEFAULT 10000   -- cap per list (objects per pair, events, audit rows); `truncated` says when it hit
) RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id  integer := authz._s(p_store, true);   -- retired stores stay exportable
    v_type_id   integer := authz._t(v_store_id, p_user_type);
    v_direct    jsonb;
    v_as_object jsonb;
    v_effective jsonb := '[]'::jsonb;
    v_events    jsonb := NULL;
    v_about     jsonb := NULL;
    v_audit     jsonb := NULL;
    v_events_n  bigint := 0;
    v_about_n   bigint := 0;
    v_audit_n   bigint := 0;
BEGIN
    IF p_user_id IS NULL OR btrim(p_user_id) = '' THEN
        RAISE EXCEPTION 'p_user_id is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 THEN
        RAISE EXCEPTION 'p_limit must be >= 1' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- the subject's own tuples (expired ones marked, not hidden)
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'object_type', ot.name, 'object_id', x.object_id, 'relation', rl.name,
               'user_relation', ur.name, 'condition', c.name, 'condition_context', x.condition_context,
               'created_at', x.created_at, 'expires_at', x.expires_at,
               'expired', x.expires_at IS NOT NULL AND x.expires_at <= statement_timestamp())
               ORDER BY ot.name, rl.name, x.object_id), '[]'::jsonb)
      INTO v_direct
      FROM authz._rls_subject_tuples(v_store_id, v_type_id, p_user_id) x
      JOIN authz.types     ot ON ot.id = x.object_type
      JOIN authz.relations rl ON rl.id = x.relation
      LEFT JOIN authz.relations  ur ON ur.id = x.user_relation
      LEFT JOIN authz.conditions c  ON c.id  = x.condition_id
     WHERE x.side = 'subject';

    -- the tuples whose object is the subject
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'user_type', ut.name, 'user_id', x.user_id, 'user_relation', ur.name, 'relation', rl.name,
               'condition', c.name, 'condition_context', x.condition_context,
               'created_at', x.created_at, 'expires_at', x.expires_at,
               'expired', x.expires_at IS NOT NULL AND x.expires_at <= statement_timestamp())
               ORDER BY rl.name, ut.name, x.user_id), '[]'::jsonb)
      INTO v_as_object
      FROM authz._rls_subject_tuples(v_store_id, v_type_id, p_user_id) x
      JOIN authz.types     ut ON ut.id = x.user_type
      JOIN authz.relations rl ON rl.id = x.relation
      LEFT JOIN authz.relations  ur ON ur.id = x.user_relation
      LEFT JOIN authz.conditions c  ON c.id  = x.condition_id
     WHERE x.side = 'object';

    -- what the subject can effectively reach, per (object type, relation) of
    -- the model — list_subject_objects, the takeout question, grouped
    IF p_include_effective THEN
        SELECT coalesce(jsonb_agg(jsonb_build_object(
                   'object_type', g.object_type, 'relation', g.relation,
                   'objects', g.objects, 'direct', g.direct, 'truncated', g.truncated)
                   ORDER BY g.object_type, g.relation), '[]'::jsonb)
          INTO v_effective
          FROM (SELECT o.object_type, o.relation,
                       jsonb_agg(o.object_id ORDER BY o.is_wildcard DESC, o.object_id) FILTER (WHERE NOT o.truncated) AS objects,
                       jsonb_agg(o.object_id ORDER BY o.object_id) FILTER (WHERE o.direct AND NOT o.truncated) AS direct,
                       bool_or(o.truncated) AS truncated
                  FROM authz.list_subject_objects(p_store, p_user_type, p_user_id, p_relations, NULL, p_limit) o
                 GROUP BY o.object_type, o.relation) g;
        v_effective := (SELECT coalesce(jsonb_agg(CASE WHEN e->'objects' IS NULL OR e->'objects' = 'null'::jsonb THEN e || '{"objects": []}' ELSE e END), '[]'::jsonb)
                          FROM jsonb_array_elements(v_effective) e);
    END IF;

    -- the subject's recorded actions
    IF p_include_events THEN
        SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.occurred_at, e.seq), '[]'::jsonb), count(*)
          INTO v_events, v_events_n
          FROM authz.list_events(p_store, p_user_type, p_user_id, p_limit => p_limit + 1) e;
        IF v_events_n > p_limit THEN
            v_events := (SELECT coalesce(jsonb_agg(e), '[]'::jsonb) FROM (SELECT e FROM jsonb_array_elements(v_events) e LIMIT p_limit) s);
        END IF;
        -- what others did TO the subject (the subject as the event's object)
        SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.occurred_at, e.seq), '[]'::jsonb), count(*)
          INTO v_about, v_about_n
          FROM authz.list_events(p_store, p_object_type => p_user_type, p_object_id => p_user_id, p_limit => p_limit + 1) e
         WHERE NOT (e.subject_type = p_user_type AND e.subject_id = p_user_id);
        IF v_about_n > p_limit THEN
            v_about := (SELECT coalesce(jsonb_agg(e), '[]'::jsonb) FROM (SELECT e FROM jsonb_array_elements(v_about) e LIMIT p_limit) s);
        END IF;
    END IF;

    -- every tuple change that named the subject, either side
    IF p_include_audit THEN
        SELECT coalesce(jsonb_agg(jsonb_build_object(
                   'performed_at', a.performed_at, 'performed_by', a.performed_by, 'action', a.action,
                   'user_type', ut.name, 'user_id', a.user_id, 'user_relation', ur.name, 'relation', rl.name,
                   'object_type', ot.name, 'object_id', a.object_id, 'condition_context', a.condition_context)
                   ORDER BY a.performed_at, a.seq), '[]'::jsonb), count(*)
          INTO v_audit, v_audit_n
          FROM (SELECT * FROM authz.tuples_audit ta
                 WHERE ta.store_id = v_store_id
                   AND ((ta.user_type = v_type_id AND ta.user_id = p_user_id)
                     OR (ta.object_type = v_type_id AND ta.object_id = p_user_id))
                 ORDER BY ta.performed_at, ta.seq
                 LIMIT p_limit + 1) a
          JOIN authz.types     ut ON ut.id = a.user_type
          JOIN authz.types     ot ON ot.id = a.object_type
          JOIN authz.relations rl ON rl.id = a.relation
          LEFT JOIN authz.relations ur ON ur.id = a.user_relation;
        IF v_audit_n > p_limit THEN
            v_audit := (SELECT coalesce(jsonb_agg(e), '[]'::jsonb) FROM (SELECT e FROM jsonb_array_elements(v_audit) e LIMIT p_limit) s);
        END IF;
    END IF;

    RETURN jsonb_build_object(
        'store',       p_store,
        'subject',     jsonb_build_object('type', p_user_type, 'id', p_user_id),
        'exported_at', now(),
        'limit',       p_limit,
        'direct',      v_direct,
        'as_object',   v_as_object,
        'effective',   v_effective,
        'events',      v_events,
        'events_truncated', v_events_n > p_limit,
        'events_about', v_about,
        'events_about_truncated', v_about_n > p_limit,
        'audit',       v_audit,
        'audit_truncated',  v_audit_n > p_limit);
END;
$$;
