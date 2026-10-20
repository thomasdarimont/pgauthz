-- Random tuple mutations against one store, for the derived-permissions
-- differential in tests/test-replication.sh (and ad-hoc soak runs).
--
-- Parameters arrive as GUCs because psql does not interpolate :vars inside a
-- DO body. Preamble:
--   SELECT set_config('mutate.store', 'demo', false),
--          set_config('mutate.n',     '30',   false),
--          set_config('mutate.seed',  '0.42', false);
--   \i tests/sql/derived_permissions_mutate.sql
--
-- Each iteration draws one of: direct grant (to a known, a fresh or — where
-- the restriction allows it — the '*' subject; on a known or a fresh object),
-- expiring direct grant (1–3 s), revoke of a random tuple, revoke of a random
-- userset / wildcard tuple, userset grant (team#member style), object-wildcard
-- grant. Writes the model rejects (type restrictions, wildcards not allowed,
-- namespaces) and draws with nothing to act on are counted as rejected and
-- skipped, so the walk stays inside the model; any other error is counted as
-- UNEXPECTED and reported with its first message — the test asserts zero.
-- setseed() makes a run reproducible for a given seed and starting state
-- (the walk still depends on which expiring tuples are alive, i.e. on
-- cadence).
DO $$
DECLARE
    v_store    text  := current_setting('mutate.store');
    v_n        int   := current_setting('mutate.n')::int;
    v_seed     float := current_setting('mutate.seed')::float;
    v_store_id int;
    v_i        int;
    v_op       int;
    v_otype    text; v_rel text; v_utype text; v_urel text;
    v_obj      text; v_subj text; v_wild boolean;
    v_applied    int := 0;
    v_rejected   int := 0;
    v_unexpected int := 0;
    v_first_err  text;
    v_msg        text;
BEGIN
    PERFORM setseed(v_seed);
    v_store_id := authz._s(v_store);

    FOR v_i IN 1..v_n LOOP
        v_op := floor(random() * 10)::int;
        v_otype := NULL; v_rel := NULL; v_utype := NULL; v_urel := NULL; v_obj := NULL; v_subj := NULL;
        BEGIN
            IF v_op <= 3 OR v_op = 7 THEN
                -- direct grant (7: expiring)
                SELECT ot.name, r.name, ut.name, tr.allow_wildcard
                  INTO v_otype, v_rel, v_utype, v_wild
                  FROM authz.type_restrictions tr
                  JOIN authz.types     ot ON ot.id = tr.object_type
                  JOIN authz.relations r  ON r.id  = tr.relation
                  JOIN authz.types     ut ON ut.id = tr.allowed_user_type
                 WHERE tr.store_id = v_store_id
                   AND tr.allowed_user_relation IS NULL AND tr.condition_id IS NULL
                 ORDER BY random() LIMIT 1;
                IF v_otype IS NULL THEN RAISE EXCEPTION 'no direct restriction'; END IF;

                IF random() < 0.2 THEN
                    v_obj := 'rnd_' || v_otype || '_' || floor(random() * 4)::int;
                ELSE
                    SELECT t.object_id INTO v_obj
                      FROM authz.tuples t JOIN authz.types ot ON ot.id = t.object_type
                     WHERE t.store_id = v_store_id AND ot.name = v_otype AND t.object_id <> '*'
                     ORDER BY random() LIMIT 1;
                    v_obj := COALESCE(v_obj, 'rnd_' || v_otype || '_0');
                END IF;

                IF v_wild AND random() < 0.2 THEN
                    v_subj := '*';
                ELSIF random() < 0.15 THEN
                    v_subj := 'rnd_' || v_utype || '_' || floor(random() * 4)::int;
                ELSE
                    SELECT t.user_id INTO v_subj
                      FROM authz.tuples t JOIN authz.types ut ON ut.id = t.user_type
                     WHERE t.store_id = v_store_id AND ut.name = v_utype
                       AND t.user_relation IS NULL AND t.user_id <> '*'
                     ORDER BY random() LIMIT 1;
                    v_subj := COALESCE(v_subj, 'rnd_' || v_utype || '_0');
                END IF;

                IF v_op = 7 THEN
                    PERFORM authz.write_tuple(v_store, v_utype, v_subj, v_rel, v_otype, v_obj,
                        p_expires_at => clock_timestamp() + make_interval(secs => 1 + random() * 2));
                ELSE
                    PERFORM authz.write_tuple(v_store, v_utype, v_subj, v_rel, v_otype, v_obj);
                END IF;

            ELSIF v_op <= 5 OR v_op = 9 THEN
                -- revoke a random tuple (9: a userset or wildcard tuple if there is one)
                SELECT ut.name, t.user_id, r.name, ot.name, t.object_id, ur.name
                  INTO v_utype, v_subj, v_rel, v_otype, v_obj, v_urel
                  FROM authz.tuples t
                  JOIN authz.types     ut ON ut.id = t.user_type
                  JOIN authz.relations r  ON r.id  = t.relation
                  JOIN authz.types     ot ON ot.id = t.object_type
             LEFT JOIN authz.relations ur ON ur.id = t.user_relation
                 WHERE t.store_id = v_store_id
                   AND (v_op <> 9 OR t.user_relation IS NOT NULL OR t.user_id = '*' OR t.object_id = '*')
                 ORDER BY random() LIMIT 1;
                IF v_subj IS NULL THEN RAISE EXCEPTION 'nothing to revoke'; END IF;
                PERFORM authz.delete_tuple(v_store, v_utype, v_subj, v_rel, v_otype, v_obj, v_urel);

            ELSIF v_op = 6 THEN
                -- userset grant: a known object of the restriction's user type, as <type>:<id>#<relation>
                SELECT ot.name, r.name, ut.name, ur.name
                  INTO v_otype, v_rel, v_utype, v_urel
                  FROM authz.type_restrictions tr
                  JOIN authz.types     ot ON ot.id = tr.object_type
                  JOIN authz.relations r  ON r.id  = tr.relation
                  JOIN authz.types     ut ON ut.id = tr.allowed_user_type
                  JOIN authz.relations ur ON ur.id = tr.allowed_user_relation
                 WHERE tr.store_id = v_store_id AND tr.condition_id IS NULL
                 ORDER BY random() LIMIT 1;
                IF v_otype IS NULL THEN RAISE EXCEPTION 'no userset restriction'; END IF;
                SELECT t.object_id INTO v_obj
                  FROM authz.tuples t JOIN authz.types ot ON ot.id = t.object_type
                 WHERE t.store_id = v_store_id AND ot.name = v_otype AND t.object_id <> '*'
                 ORDER BY random() LIMIT 1;
                SELECT t.object_id INTO v_subj
                  FROM authz.tuples t JOIN authz.types ot ON ot.id = t.object_type
                 WHERE t.store_id = v_store_id AND ot.name = v_utype AND t.object_id <> '*'
                 ORDER BY random() LIMIT 1;
                IF v_obj IS NULL OR v_subj IS NULL THEN RAISE EXCEPTION 'no objects for userset'; END IF;
                PERFORM authz.write_tuple(v_store, v_utype, v_subj, v_rel, v_otype, v_obj, p_user_relation => v_urel);

            ELSE
                -- object-wildcard grant on a relation whose direct rule allows it
                SELECT ot.name, r.name INTO v_otype, v_rel
                  FROM authz.models m
                  JOIN authz.types     ot ON ot.id = m.object_type
                  JOIN authz.relations r  ON r.id  = m.relation
                 WHERE m.store_id = v_store_id AND m.allow_object_wildcard
                 ORDER BY random() LIMIT 1;
                IF v_otype IS NULL THEN RAISE EXCEPTION 'no object-wildcard rule'; END IF;
                SELECT ut.name INTO v_utype
                  FROM authz.type_restrictions tr
                  JOIN authz.types     ut ON ut.id = tr.allowed_user_type
                  JOIN authz.types     ot ON ot.id = tr.object_type
                  JOIN authz.relations r  ON r.id  = tr.relation
                 WHERE tr.store_id = v_store_id AND ot.name = v_otype AND r.name = v_rel
                   AND tr.allowed_user_relation IS NULL
                 ORDER BY random() LIMIT 1;
                IF v_utype IS NULL THEN RAISE EXCEPTION 'no direct restriction for the wildcard rule'; END IF;
                IF random() < 0.5 THEN
                    v_subj := 'rnd_' || v_utype || '_' || floor(random() * 4)::int;
                ELSE
                    SELECT t.user_id INTO v_subj
                      FROM authz.tuples t JOIN authz.types ut ON ut.id = t.user_type
                     WHERE t.store_id = v_store_id AND ut.name = v_utype
                       AND t.user_relation IS NULL AND t.user_id <> '*'
                     ORDER BY random() LIMIT 1;
                    v_subj := COALESCE(v_subj, 'rnd_' || v_utype || '_0');
                END IF;
                PERFORM authz.write_tuple(v_store, v_utype, v_subj, v_rel, v_otype, '*');
            END IF;
            v_applied := v_applied + 1;
        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS v_msg = MESSAGE_TEXT;
            IF v_msg ~* '^(type restriction|wildcard|namespace|nothing to revoke|no [a-z -]+(restriction|rule|objects))'
               OR v_msg ~* 'not allowed|restriction|namespace' THEN
                v_rejected := v_rejected + 1;
            ELSE
                v_unexpected := v_unexpected + 1;
                v_first_err := COALESCE(v_first_err, v_msg);
            END IF;
        END;
    END LOOP;

    RAISE NOTICE 'mutate % (seed %, % draws): % applied, % rejected by the model, % unexpected errors%',
        v_store, v_seed, v_n, v_applied, v_rejected, v_unexpected,
        COALESCE(' (first: ' || v_first_err || ')', '');
END;
$$;
