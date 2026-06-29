-- Property-based differential test for the memoization wrapper.
--
-- Invariant: a memoized check must equal the un-memoized check for the SAME
-- input, on EVERY graph — otherwise the memo is unsound (e.g. it cached a
-- path-dependent / cycle-pruned result). We fuzz random graphs over a
-- feature-rich fixed model and assert, for many random checks:
--
--     check(memoize=off) == check(memoize=on)
--
-- across BOTH memo backends: temp-table (writable txn / primary) and session-GUC
-- (read-only txn / replica). The fixed model exercises OR / intersection /
-- exclusion groups, computed + TTU rules, usersets (incl. nesting), subject and
-- object wildcards, and conditions; the random graph adds cycles and diamonds;
-- random checks add request context and contextual (ephemeral) tuples.
--
-- Deterministic via setseed — a failure reproduces on re-run, and the first
-- mismatch is RAISEd with its full input so it can be replayed by hand.

SELECT _test_reset();
SELECT setseed(0.20240617);   -- bump to explore more graphs

-- ── Feature-rich model ───────────────────────────────────────────────────────
DO $$
DECLARE s int;
BEGIN
    BEGIN PERFORM authz.delete_store('memoprop'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('memoprop');
    INSERT INTO authz.types (store_id,name) VALUES (s,'user'),(s,'group'),(s,'doc');
    INSERT INTO authz.relations (store_id,name) VALUES
        (s,'member'),(s,'viewer'),(s,'editor'),(s,'owner'),(s,'parent'),(s,'blocked'),
        (s,'can_read'),(s,'can_edit'),(s,'can_admin');

    -- group.member: direct (users and nested group#member)
    PERFORM authz.model_add_rule('memoprop','group','member','direct');
    -- doc base relations (direct). viewer permits object_id = '*' (object wildcard).
    PERFORM authz.model_add_rule('memoprop','doc','viewer','direct', p_allow_object_wildcard=>true);
    PERFORM authz.model_add_rule('memoprop','doc','editor','direct');
    PERFORM authz.model_add_rule('memoprop','doc','owner','direct');
    PERFORM authz.model_add_rule('memoprop','doc','blocked','direct');
    PERFORM authz.model_add_rule('memoprop','doc','parent','direct');
    -- can_read = viewer OR owner OR editor OR parent->can_read   (OR group + TTU recursion)
    PERFORM authz.model_add_rule('memoprop','doc','can_read','computed', p_computed_relation=>'viewer',  p_group_id=>0, p_group_op=>'or');
    PERFORM authz.model_add_rule('memoprop','doc','can_read','computed', p_computed_relation=>'owner',   p_group_id=>0, p_group_op=>'or');
    PERFORM authz.model_add_rule('memoprop','doc','can_read','computed', p_computed_relation=>'editor',  p_group_id=>0, p_group_op=>'or');
    PERFORM authz.model_add_rule('memoprop','doc','can_read','ttu', p_tupleset_relation=>'parent', p_tupleset_computed=>'can_read', p_group_id=>0, p_group_op=>'or');
    -- can_edit = editor BUT NOT blocked   (exclusion group)
    PERFORM authz.model_add_rule('memoprop','doc','can_edit','computed', p_computed_relation=>'editor',  p_group_id=>1, p_group_op=>'exclusion', p_negated=>false);
    PERFORM authz.model_add_rule('memoprop','doc','can_edit','computed', p_computed_relation=>'blocked', p_group_id=>1, p_group_op=>'exclusion', p_negated=>true);
    -- can_admin = owner AND can_edit   (intersection group; can_edit is itself an exclusion)
    PERFORM authz.model_add_rule('memoprop','doc','can_admin','computed', p_computed_relation=>'owner',   p_group_id=>2, p_group_op=>'intersection');
    PERFORM authz.model_add_rule('memoprop','doc','can_admin','computed', p_computed_relation=>'can_edit', p_group_id=>2, p_group_op=>'intersection');

    -- Conditions: request-context gated ('allow' flag) and a stored-threshold one.
    INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
        (s, 'ctx_allow', '($1->>''allow'') = ''true''', '{"request":["allow"]}'::jsonb),
        (s, 'min_level', '($1->>''level'')::int >= ($2->>''min'')::int', '{"request":["level"],"stored":["min"]}'::jsonb);
END $$;

-- ── Writable phase: fuzz the graph + temp-table memo differential ─────────────
DO $$
DECLARE
    n_users int := 6; n_docs int := 7; n_groups int := 3;
    trial int; c int; i int;
    su text; sid text; rel text; doc text; grp text;
    ctx jsonb; ctup authz.tuple_input[];
    r_off boolean; r_on boolean;
    mism int := 0; first_fail text := '';
    -- pick helpers
    rels  text[] := ARRAY['viewer','editor','owner','blocked'];
    crels text[] := ARRAY['can_read','can_edit','can_admin','viewer'];
BEGIN
    FOR trial IN 1..45 LOOP
        -- ── mutate the graph (cycles, diamonds, usersets, wildcards, conditions)
        FOR i IN 1..4 LOOP
            doc := 'd' || (1 + floor(random()*n_docs))::int;
            rel := rels[1 + floor(random()*4)::int];
            CASE (floor(random()*5))::int
            WHEN 0 THEN  -- plain user grant
                PERFORM authz.write_tuple('memoprop','user','u'||(1+floor(random()*n_users))::int, rel,'doc',doc);
            WHEN 1 THEN  -- userset grant: group#member
                PERFORM authz.write_tuple('memoprop','group','g'||(1+floor(random()*n_groups))::int, rel,'doc',doc, p_user_relation=>'member');
            WHEN 2 THEN  -- subject wildcard
                PERFORM authz.write_tuple('memoprop','user','*', rel,'doc',doc);
            WHEN 3 THEN  -- conditional grant
                PERFORM authz.write_tuple('memoprop','user','u'||(1+floor(random()*n_users))::int, rel,'doc',doc,
                    p_condition=> (ARRAY['ctx_allow','min_level'])[1+floor(random()*2)::int],
                    p_condition_context=>'{"min":3}'::jsonb);
            ELSE  -- parent edge (doc d's parent = another doc) → cycles + diamonds
                PERFORM authz.write_tuple('memoprop','doc','d'||(1+floor(random()*n_docs))::int,'parent','doc',doc);
            END CASE;
        END LOOP;
        -- object wildcard + group memberships (incl. nesting)
        IF random() < 0.3 THEN
            PERFORM authz.write_tuple('memoprop','user','u'||(1+floor(random()*n_users))::int,'viewer','doc','*');
        END IF;
        PERFORM authz.write_tuple('memoprop','user','u'||(1+floor(random()*n_users))::int,'member','group','g'||(1+floor(random()*n_groups))::int);
        IF random() < 0.3 THEN  -- nested group: g#member is a member of another group
            PERFORM authz.write_tuple('memoprop','group','g'||(1+floor(random()*n_groups))::int,'member','group','g'||(1+floor(random()*n_groups))::int, p_user_relation=>'member');
        END IF;

        -- ── random checks: memoize off vs on (temp backend) ──────────────────
        FOR c IN 1..8 LOOP
            su  := 'user';
            sid := 'u' || (1 + floor(random()*(n_users+1)))::int;  -- u1..u7 (u7 ungranted)
            rel := crels[1 + floor(random()*4)::int];
            doc := 'd' || (1 + floor(random()*n_docs))::int;
            ctx := jsonb_build_object('allow', (random()<0.5), 'level', (floor(random()*6))::int);
            -- sometimes inject an ephemeral contextual tuple
            ctup := NULL;
            IF random() < 0.3 THEN
                ctup := ARRAY[ROW('user', sid, NULL,
                    rels[1+floor(random()*4)::int], 'doc', doc)::authz.tuple_input];
            END IF;

            PERFORM set_config('authz.memoize','off',true);
            r_off := authz.check_access_with_contextual_tuples('memoprop',su,sid,rel,'doc',doc, ctx, ctup);
            PERFORM set_config('authz.memoize','on',true);
            r_on  := authz.check_access_with_contextual_tuples('memoprop',su,sid,rel,'doc',doc, ctx, ctup);

            IF r_off IS DISTINCT FROM r_on THEN
                mism := mism + 1;
                IF first_fail = '' THEN
                    first_fail := format('trial=%s check(%s,%s,%s,doc,%s) ctx=%s ctup=%s -> off=%s on=%s',
                        trial, su, sid, rel, doc, ctx, (ctup IS NOT NULL), r_off, r_on);
                END IF;
            END IF;
        END LOOP;
    END LOOP;

    PERFORM set_config('authz.memoize','on',true);
    PERFORM _test_assert('memo_prop_01_temp_backend_matches_no_memo', mism::text, '0');
    IF mism > 0 THEN RAISE WARNING 'temp-backend mismatch (first): %', first_fail; END IF;
END $$;

-- ── Read-only phase: GUC-backend memo differential on the final graph ─────────
BEGIN;
SET TRANSACTION READ ONLY;
DO $$
DECLARE
    n_users int := 7; n_docs int := 7;
    c int; sid text; rel text; doc text; ctx jsonb;
    r_off boolean; r_on boolean; mism int := 0; first_fail text := '';
    crels text[] := ARRAY['can_read','can_edit','can_admin','viewer'];
BEGIN
    FOR c IN 1..250 LOOP
        sid := 'u' || (1 + floor(random()*n_users))::int;
        rel := crels[1 + floor(random()*4)::int];
        doc := 'd' || (1 + floor(random()*n_docs))::int;
        ctx := jsonb_build_object('allow', (random()<0.5), 'level', (floor(random()*6))::int);

        PERFORM set_config('authz.memoize','off',true);
        r_off := authz.check_access_with_context('memoprop','user',sid,rel,'doc',doc, ctx);
        PERFORM set_config('authz.memoize','on',true);   -- read-only txn => GUC backend
        r_on  := authz.check_access_with_context('memoprop','user',sid,rel,'doc',doc, ctx);

        IF r_off IS DISTINCT FROM r_on THEN
            mism := mism + 1;
            IF first_fail = '' THEN
                first_fail := format('check(user,%s,%s,doc,%s) ctx=%s -> off=%s on=%s',
                    sid, rel, doc, ctx, r_off, r_on);
            END IF;
        END IF;
    END LOOP;
    PERFORM set_config('authz._mp_guc_mism', mism::text, false);
    PERFORM set_config('authz._mp_guc_fail', first_fail, false);
END $$;
COMMIT;

DO $$
BEGIN
    PERFORM _test_assert('memo_prop_02_guc_backend_matches_no_memo',
        current_setting('authz._mp_guc_mism', true), '0');
    IF current_setting('authz._mp_guc_mism', true) <> '0' THEN
        RAISE WARNING 'guc-backend mismatch (first): %', current_setting('authz._mp_guc_fail', true);
    END IF;
    PERFORM authz.delete_store('memoprop');
END $$;

SELECT _test_report('memoization property / differential (random graphs)');
