-- Compositional tri-state for check_access_detailed (review #4 P0).
--
-- `conditional` must mean "supplying the missing context could flip DENY→ALLOW"
-- — not merely "some condition lacked context somewhere in the trace". Proven
-- by the engine's optimistic second pass (authz._assume_missing_ctx). These
-- exercise the dominance rules across OR / AND / EXCLUSION with a
-- conditional-on-missing term next to structural allow/deny terms.

SELECT _test_reset();

DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_ts'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_ts');
    PERFORM authz.model_register_type('test_ts', 'user');
    PERFORM authz.model_register_type('test_ts', 'doc');
    PERFORM authz.model_register_relation('test_ts', 'a');       -- base term A
    PERFORM authz.model_register_relation('test_ts', 'b');       -- base term B
    PERFORM authz.model_register_relation('test_ts', 'banned');  -- exclusion term
    PERFORM authz.model_register_relation('test_ts', 'and_ab');  -- a AND b
    PERFORM authz.model_register_relation('test_ts', 'or_ab');   -- a OR b
    PERFORM authz.model_register_relation('test_ts', 'excl');    -- a BUT NOT banned
    -- a AND b  (intersection, group 1)
    PERFORM authz.model_add_rule('test_ts','doc','and_ab','computed', p_computed_relation=>'a', p_group_id=>1, p_group_op=>'intersection');
    PERFORM authz.model_add_rule('test_ts','doc','and_ab','computed', p_computed_relation=>'b', p_group_id=>1, p_group_op=>'intersection');
    -- a OR b  (two OR groups)
    PERFORM authz.model_add_rule('test_ts','doc','or_ab','computed', p_computed_relation=>'a', p_group_id=>0);
    PERFORM authz.model_add_rule('test_ts','doc','or_ab','computed', p_computed_relation=>'b', p_group_id=>1);
    -- a BUT NOT banned  (exclusion, group 1)
    PERFORM authz.model_add_rule('test_ts','doc','excl','computed', p_computed_relation=>'a',      p_group_id=>1, p_group_op=>'exclusion');
    PERFORM authz.model_add_rule('test_ts','doc','excl','computed', p_computed_relation=>'banned', p_group_id=>1, p_group_op=>'exclusion', p_negated=>true);
    PERFORM authz.model_add_rule('test_ts','doc','a','direct');
    PERFORM authz.model_add_rule('test_ts','doc','b','direct');
    PERFORM authz.model_add_rule('test_ts','doc','banned','direct');
    PERFORM authz.create_condition_sql('test_ts','cond', $e$ ($1->>'k')='ok' $e$, '{"request":["k"]}');
END;
$$;

-- Helper: assert the detailed state for (user, relation).
CREATE FUNCTION pg_temp._ts(p_user text, p_rel text, p_ctx jsonb DEFAULT NULL) RETURNS text
LANGUAGE sql AS $$
    SELECT authz.check_access_detailed('test_ts','user',p_user,p_rel,'doc','d1',p_ctx)->>'state';
$$;

DO $$
BEGIN
    -- AND: a=conditional(missing), b=DENY(no tuple) → structural deny wins.
    PERFORM authz.write_tuple('test_ts','user','u1','a','doc','d1', p_condition=>'cond');
    PERFORM _test_assert('ts_1_and__cond_AND_hardDeny', pg_temp._ts('u1','and_ab'), 'deny');

    -- AND: a=conditional(missing), b=ALLOW → missing context is the only blocker.
    PERFORM authz.write_tuple('test_ts','user','u2','a','doc','d1', p_condition=>'cond');
    PERFORM authz.write_tuple('test_ts','user','u2','b','doc','d1');
    PERFORM _test_assert('ts_2_and__cond_AND_allow', pg_temp._ts('u2','and_ab'), 'conditional');
    PERFORM _test_assert('ts_2b_and__with_ctx_allows', pg_temp._ts('u2','and_ab','{"k":"ok"}'), 'allow');

    -- OR: a=DENY(no tuple), b=conditional(missing) → could flip → conditional.
    PERFORM authz.write_tuple('test_ts','user','u3','b','doc','d1', p_condition=>'cond');
    PERFORM _test_assert('ts_3_or__hardDeny_OR_cond', pg_temp._ts('u3','or_ab'), 'conditional');

    -- OR: a=ALLOW → allow regardless of the other branch.
    PERFORM authz.write_tuple('test_ts','user','u4','a','doc','d1');
    PERFORM _test_assert('ts_4_or__allow_dominates', pg_temp._ts('u4','or_ab'), 'allow');

    -- Plain deny: no grant at all, no conditions → deny (not conditional).
    PERFORM _test_assert('ts_5_plain_deny', pg_temp._ts('nobody','and_ab'), 'deny');

    -- EXCLUSION: a=conditional(missing), not banned → base could flip → conditional.
    PERFORM authz.write_tuple('test_ts','user','u6','a','doc','d1', p_condition=>'cond');
    PERFORM _test_assert('ts_6_excl__cond_base_not_banned', pg_temp._ts('u6','excl'), 'conditional');

    -- EXCLUSION: a=ALLOW but banned → excluded → hard deny, context irrelevant.
    PERFORM authz.write_tuple('test_ts','user','u7','a','doc','d1');
    PERFORM authz.write_tuple('test_ts','user','u7','banned','doc','d1');
    PERFORM _test_assert('ts_7_excl__banned_hard_deny', pg_temp._ts('u7','excl'), 'deny');
END;
$$;

DO $$ BEGIN PERFORM authz.delete_store('test_ts'); END; $$;

SELECT _test_report('decision tri-state');
