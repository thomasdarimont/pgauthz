-- Tests for authz.describe_model — readable rendering of a stored model.
-- Exercises the paths the demo model doesn't: type restrictions (direct user,
-- userset, wildcard), union, intersection, and exclusion.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_desc();
CREATE FUNCTION _test_setup_desc() RETURNS void LANGUAGE plpgsql AS $$
DECLARE s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_desc'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_desc');
    s := authz._s('test_desc');
    INSERT INTO authz.types (store_id, name) VALUES (s,'user'),(s,'team'),(s,'folder'),(s,'doc');
    INSERT INTO authz.relations (store_id, name) VALUES
        (s,'member'),(s,'parent'),(s,'viewer'),(s,'editor'),(s,'banned'),
        (s,'can_read'),(s,'can_edit'),(s,'can_share');
    PERFORM authz._ensure_tuple_partition(s,'team');
    PERFORM authz._ensure_tuple_partition(s,'folder');
    PERFORM authz._ensure_tuple_partition(s,'doc');

    -- team#member, folder#viewer, doc direct relations
    INSERT INTO authz.models (store_id,object_type,relation,rule_type,computed_relation,tupleset_relation,tupleset_computed,group_id,group_op) VALUES
        (s, authz._t(s,'team'),   authz._r(s,'member'), authz._rel_direct(), NULL,NULL,NULL, 0, authz._combine_or()),
        (s, authz._t(s,'folder'), authz._r(s,'viewer'), authz._rel_direct(), NULL,NULL,NULL, 0, authz._combine_or()),
        (s, authz._t(s,'doc'),    authz._r(s,'parent'), authz._rel_direct(), NULL,NULL,NULL, 0, authz._combine_or()),
        (s, authz._t(s,'doc'),    authz._r(s,'viewer'), authz._rel_direct(), NULL,NULL,NULL, 0, authz._combine_or()),
        (s, authz._t(s,'doc'),    authz._r(s,'editor'), authz._rel_direct(), NULL,NULL,NULL, 0, authz._combine_or()),
        (s, authz._t(s,'doc'),    authz._r(s,'banned'), authz._rel_direct(), NULL,NULL,NULL, 0, authz._combine_or());

    -- type restrictions on team#member ([user]) and doc#viewer ([user, team#member, user:*])
    INSERT INTO authz.type_restrictions (store_id,object_type,relation,allowed_user_type,allowed_user_relation,allow_wildcard) VALUES
        (s, authz._t(s,'team'), authz._r(s,'member'), authz._t(s,'user'), NULL, false),
        (s, authz._t(s,'doc'),  authz._r(s,'viewer'), authz._t(s,'user'), NULL, false),
        (s, authz._t(s,'doc'),  authz._r(s,'viewer'), authz._t(s,'team'), authz._r(s,'member'), false),
        (s, authz._t(s,'doc'),  authz._r(s,'viewer'), authz._t(s,'user'), NULL, true);

    -- can_read = viewer or editor or viewer from parent   (union + TTU)
    INSERT INTO authz.models (store_id,object_type,relation,rule_type,computed_relation,tupleset_relation,tupleset_computed,group_id,group_op) VALUES
        (s, authz._t(s,'doc'), authz._r(s,'can_read'), authz._rel_computed(), authz._r(s,'viewer'), NULL, NULL, 0, authz._combine_or()),
        (s, authz._t(s,'doc'), authz._r(s,'can_read'), authz._rel_computed(), authz._r(s,'editor'), NULL, NULL, 0, authz._combine_or()),
        (s, authz._t(s,'doc'), authz._r(s,'can_read'), authz._rel_ttu(),      NULL, authz._r(s,'parent'), authz._r(s,'viewer'), 0, authz._combine_or());

    -- can_edit = editor and viewer   (intersection)
    INSERT INTO authz.models (store_id,object_type,relation,rule_type,computed_relation,tupleset_relation,tupleset_computed,group_id,group_op) VALUES
        (s, authz._t(s,'doc'), authz._r(s,'can_edit'), authz._rel_computed(), authz._r(s,'editor'), NULL, NULL, 0, authz._combine_and()),
        (s, authz._t(s,'doc'), authz._r(s,'can_edit'), authz._rel_computed(), authz._r(s,'viewer'), NULL, NULL, 0, authz._combine_and());

    -- can_share = viewer but not banned   (exclusion)
    INSERT INTO authz.models (store_id,object_type,relation,rule_type,computed_relation,tupleset_relation,tupleset_computed,group_id,group_op,negated) VALUES
        (s, authz._t(s,'doc'), authz._r(s,'can_share'), authz._rel_computed(), authz._r(s,'viewer'), NULL, NULL, 0, authz._combine_exclusion(), false),
        (s, authz._t(s,'doc'), authz._r(s,'can_share'), authz._rel_computed(), authz._r(s,'banned'), NULL, NULL, 0, authz._combine_exclusion(), true);
END;
$$;

SELECT _test_setup_desc();

DO $$
DECLARE d text;
BEGIN
    d := authz.describe_model('test_desc');

    PERFORM _test_assert_true('desc_01_direct_type_restriction',
        position('define member: [user]' in d) > 0, d);
    PERFORM _test_assert_true('desc_02_userset_and_wildcard_restriction',
        position('team#member' in d) > 0 AND position('user:*' in d) > 0, d);
    PERFORM _test_assert_true('desc_03_union_and_ttu',
        position('define can_read: viewer or editor or viewer from parent' in d) > 0, d);
    PERFORM _test_assert_true('desc_04_intersection',
        position('define can_edit: editor and viewer' in d) > 0, d);
    PERFORM _test_assert_true('desc_05_exclusion',
        position('define can_share: viewer but not banned' in d) > 0, d);
    PERFORM _test_assert_true('desc_06_type_header',
        position('type doc' in d) > 0 AND position('store: test_desc' in d) > 0, d);
END $$;

SELECT authz.delete_store('test_desc');
DROP FUNCTION IF EXISTS _test_setup_desc();

SELECT _test_report('describe_model checks');
