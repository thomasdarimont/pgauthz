-- Authorization checks for the todo model — derived from the AuthZEN interop
-- assertions in authzen-todo.fga.yaml:
--   https://github.com/openfga/authzen-interop/blob/main/todo/authzen-todo.fga.yaml
-- (user ids mapped to the readable aliases used in seed.sql).

DO $$
DECLARE
    pass_count int := 0;
    fail_count int := 0;
    total      int := 0;
    result     boolean;
    rec        record;
    -- Peter is a test-only "pure evil_genius" — his role is supplied as a
    -- contextual tuple (as the interop suite does), never stored.
    peter_evil jsonb := '[{"user_type":"user","user_id":"peter","relation":"evil_genius","object_type":"todo","object_id":"todo-1"}]';
BEGIN
    CREATE TEMP TABLE test_checks (
        id          serial,
        description text,
        user_type   text,
        user_id     text,
        relation    text,
        object_type text,
        object_id   text,
        expected    boolean
    );

    INSERT INTO test_checks (description, user_type, user_id, relation, object_type, object_id, expected) VALUES
    -- Rick: admin + evil_genius on the list → manages everything, deletes (admin) and updates (evil) every item.
    ('Rick can read the list',                       'user','rick','can_read_todos', 'todo','todo-1',    true),
    ('Rick can create todos (manager)',              'user','rick','can_create_todo','todo','todo-1',    true),
    ('Rick can delete his own item',                 'user','rick','can_delete_todo','todo','item_rick', true),
    ('Rick can delete another''s item (admin)',      'user','rick','can_delete_todo','todo','item_morty',true),
    ('Rick can update another''s item (evil_genius)','user','rick','can_update_todo','todo','item_beth', true),

    -- Morty: editor, owns item_morty → can delete/update only what he owns (manage-on-parent AND owner).
    ('Morty can read the list',                      'user','morty','can_read_todos', 'todo','todo-1',     true),
    ('Morty can create todos (editor→manager)',      'user','morty','can_create_todo','todo','todo-1',     true),
    ('Morty owns item_morty',                        'user','morty','owner',          'todo','item_morty', true),
    ('Morty can delete his own item',                'user','morty','can_delete_todo','todo','item_morty', true),
    ('Morty can update his own item',                'user','morty','can_update_todo','todo','item_morty', true),
    ('Morty cannot delete Rick''s item',             'user','morty','can_delete_todo','todo','item_rick',  false),
    ('Morty cannot update Summer''s item',           'user','morty','can_update_todo','todo','item_summer',false),

    -- Summer: editor, owns item_summer.
    ('Summer can delete her own item',               'user','summer','can_delete_todo','todo','item_summer',true),
    ('Summer can update her own item',               'user','summer','can_update_todo','todo','item_summer',true),
    ('Summer cannot delete Morty''s item',           'user','summer','can_delete_todo','todo','item_morty', false),

    -- Jerry: viewer, owns item_jerry. KEY: ownership is NOT enough — a viewer is
    -- not can_manage_todo_items, so the (manage-on-parent AND owner) intersection fails.
    ('Jerry (viewer) can read the list',             'user','jerry','can_read_todos', 'todo','todo-1',     true),
    ('Jerry (viewer) cannot create todos',           'user','jerry','can_create_todo','todo','todo-1',     false),
    ('Jerry owns item_jerry',                        'user','jerry','owner',          'todo','item_jerry', true),
    ('Jerry cannot delete his OWN item (not manager)','user','jerry','can_delete_todo','todo','item_jerry',false),
    ('Jerry cannot update his OWN item (not manager)','user','jerry','can_update_todo','todo','item_jerry',false),

    -- Beth: viewer, owns item_beth — same as Jerry.
    ('Beth (viewer) can read the list',              'user','beth','can_read_todos', 'todo','todo-1',   true),
    ('Beth cannot delete her own item',              'user','beth','can_delete_todo','todo','item_beth',false),

    -- Profiles are world-readable (user:* wildcard) — even an unknown user.
    ('Anyone can read a user profile',               'user','somebody_new','can_read_user','user','rick', true),
    ('Rick can read Beth''s profile',                'user','rick','can_read_user','user','beth',          true);

    FOR rec IN SELECT * FROM test_checks ORDER BY id LOOP
        total := total + 1;
        result := authz.check_access('todo', rec.user_type, rec.user_id, rec.relation, rec.object_type, rec.object_id);
        IF result = rec.expected THEN
            pass_count := pass_count + 1;
            RAISE NOTICE '    PASS  %', rec.description;
        ELSE
            fail_count := fail_count + 1;
            RAISE NOTICE '    FAIL  %  (expected=%, got=%)', rec.description, rec.expected, result;
        END IF;
    END LOOP;

    -- Peter (pure evil_genius) via a CONTEXTUAL tuple — as the interop suite does.
    -- He can update any item (evil_genius from parent) but delete none (delete needs
    -- admin from parent). Not a stored user; the role lives only in `peter_evil`.
    CREATE TEMP TABLE peter_checks (description text, relation text, object_id text, expected boolean);
    INSERT INTO peter_checks VALUES
        ('Peter (contextual evil_genius) can create todos',       'can_create_todo', 'todo-1',     true),
        ('Peter (contextual evil_genius) can update any item',    'can_update_todo', 'item_morty', true),
        ('Peter (contextual evil_genius) cannot delete any item', 'can_delete_todo', 'item_morty', false);
    FOR rec IN SELECT * FROM peter_checks ORDER BY description LOOP
        total := total + 1;
        result := authz.check_access_with_contextual_tuples_jsonb(
            'todo', 'user', 'peter', rec.relation, 'todo', rec.object_id, NULL, peter_evil);
        IF result = rec.expected THEN
            pass_count := pass_count + 1;
            RAISE NOTICE '    PASS  %', rec.description;
        ELSE
            fail_count := fail_count + 1;
            RAISE NOTICE '    FAIL  %  (expected=%, got=%)', rec.description, rec.expected, result;
        END IF;
    END LOOP;
    DROP TABLE peter_checks;

    RAISE NOTICE '';
    RAISE NOTICE '==> % passed, % failed (of % todo checks)', pass_count, fail_count, total;

    DROP TABLE test_checks;

    IF fail_count > 0 THEN
        RAISE EXCEPTION '% checks failed', fail_count;
    END IF;
END;
$$;
