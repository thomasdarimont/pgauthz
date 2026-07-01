-- ============================================================================
-- AuthZEN "Todo" interop model
-- ============================================================================
--
-- A pgauthz port of the OpenFGA model used in the AuthZEN interop test suite:
--   https://github.com/openfga/authzen-interop/tree/main/todo
--
-- A todo list (`todo:todo-1`) holds child items (`todo:<uuid>`, linked by
-- `parent`). Users hold a role on the list — admin, editor, evil_genius or
-- viewer — and each item has an `owner`. The interesting bit is the
-- **intersection**: deleting/updating an item requires management rights on the
-- parent list AND ownership of the item — unless you are admin (delete) or
-- evil_genius (update) on the parent, which bypass ownership.
--
-- Features demonstrated:
--   - Subject wildcards (`user:*` as can_read_user — anyone can read a profile)
--   - Union / role rollup (can_manage_todo_items = editor or admin or evil_genius)
--   - Computed relations (can_create_todo, can_read_todos)
--   - Tuple-to-userset (… from parent)
--   - INTERSECTION (AND) within a union: (manage from parent AND owner) or …
--
-- OpenFGA DSL equivalent:
--
--   type user
--     relations
--       define can_read_user: [user:*]
--
--   type todo
--     relations
--       define admin:       [user]
--       define editor:      [user]
--       define evil_genius: [user]
--       define viewer:      [user]
--       define owner:       [user]
--       define parent:      [todo]
--       define can_manage_todo_items: editor or admin or evil_genius
--       define can_create_todo:       can_manage_todo_items
--       define can_read_todos:        viewer or can_manage_todo_items
--       define can_delete_todo: (can_manage_todo_items from parent and owner) or admin from parent
--       define can_update_todo: (can_manage_todo_items from parent and owner) or evil_genius from parent

----------------------------------------------------------------------
-- Todo store. Dropped first so this file is idempotent (re-running it
-- resets the store). Audit history is purged — this is an example fixture.
----------------------------------------------------------------------
DO $$
BEGIN
    PERFORM authz.delete_store('todo', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN
    NULL;  -- store did not exist yet
END $$;
SELECT authz.create_store('todo', 'AuthZEN interop todo model');

DO $$
DECLARE
    s smallint := authz._s('todo');

    -- Type shortcuts
    t_user smallint;
    t_todo smallint;

    -- Relation shortcuts
    r_admin                 smallint;
    r_editor                smallint;
    r_evil_genius           smallint;
    r_viewer                smallint;
    r_owner                 smallint;
    r_parent                smallint;
    r_can_manage_todo_items smallint;
    r_can_create_todo       smallint;
    r_can_read_todos        smallint;
    r_can_delete_todo       smallint;
    r_can_update_todo       smallint;
    r_can_read_user         smallint;
BEGIN
    ----------------------------------------------------------------------
    -- Types
    ----------------------------------------------------------------------
    -- Ids are identity-assigned (not explicit) so this store coexists with the
    -- other example stores; the engine references types by name.
    INSERT INTO authz.types (store_id, name, description) VALUES
        (s, 'user', 'A person. Profiles are world-readable via the can_read_user wildcard.'),
        (s, 'todo', 'A todo list or a child item within one (linked to its list by `parent`).');

    -- Advisory grouping labels (used by the playground to cluster types).
    PERFORM authz.model_set_type_labels('todo', 'user', ARRAY['area:identity']);
    PERFORM authz.model_set_type_labels('todo', 'todo', ARRAY['area:tasks']);

    -- Partitions for the object types.
    PERFORM authz._ensure_tuple_partition(s, 'todo');
    PERFORM authz._ensure_tuple_partition(s, 'user');

    ----------------------------------------------------------------------
    -- Relations
    ----------------------------------------------------------------------
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'admin'),
        (s, 'editor'),
        (s, 'evil_genius'),
        (s, 'viewer'),
        (s, 'owner'),
        (s, 'parent'),
        (s, 'can_manage_todo_items'),
        (s, 'can_create_todo'),
        (s, 'can_read_todos'),
        (s, 'can_delete_todo'),
        (s, 'can_update_todo'),
        (s, 'can_read_user');

    t_user := authz._t(s, 'user');
    t_todo := authz._t(s, 'todo');

    r_admin                 := authz._r(s, 'admin');
    r_editor                := authz._r(s, 'editor');
    r_evil_genius           := authz._r(s, 'evil_genius');
    r_viewer                := authz._r(s, 'viewer');
    r_owner                 := authz._r(s, 'owner');
    r_parent                := authz._r(s, 'parent');
    r_can_manage_todo_items := authz._r(s, 'can_manage_todo_items');
    r_can_create_todo       := authz._r(s, 'can_create_todo');
    r_can_read_todos        := authz._r(s, 'can_read_todos');
    r_can_delete_todo       := authz._r(s, 'can_delete_todo');
    r_can_update_todo       := authz._r(s, 'can_update_todo');
    r_can_read_user         := authz._r(s, 'can_read_user');

    ----------------------------------------------------------------------
    -- Model rules (unions — one row per OR branch, group 0 by default)
    ----------------------------------------------------------------------
    INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed) VALUES

    -- type user: can_read_user is a plain direct relation; the `user:*` wildcard
    -- lives in the tuples (user:* can_read_user user:X), so anyone can read a profile.
    (s, t_user, r_can_read_user, authz._rel_direct(), NULL, NULL, NULL),

    -- type todo: roles + structure (direct)
    (s, t_todo, r_admin,       authz._rel_direct(), NULL, NULL, NULL),
    (s, t_todo, r_editor,      authz._rel_direct(), NULL, NULL, NULL),
    (s, t_todo, r_evil_genius, authz._rel_direct(), NULL, NULL, NULL),
    (s, t_todo, r_viewer,      authz._rel_direct(), NULL, NULL, NULL),
    (s, t_todo, r_owner,       authz._rel_direct(), NULL, NULL, NULL),
    (s, t_todo, r_parent,      authz._rel_direct(), NULL, NULL, NULL),

    -- can_manage_todo_items: editor or admin or evil_genius
    (s, t_todo, r_can_manage_todo_items, authz._rel_computed(), r_editor,      NULL, NULL),
    (s, t_todo, r_can_manage_todo_items, authz._rel_computed(), r_admin,       NULL, NULL),
    (s, t_todo, r_can_manage_todo_items, authz._rel_computed(), r_evil_genius, NULL, NULL),

    -- can_create_todo: can_manage_todo_items
    (s, t_todo, r_can_create_todo, authz._rel_computed(), r_can_manage_todo_items, NULL, NULL),

    -- can_read_todos: viewer or can_manage_todo_items
    (s, t_todo, r_can_read_todos, authz._rel_computed(), r_viewer,                NULL, NULL),
    (s, t_todo, r_can_read_todos, authz._rel_computed(), r_can_manage_todo_items, NULL, NULL);

    ----------------------------------------------------------------------
    -- Grouped rules: an intersection (group 1, AND) unioned with a single
    -- TTU (group 0, OR). Groups are OR-ed together; rules within a group with
    -- op = intersection are AND-ed.
    --
    --   can_delete_todo: (can_manage_todo_items from parent AND owner) OR admin from parent
    --   can_update_todo: (can_manage_todo_items from parent AND owner) OR evil_genius from parent
    ----------------------------------------------------------------------
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed,
                              group_id, group_op) VALUES
    -- can_delete_todo
    (s, t_todo, r_can_delete_todo, authz._rel_ttu(),      NULL,    r_parent, r_can_manage_todo_items, 1, authz._combine_and()),
    (s, t_todo, r_can_delete_todo, authz._rel_computed(), r_owner, NULL,     NULL,                    1, authz._combine_and()),
    (s, t_todo, r_can_delete_todo, authz._rel_ttu(),      NULL,    r_parent, r_admin,                 0, authz._combine_or()),
    -- can_update_todo
    (s, t_todo, r_can_update_todo, authz._rel_ttu(),      NULL,    r_parent, r_can_manage_todo_items, 1, authz._combine_and()),
    (s, t_todo, r_can_update_todo, authz._rel_computed(), r_owner, NULL,     NULL,                    1, authz._combine_and()),
    (s, t_todo, r_can_update_todo, authz._rel_ttu(),      NULL,    r_parent, r_evil_genius,           0, authz._combine_or());

    -- Profiles are world-readable. OpenFGA can only express this per-object with a
    -- subject wildcard (user:* on each user). pgauthz also supports OBJECT wildcards
    -- (object_id = '*'), which are default-deny — opt the direct rule in here so a
    -- single `(user:*, can_read_user, user:*)` tuple covers every user. (This is a
    -- pgauthz enhancement beyond the OpenFGA interop model.)
    PERFORM authz.model_add_rule('todo', 'user', 'can_read_user', 'direct', p_allow_object_wildcard => true);

END;
$$;
