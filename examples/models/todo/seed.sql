-- Sample tuples for the AuthZEN todo model.
--
-- This mirrors the roles and ownership of the OpenFGA interop fixture
--   https://github.com/openfga/authzen-interop/tree/main/todo
-- but uses readable ids instead of the opaque OIDC `sub` claims. The mapping:
--
--   rick    = admin + evil_genius on the list, owns item_rick     (interop fd0…)
--   morty   = editor,               owns item_morty               (interop fd1…)
--   summer  = editor,               owns item_summer              (interop fd2…)
--   jerry   = viewer,               owns item_jerry               (interop fd3…)
--   beth    = viewer,               owns item_beth                (interop fd4…)
--
-- (The interop's "pure evil_genius" user `peter` is intentionally NOT seeded — the
--  interop supplies him as a per-test CONTEXTUAL tuple, not stored data; tests.sql
--  does the same with check_access_with_contextual_tuples.)
--
-- todo-1 is the list; item_* are its children (linked by `parent`).
--
-- write_tuple args: (store, SUBJECT_type, SUBJECT_id, relation, OBJECT_type, OBJECT_id).

DO $$
BEGIN
    ------------------------------------------------------------------
    -- Roles on the list todo:todo-1  (subject = user:<x>)
    ------------------------------------------------------------------
    PERFORM authz.write_tuple('todo', 'user', 'rick',   'admin',       'todo', 'todo-1');
    PERFORM authz.write_tuple('todo', 'user', 'rick',   'evil_genius', 'todo', 'todo-1');
    PERFORM authz.write_tuple('todo', 'user', 'morty',  'editor',      'todo', 'todo-1');
    PERFORM authz.write_tuple('todo', 'user', 'summer', 'editor',      'todo', 'todo-1');
    PERFORM authz.write_tuple('todo', 'user', 'jerry',  'viewer',      'todo', 'todo-1');
    PERFORM authz.write_tuple('todo', 'user', 'beth',   'viewer',      'todo', 'todo-1');

    ------------------------------------------------------------------
    -- Child items: each has the list as `parent` (subject = todo:todo-1)
    -- and one `owner` (subject = user:<x>).
    ------------------------------------------------------------------
    PERFORM authz.write_tuple('todo', 'todo', 'todo-1', 'parent', 'todo', 'item_morty');
    PERFORM authz.write_tuple('todo', 'user', 'morty',  'owner',  'todo', 'item_morty');

    PERFORM authz.write_tuple('todo', 'todo', 'todo-1', 'parent', 'todo', 'item_rick');
    PERFORM authz.write_tuple('todo', 'user', 'rick',   'owner',  'todo', 'item_rick');

    PERFORM authz.write_tuple('todo', 'todo', 'todo-1', 'parent', 'todo', 'item_summer');
    PERFORM authz.write_tuple('todo', 'user', 'summer', 'owner',  'todo', 'item_summer');

    PERFORM authz.write_tuple('todo', 'todo', 'todo-1', 'parent', 'todo', 'item_jerry');
    PERFORM authz.write_tuple('todo', 'user', 'jerry',  'owner',  'todo', 'item_jerry');

    PERFORM authz.write_tuple('todo', 'todo', 'todo-1', 'parent', 'todo', 'item_beth');
    PERFORM authz.write_tuple('todo', 'user', 'beth',   'owner',  'todo', 'item_beth');

    ------------------------------------------------------------------
    -- Profiles are world-readable: EVERY user (subject user:*) can read EVERY user
    -- (object user:*). This one tuple uses both a subject and an OBJECT wildcard —
    -- the latter enabled by allow_object_wildcard on the can_read_user rule (model.sql).
    -- OpenFGA has no object wildcards, so the interop lists each user separately.
    ------------------------------------------------------------------
    PERFORM authz.write_tuple('todo', 'user', '*', 'can_read_user', 'user', '*');
END $$;
