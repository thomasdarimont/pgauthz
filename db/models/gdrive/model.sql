-- ============================================================================
-- Google Drive Permission Model
-- ============================================================================
--
-- A Google Drive-like permission system with folders, documents, groups,
-- and inherited access. Implements the model from MODEL_DESIGN.md.
--
-- Features demonstrated:
--   - Direct relations (owner, parent, viewer, member)
--   - Computed relations (can_read includes owner and viewer)
--   - TTU / folder inheritance (viewer from parent, can_write from parent)
--   - Usersets / group membership (group#member as viewer)
--   - Wildcard tuples (user:* as viewer for public access)
--   - Recursive folder hierarchy (folder.viewer from parent)
--
-- OpenFGA DSL equivalent:
--
--   type user
--
--   type group
--     relations
--       define member: [user]
--
--   type folder
--     relations
--       define owner:  [user]
--       define parent: [folder]
--       define viewer: [user, user:*, group#member] or owner or viewer from parent
--       define can_create_file: owner
--       define can_write: owner or can_write from parent
--       define can_share: owner or can_share from parent
--
--   type doc
--     relations
--       define owner:  [user]
--       define parent: [folder]
--       define viewer: [user, user:*, group#member]
--       define can_change_owner: owner
--       define can_read:  viewer or owner or viewer from parent
--       define can_share: owner or can_share from parent
--       define can_write: owner or can_write from parent

-- Create the store
SELECT authz.create_store('gdrive', 'Google Drive permission model');

DO $$
DECLARE
    s smallint := authz._s('gdrive');

    -- Type shortcuts
    t_group   smallint;
    t_folder  smallint;
    t_doc     smallint;

    -- Relation shortcuts
    r_member           smallint;
    r_owner            smallint;
    r_parent           smallint;
    r_viewer           smallint;
    r_can_create_file  smallint;
    r_can_change_owner smallint;
    r_can_read         smallint;
    r_can_share        smallint;
    r_can_write        smallint;
BEGIN
    -- Types
    INSERT INTO authz.types (store_id, name) VALUES
        (s, 'user'),
        (s, 'group'),
        (s, 'folder'),
        (s, 'doc');

    -- Partitions
    PERFORM authz._ensure_tuple_partition(s, 'group');
    PERFORM authz._ensure_tuple_partition(s, 'folder');
    PERFORM authz._ensure_tuple_partition(s, 'doc', 8);

    -- Relations
    INSERT INTO authz.relations (store_id, name) VALUES
        (s, 'member'),
        (s, 'owner'),
        (s, 'parent'),
        (s, 'viewer'),
        (s, 'can_create_file'),
        (s, 'can_change_owner'),
        (s, 'can_read'),
        (s, 'can_share'),
        (s, 'can_write');

    -- Resolve IDs
    t_group   := authz._t(s, 'group');
    t_folder  := authz._t(s, 'folder');
    t_doc     := authz._t(s, 'doc');

    r_member           := authz._r(s, 'member');
    r_owner            := authz._r(s, 'owner');
    r_parent           := authz._r(s, 'parent');
    r_viewer           := authz._r(s, 'viewer');
    r_can_create_file  := authz._r(s, 'can_create_file');
    r_can_change_owner := authz._r(s, 'can_change_owner');
    r_can_read         := authz._r(s, 'can_read');
    r_can_share        := authz._r(s, 'can_share');
    r_can_write        := authz._r(s, 'can_write');

    -- ── Type Restrictions ────────────────────────────────────────
    -- Constrain which subject types can be directly assigned to
    -- each relation. Registered before model rules so that tuple
    -- enforcement is active from the start.

    -- group.member: [user]
    PERFORM authz.model_add_type_restriction('gdrive', 'group', 'member', 'user');

    -- folder.owner: [user]
    PERFORM authz.model_add_type_restriction('gdrive', 'folder', 'owner', 'user');
    -- folder.parent: [folder]
    PERFORM authz.model_add_type_restriction('gdrive', 'folder', 'parent', 'folder');
    -- folder.viewer: [user, user:*, group#member]
    PERFORM authz.model_add_type_restriction('gdrive', 'folder', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('gdrive', 'folder', 'viewer', 'user',
        p_allow_wildcard => true);
    PERFORM authz.model_add_type_restriction('gdrive', 'folder', 'viewer', 'group',
        p_allowed_user_relation => 'member');

    -- doc.owner: [user]
    PERFORM authz.model_add_type_restriction('gdrive', 'doc', 'owner', 'user');
    -- doc.parent: [folder]
    PERFORM authz.model_add_type_restriction('gdrive', 'doc', 'parent', 'folder');
    -- doc.viewer: [user, user:*, group#member]
    PERFORM authz.model_add_type_restriction('gdrive', 'doc', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('gdrive', 'doc', 'viewer', 'user',
        p_allow_wildcard => true);
    PERFORM authz.model_add_type_restriction('gdrive', 'doc', 'viewer', 'group',
        p_allowed_user_relation => 'member');

    -- Model rules
    INSERT INTO authz.models
        (store_id, object_type, relation, rule_type,
         computed_relation, tupleset_relation, tupleset_computed)
    VALUES

    -- ── type group ─────────────────────────────────────────────
    -- define member: [user]
    (s, t_group, r_member, authz._rel_direct(), NULL, NULL, NULL),

    -- ── type folder ────────────────────────────────────────────
    -- define owner: [user]
    (s, t_folder, r_owner,  authz._rel_direct(), NULL, NULL, NULL),
    -- define parent: [folder]
    (s, t_folder, r_parent, authz._rel_direct(), NULL, NULL, NULL),

    -- define viewer: [user, user:*, group#member] or owner or viewer from parent
    (s, t_folder, r_viewer, authz._rel_direct(),   NULL, NULL, NULL),
    (s, t_folder, r_viewer, authz._rel_computed(), r_owner, NULL, NULL),
    (s, t_folder, r_viewer, authz._rel_ttu(),      NULL, r_parent, r_viewer),

    -- define can_create_file: owner
    (s, t_folder, r_can_create_file, authz._rel_computed(), r_owner, NULL, NULL),

    -- define can_write: owner or can_write from parent
    (s, t_folder, r_can_write, authz._rel_computed(), r_owner, NULL, NULL),
    (s, t_folder, r_can_write, authz._rel_ttu(),      NULL, r_parent, r_can_write),

    -- define can_share: owner or can_share from parent
    (s, t_folder, r_can_share, authz._rel_computed(), r_owner, NULL, NULL),
    (s, t_folder, r_can_share, authz._rel_ttu(),      NULL, r_parent, r_can_share),

    -- ── type doc ───────────────────────────────────────────────
    -- define owner: [user]
    (s, t_doc, r_owner,  authz._rel_direct(), NULL, NULL, NULL),
    -- define parent: [folder]
    (s, t_doc, r_parent, authz._rel_direct(), NULL, NULL, NULL),
    -- define viewer: [user, user:*, group#member]
    (s, t_doc, r_viewer, authz._rel_direct(), NULL, NULL, NULL),

    -- define can_change_owner: owner
    (s, t_doc, r_can_change_owner, authz._rel_computed(), r_owner, NULL, NULL),

    -- define can_read: viewer or owner or viewer from parent
    (s, t_doc, r_can_read, authz._rel_computed(), r_viewer, NULL, NULL),
    (s, t_doc, r_can_read, authz._rel_computed(), r_owner,  NULL, NULL),
    (s, t_doc, r_can_read, authz._rel_ttu(),      NULL, r_parent, r_viewer),

    -- define can_share: owner or can_share from parent
    (s, t_doc, r_can_share, authz._rel_computed(), r_owner, NULL, NULL),
    (s, t_doc, r_can_share, authz._rel_ttu(),      NULL, r_parent, r_can_share),

    -- define can_write: owner or can_write from parent
    (s, t_doc, r_can_write, authz._rel_computed(), r_owner, NULL, NULL),
    (s, t_doc, r_can_write, authz._rel_ttu(),      NULL, r_parent, r_can_write)
    ;
END;
$$;
