-- ============================================================================
-- Google Drive Permission Model — Seed Data
-- ============================================================================
--
-- Scenario:
--
--   Folder hierarchy:
--     root/
--       projects/
--         design_spec (doc)
--         budget (doc)
--       public/ (publicly viewable via wildcard)
--         announcement (doc)
--
--   Users:
--     alice   — owner of root folder
--     bob     — explicit viewer of design_spec
--     frank   — owner of design_spec
--     charlie — member of engineering group
--
--   Group:
--     engineering — has viewer access on root folder (via userset)
--
--   Wildcard:
--     user:* — viewer of public/ folder (everyone can view)
--
-- Expected permissions:
--   alice   → can read/write/share design_spec (owner of root, inherited)
--   alice   → cannot change_owner on design_spec (that requires doc ownership)
--   frank   → can change_owner on design_spec (doc owner)
--   bob     → can read design_spec (direct viewer), cannot write
--   charlie → can read design_spec (eng group → viewer on root → inherited)
--   anyone  → can read announcement (wildcard viewer on public/)

DO $$
BEGIN
    -- Folder hierarchy
    PERFORM authz.write_tuple('gdrive', 'user', 'alice', 'owner', 'folder', 'root');
    PERFORM authz.write_tuple('gdrive', 'folder', 'root', 'parent', 'folder', 'projects');
    PERFORM authz.write_tuple('gdrive', 'folder', 'root', 'parent', 'folder', 'public');

    -- Documents in projects/
    PERFORM authz.write_tuple('gdrive', 'folder', 'projects', 'parent', 'doc', 'design_spec');
    PERFORM authz.write_tuple('gdrive', 'folder', 'projects', 'parent', 'doc', 'budget');

    -- Document in public/
    PERFORM authz.write_tuple('gdrive', 'folder', 'public', 'parent', 'doc', 'announcement');

    -- Bob is an explicit viewer of the design spec
    PERFORM authz.write_tuple('gdrive', 'user', 'bob', 'viewer', 'doc', 'design_spec');

    -- Frank is the owner of the design spec
    PERFORM authz.write_tuple('gdrive', 'user', 'frank', 'owner', 'doc', 'design_spec');

    -- Engineering group gets viewer access on the root folder (userset)
    PERFORM authz.write_tuple('gdrive',
        'group', 'engineering', 'viewer', 'folder', 'root',
        'member'  -- userset: all group members
    );

    -- Charlie is a member of the engineering group
    PERFORM authz.write_tuple('gdrive', 'user', 'charlie', 'member', 'group', 'engineering');

    -- Public folder is viewable by everyone (wildcard)
    PERFORM authz.write_tuple('gdrive', 'user', '*', 'viewer', 'folder', 'public');
END;
$$;
