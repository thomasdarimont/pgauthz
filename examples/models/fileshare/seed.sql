-- ============================================================================
-- Advanced File Sharing — Seed Data
-- ============================================================================
--
-- The gdrive scenario (root/ → projects/ {design_spec, budget}, public/
-- {announcement}; alice owns root, frank owns design_spec, bob views it,
-- charlie reads through group engineering, everyone views public/) plus:
--
--   dana  — editor of design_spec (writes, cannot share)
--   temp  — viewer of budget for seven days (an expiring share)
--
DO $$
BEGIN
    PERFORM authz.write_tuple('fileshare', 'user', 'alice', 'owner', 'folder', 'root');
    PERFORM authz.write_tuple('fileshare', 'folder', 'root', 'parent', 'folder', 'projects');
    PERFORM authz.write_tuple('fileshare', 'folder', 'root', 'parent', 'folder', 'public');
    PERFORM authz.write_tuple('fileshare', 'folder', 'projects', 'parent', 'doc', 'design_spec');
    PERFORM authz.write_tuple('fileshare', 'folder', 'projects', 'parent', 'doc', 'budget');
    PERFORM authz.write_tuple('fileshare', 'folder', 'public', 'parent', 'doc', 'announcement');

    PERFORM authz.write_tuple('fileshare', 'user', 'frank', 'owner', 'doc', 'design_spec');
    PERFORM authz.write_tuple('fileshare', 'user', 'bob', 'viewer', 'doc', 'design_spec');
    PERFORM authz.write_tuple('fileshare', 'user', 'dana', 'editor', 'doc', 'design_spec');

    PERFORM authz.write_tuple('fileshare', 'group', 'engineering', 'viewer', 'folder', 'root', 'member');
    PERFORM authz.write_tuple('fileshare', 'user', 'charlie', 'member', 'group', 'engineering');

    PERFORM authz.write_tuple('fileshare', 'user', '*', 'viewer', 'folder', 'public');

    -- an expiring share: temp reviews the budget for a week
    PERFORM authz.write_tuple('fileshare', 'user', 'temp', 'viewer', 'doc', 'budget',
                              p_expires_at => now() + interval '7 days');
END;
$$;
