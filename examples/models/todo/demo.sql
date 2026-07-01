-- ============================================================================
-- Todo model — showcase queries
-- ============================================================================
-- Run after loading model.sql + seed.sql. Each block prints the explain_access
-- `summary` so you can see *why* access was (or wasn't) granted.

\echo
\echo '== Roles roll up: an editor can create todos on the list =='
-- can_create_todo = can_manage_todo_items = editor or admin or evil_genius
SELECT authz.explain_access('todo','user','morty','can_create_todo','todo','todo-1') ->> 'summary';

\echo
\echo '== A viewer can read the list but cannot create =='
SELECT authz.check_access('todo','user','jerry','can_read_todos','todo','todo-1')  AS jerry_can_read,
       authz.check_access('todo','user','jerry','can_create_todo','todo','todo-1') AS jerry_can_create;

\echo
\echo '== INTERSECTION: deleting an item needs manage-on-parent AND ownership =='
-- Morty is an editor (manages the parent list) AND owns item_morty → can delete.
SELECT authz.explain_access('todo','user','morty','can_delete_todo','todo','item_morty') ->> 'summary';

\echo
\echo '== ... so ownership alone is NOT enough: Jerry (viewer) OWNS item_jerry but cannot delete it =='
-- viewer is not can_manage_todo_items, so the (manage-on-parent AND owner) branch fails,
-- and Jerry is neither admin nor evil_genius on the parent.
SELECT authz.check_access('todo','user','jerry','owner','todo','item_jerry')           AS jerry_owns_it,
       authz.check_access('todo','user','jerry','can_delete_todo','todo','item_jerry')  AS jerry_can_delete;
SELECT authz.explain_access('todo','user','jerry','can_delete_todo','todo','item_jerry') ->> 'summary';

\echo
\echo '== admin bypass: Rick can delete an item he does NOT own (admin from parent) =='
SELECT authz.explain_access('todo','user','rick','can_delete_todo','todo','item_morty') ->> 'summary';

\echo
\echo '== evil_genius asymmetry: Peter can UPDATE any item but cannot DELETE it =='
-- can_update_todo has an `evil_genius from parent` branch; can_delete_todo has `admin from parent`.
SELECT authz.check_access('todo','user','peter','can_update_todo','todo','item_beth') AS peter_can_update,
       authz.check_access('todo','user','peter','can_delete_todo','todo','item_beth') AS peter_can_delete;

\echo
\echo '== Object wildcard: EVERY profile is world-readable via one (user:* → user:*) tuple =='
-- pgauthz-only: OpenFGA has no object wildcards, so the interop lists each user.
SELECT authz.explain_access('todo','user','anyone_at_all','can_read_user','user','rick') ->> 'summary';

\echo
\echo '== Search: which todos can Summer delete? (list_objects) =='
SELECT authz.list_objects('todo','user','summer','can_delete_todo','todo');
