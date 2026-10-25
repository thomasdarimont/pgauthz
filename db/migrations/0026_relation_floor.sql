-- 0026_relation_floor.sql
--
-- min_direct on relation constraints: an object keeps at least this many
-- active direct assignments of the relation once it has any. Enforced on the
-- revocation paths an application or end user uses for individual access
-- changes (delete_tuple, delete_tuples, revoke, apply_grants, checked-write
-- deletes): the delete that would leave fewer is refused with SQLSTATE
-- 'ZA002'. Teardown and administrative paths (delete_user_tuples,
-- erase_subject, model_remove_type, delete_store) and expiry are exempt —
-- "a document keeps at least one owner" is a rule for revoking, not for
-- offboarding a person or deleting the document.
ALTER TABLE authz.relation_constraints
    ADD COLUMN min_direct integer CHECK (min_direct > 0);
ALTER TABLE authz.relation_constraints DROP CONSTRAINT relation_constraints_check;
ALTER TABLE authz.relation_constraints ADD CONSTRAINT relation_constraints_check
    CHECK (max_direct IS NOT NULL OR max_effective IS NOT NULL OR min_direct IS NOT NULL);
ALTER TABLE authz.relation_constraints ADD CONSTRAINT relation_constraints_min_max_check
    CHECK (min_direct IS NULL OR max_direct IS NULL OR min_direct <= max_direct);
ALTER TABLE authz.relation_constraints_audit ADD COLUMN min_direct integer;
