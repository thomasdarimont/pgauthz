-- 0027_grant_rule_record_as.sql
--
-- Sharing as an action: a grant rule may name a relation (an action of the
-- store's vocabulary) under which authz.grant / revoke / apply_grants record
-- an event for the ACTOR in the action log (ADR 0012) whenever they change a
-- tuple. Temporal gates on the rule's required relation then rate-limit or
-- four-eye sharing with no PEP code. NULL (the default): nothing is recorded.
ALTER TABLE authz.grant_rules ADD COLUMN record_as integer;
ALTER TABLE authz.grant_rules ADD CONSTRAINT grant_rules_record_as_store_id_fkey
    FOREIGN KEY (record_as, store_id) REFERENCES authz.relations (id, store_id);
ALTER TABLE authz.grant_rules_audit ADD COLUMN record_as integer;
