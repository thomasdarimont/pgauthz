-- ============================================================================
-- AuthZEN certification fixture — tuples
-- ============================================================================
--
-- Prerequisites: run model.sql first.
--
-- alice writes record-1 (so she reads, writes and deletes it); bob only reads
-- it. alice merely reads record-2, the archived record, so she cannot write it
-- (fixture rule 5) and resource search for her readable records returns both
-- records (the suite allows results beyond the ones it requires).
--
-- write_tuple args: (store, SUBJECT_type, SUBJECT_id, relation, OBJECT_type, OBJECT_id).
-- ============================================================================

SELECT authz.write_tuple('authzen_cert', 'user', 'alice', 'writer', 'record', 'record-1');
SELECT authz.write_tuple('authzen_cert', 'user', 'bob',   'reader', 'record', 'record-1');
SELECT authz.write_tuple('authzen_cert', 'user', 'alice', 'reader', 'record', 'record-2');

-- Entity attributes as data (Properties level): bob is an admin on every record
-- (object wildcard), record-2 is archived (a flag tuple that holds for everyone).
SELECT authz.write_tuple('authzen_cert', 'user', 'bob', 'admin',    'record', '*');
SELECT authz.write_tuple('authzen_cert', 'user', '*',   'archived', 'record', 'record-2');

-- The request-property rule as ONE tuple: anyone may soft-delete any record they
-- may otherwise delete — the condition reads action.properties.soft at check time.
SELECT authz.write_tuple('authzen_cert', 'user', '*', 'soft_delete', 'record', '*',
    p_condition => 'soft_requested');
