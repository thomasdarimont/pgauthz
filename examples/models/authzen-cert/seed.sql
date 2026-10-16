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
