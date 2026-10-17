-- 0022_trim_condition_expressions.sql
--
-- Condition expressions are stored trimmed from now on (create_condition);
-- trim the ones written before. Audit rows are written by the trigger as
-- for any change, and a registry version whose model carries such a
-- condition will show as drifted once, since its checksum covers the text.
UPDATE authz.conditions SET expression = btrim(expression, E' \t\r\n')
 WHERE expression <> btrim(expression, E' \t\r\n');
