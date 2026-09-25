-- 0012_events_subject_list_index.sql
--
-- A listing index for the action log (ADR 0012): authz.list_events pages a
-- subject's events in (occurred_at, seq) order. The window index from 0010
-- (store, subject_type, subject_id, action, occurred_at DESC) serves the gate
-- primitives, which always know the action; a by-subject listing does not,
-- so the planner fell back to walking the time-ordered primary key until it
-- had found a page's worth of that subject's rows — the whole log when the
-- subject's events sit at the end of the time order (a recently active
-- subject: measured 23 ms and 191k buffers for a 100-row page on a 220k-row
-- log, 0.25 ms with this index). One more btree per insert (~+6% on
-- record_event); reads of both kinds stay index-driven.
CREATE INDEX idx_events_subject_list
    ON authz.events (store_id, subject_type, subject_id, occurred_at, seq);
