-- 0016_condition_time_source.sql
--
-- A condition declares which clock `current_time` comes from.
--
--   server (default)  the engine sets `current_time` to its own clock before
--                     evaluating this condition, ignoring any caller value
--                     (statement time on live paths; `p_at` on time-travel
--                     paths, as for every condition). Business hours, grant
--                     windows, anything a caller could be tempted to backdate —
--                     safe without the author knowing the option exists.
--   caller            the request context supplies `current_time` — the
--                     enforcement point asserts a time; replayable, testable,
--                     the explicit choice when the caller legitimately asks
--                     about another moment (tests, demos, "as of T" live).
--
-- Conditions that exist when this migration runs are stamped `caller`: they
-- were written against the caller's clock and must not change behaviour on
-- upgrade. describe_model renders the clock so they can be reviewed.
--
-- The choice is part of the policy: versioned in conditions_audit (time
-- travel evaluates the clock choice in effect as of p_at), exported and
-- propagated by the model registry, rendered by describe_model and in the
-- explain trace. Structure only; behaviour lives in db/engine.

ALTER TABLE authz.conditions
    ADD COLUMN time_source text NOT NULL DEFAULT 'caller'   -- existing rows: caller (see above)
        CHECK (time_source IN ('caller', 'server'));
-- New conditions default to the server's clock.
ALTER TABLE authz.conditions ALTER COLUMN time_source SET DEFAULT 'server';

COMMENT ON COLUMN authz.conditions.time_source IS
    'Where `current_time` in the request context comes from when this condition '
    'is evaluated: caller (supplied with the check) or server (set by the engine '
    'from its own clock, or p_at on time-travel paths; a caller value is ignored).';

ALTER TABLE authz.conditions_audit
    ADD COLUMN time_source text NOT NULL DEFAULT 'server';
