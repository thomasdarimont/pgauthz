-- Runs once on first database initialization (docker-entrypoint-initdb.d).
--
-- Creates the PostgREST authenticator role before PostgREST first connects —
-- PostgREST exits at startup if its login role does not exist, and init.sh
-- (which loads db/security/roles.sql) only runs after the stack is up.
-- roles.sql grants the SET ROLE targets (api_anon, authz_* roles) during init.
--
-- Dev password — override in production deployments.
CREATE ROLE authz_authenticator LOGIN NOINHERIT PASSWORD 'authz';
