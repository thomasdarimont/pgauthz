-- Runs once on first database initialization (docker-entrypoint-initdb.d).
--
-- Creates the service LOGIN roles before the services first connect — they
-- exit at startup if their login role is missing, and init.sh (which loads
-- db/security/roles.sql) only runs after the stack is up. roles.sql grants
-- these roles their privileges during init:
--   authz_authenticator — PostgREST connects, then SET ROLE per request
--                         (NOINHERIT; SET ROLE targets granted in roles.sql)
--   authzen_direct      — the AuthZEN Go service connects and calls the
--                         read API directly (INHERIT; granted authz_reader
--                         in roles.sql). Read-only, non-superuser.
--
-- Dev passwords — override in production deployments.
CREATE ROLE authz_authenticator LOGIN NOINHERIT PASSWORD 'authz';
CREATE ROLE authzen_direct       LOGIN          PASSWORD 'authz';
