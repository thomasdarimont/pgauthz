-- Test login users for direct psql and integration testing.
-- Each inherits an application role and can be used to verify
-- that privilege boundaries work as expected.
--
-- Usage:
--   psql "postgresql://app_readonly:app_readonly@localhost:55433/authz"
--   psql "postgresql://app_readwrite:app_readwrite@localhost:55433/authz"
--   psql "postgresql://app_auditor:app_auditor@localhost:55433/authz"

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_readonly') THEN
        CREATE ROLE app_readonly LOGIN PASSWORD 'app_readonly';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_readwrite') THEN
        CREATE ROLE app_readwrite LOGIN PASSWORD 'app_readwrite';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_auditor') THEN
        CREATE ROLE app_auditor LOGIN PASSWORD 'app_auditor';
    END IF;
END
$$;

GRANT authz_reader TO app_readonly;
GRANT authz_writer TO app_readwrite;
GRANT authz_auditor TO app_auditor;

-- Allow the connection role (authz) to SET ROLE to the test users.
GRANT app_readonly TO authz;
GRANT app_readwrite TO authz;
GRANT app_auditor TO authz;
