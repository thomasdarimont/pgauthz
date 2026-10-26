-- ACME: a tenant of the platform (ADR 0017) — the store group `acme` with
-- three stores carrying the example models (fileshare, todo, and the demo
-- model as `acme_tax`), its own identity provider (the Keycloak realm acme,
-- keycloak/terraform/realm.acme.tf) as a group issuer, and the console
-- access of its people: the realm roles become teams (team:role_<role>) the
-- group grants roles to. Idempotent; run by setup.sh as the engine owner.
-- Needs the example models' fixture stores (fileshare, todo, demo — loaded
-- by tests/test.sh) to publish from.

-- ── The group and its stores ────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM authz.list_store_groups() WHERE name = 'acme') THEN
        PERFORM authz.create_store_group('acme', 'ACME — a tenant: its stores, its identity provider, its admins');
    END IF;
END $$;

DO $$
DECLARE s record;
BEGIN
    FOR s IN SELECT * FROM (VALUES
        ('acme_fileshare', 'ACME file sharing (the fileshare model: Drive-like sharing with download quotas)'),
        ('acme_todo',      'ACME to-do lists (the todo model)'),
        ('acme_tax',       'ACME tax documents (the demo model: documents, folders, teams)')
    ) AS t(name, description)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM authz.list_stores() WHERE name = s.name AND retired_at IS NULL) THEN
            PERFORM authz.create_store(s.name, s.description);
        END IF;
        PERFORM authz.set_store_group(s.name, 'acme');
    END LOOP;
END $$;

-- ── The models: published from the example fixtures into the registry (an
-- unchanged definition is not a new version), applied to the tenant's stores
-- (the fixtures are ungrouped/default: their models are everyone's) ─────────
SELECT authz.publish_model('fileshare', 'fileshare', 'examples/models/fileshare');
SELECT authz.publish_model('todo',      'todo',      'examples/models/todo');
SELECT authz.publish_model('demo',      'demo',      'examples/models/demo');
SELECT authz.apply_model('acme_fileshare', 'fileshare');
SELECT authz.apply_model('acme_todo',      'todo');
SELECT authz.apply_model('acme_tax',       'demo');

-- ── The tenant's identity provider: a group issuer with its own trust anchor
-- (keys fetched from the realm; GROUP_ISSUER_HOSTS must list id.pgauthz.test),
-- the alias `acme`, and a delegated admin rule: a token of the realm is
-- user:<preferred_username> in the console store, which decides what the
-- person may manage over the admin API ──────────────────────────────────────
SELECT authz.set_issuer_binding(
    'https://id.pgauthz.test/realms/acme',
    p_store_group  => 'acme',
    p_jwks_url     => 'https://id.pgauthz.test/realms/acme/protocol/openid-connect/certs',
    p_audience     => 'authz-api',
    p_audiences    => ARRAY['https://api.pgauthz.test'],
    p_admin        => '[{"decide":{"store":"console"}}]',
    p_alias        => 'acme',
    p_description  => 'ACME tenant — Keycloak realm acme',
    p_performed_by => 'examples/tenants/acme');

-- ── Console access: the realm roles as teams, granted on the group (a role
-- on group:acme is that role on every store of the group, now and later) ────
--   acme_group_admin  admin         every store, the group's admins and its IdP
--   acme_iam_lead     issuer_admin  the identity provider (Platform → Issuers)
--                     publisher     the models: author, publish to the registry, roll out
--   acme_auditor      auditor       activity and decisions, read-only
--   acme_developer    viewer+tester the models, tests of their own access
SELECT authz.write_tuple('console', 'team', t.team, t.role, 'group', 'acme', p_user_relation => 'member', p_performed_by => 'examples/tenants/acme')
  FROM (VALUES
    ('role_acme_group_admin', 'admin'),
    ('role_acme_iam_lead',    'issuer_admin'),
    ('role_acme_iam_lead',    'publisher'),
    ('role_acme_auditor',     'auditor'),
    ('role_acme_developer',   'viewer'),
    ('role_acme_developer',   'tester')
  ) AS t(team, role);

SELECT name, store_group FROM authz.list_stores() WHERE name LIKE 'acme_%' ORDER BY 1;
