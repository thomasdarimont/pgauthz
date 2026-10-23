-- 0023_issuer_bindings.sql
--
-- Issuer BINDINGS managed in the database (console gaps item 5; design in
-- scratch/notes/issuer-management.md, option C). An identity provider is
-- TRUSTED only by pgauthzd's environment (JWT_ISSUERS: issuer, audience,
-- signing keys — the anchors); what its tokens may do here — the stores they
-- reach, the DB roles they may claim, which clients may assert subjects
-- (ADR 0014), whether its tokens are accepted at all — is a binding, an
-- authorization decision that changes with every application onboarded, and
-- lives here so the console can manage it for the whole fleet, audited,
-- applied without a restart. pgauthzd (ISSUERS_SOURCE=env+db) merges a row
-- over the environment's entry of the SAME issuer; a row for an issuer the
-- environment does not trust is ignored — the database can never add trust.
CREATE TABLE authz.issuer_bindings (
    issuer          text PRIMARY KEY CHECK (issuer <> ''),      -- the token's `iss`, as in JWT_ISSUERS
    stores          text[] NOT NULL DEFAULT '{}',               -- anchored patterns; '{}' = as the environment binds (or unbound)
    db_roles        text[] NOT NULL DEFAULT '{}',               -- anchored patterns of claimable per-app DB roles
    client_db_roles jsonb  NOT NULL DEFAULT '{}'::jsonb          -- {"azp": "db_role"}
                    CHECK (jsonb_typeof(client_db_roles) = 'object'),
    pep_clients     jsonb  NOT NULL DEFAULT '{}'::jsonb          -- {"azp": ["store pattern", ...]} (ADR 0014)
                    CHECK (jsonb_typeof(pep_clients) = 'object'),
    enabled         boolean NOT NULL DEFAULT true,              -- false: every token of the issuer is refused (trust stays configured)
    description     text,
    created_at      timestamptz NOT NULL DEFAULT now(),         -- when the row first appeared (kept by replace)
    created_by      text NOT NULL DEFAULT current_user,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text NOT NULL DEFAULT current_user
);

-- Every change, as the row was before it (DELETE) or after it (INSERT /
-- UPDATE): who changed trust bindings, and when. Written by the trigger in
-- db/engine/issuers_admin.sql, so direct table edits are recorded too.
CREATE TABLE authz.issuer_bindings_audit (
    seq             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action          text NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
    performed_at    timestamptz NOT NULL DEFAULT now(),
    performed_by    text NOT NULL,
    issuer          text NOT NULL,
    stores          text[],
    db_roles        text[],
    client_db_roles jsonb,
    pep_clients     jsonb,
    enabled         boolean,
    description     text
);
CREATE INDEX issuer_bindings_audit_issuer_seq ON authz.issuer_bindings_audit (issuer, seq DESC);

-- One row: the revision pgauthzd instances poll (and are notified about on
-- the channel authz_issuer_bindings) to learn that the set changed.
CREATE TABLE authz.issuer_bindings_revision (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision   bigint NOT NULL DEFAULT 0,
    changed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO authz.issuer_bindings_revision DEFAULT VALUES;
