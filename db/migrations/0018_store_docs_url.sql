-- Store documentation link (management console): where the people who own a
-- store keep its longer description — a wiki page, a design doc, a ticket.
-- Shown next to the store's description; set with authz.update_store.
ALTER TABLE authz.stores ADD COLUMN IF NOT EXISTS docs_url text;
ALTER TABLE authz.stores DROP CONSTRAINT IF EXISTS stores_docs_url_check;
ALTER TABLE authz.stores ADD CONSTRAINT stores_docs_url_check
    CHECK (docs_url IS NULL OR (docs_url ~ '^https?://' AND length(docs_url) <= 2048));
