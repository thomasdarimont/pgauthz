# pgauthz playground

An OpenFGA-playground-style UI for pgauthz: pick a store, run access queries, and
**visualize the resolution path** (`explain_access`) — running the real
production path end to end.

![pgauthz playground frontend](playground-frontend.png)

```
  Browser ──(session cookie)──▶ BFF (Go) ──(user's token)──▶ OPA ──▶ PostgREST ──▶ engine
  Lit SPA                       auth-code + PKCE,            data.authz.{allow,
  (frontend/)                   sessions in pgauthz_playground  explain,...}
```

The BFF is a **backend-for-frontend**: the browser does OIDC authorization-code +
PKCE against Keycloak, the BFF holds the tokens **server-side** (sessions in a
separate `pgauthz_playground` DB) and exposes only an **http-only secure cookie**
to the SPA. Every query is forwarded to OPA with the session's access token, so
it runs **as the logged-in user** — exactly like a real PEP.

## Run

```bash
./keycloak/config/generate-mkcerts.sh           # once (TLS for *.pgauthz.test)
./start.sh --playground                          # implies --keycloak; builds the BFF
(cd keycloak/terraform && terraform apply)       # provisions the playground-bff client
# /etc/hosts: 127.0.0.1 app.pgauthz.test
open https://app.pgauthz.test
```

Sign in as any demo user (`alice` / `bob` / `carol` / `eva`, password `password`).

## What you can do

A two-pane, OpenFGA-style layout. The store is selected via **`?store=`** in the
URL (e.g. `https://app.pgauthz.test/?store=demo`):

- **Left** — the **model** (`describe_model` DSL) and the store's **tuples**.
- **Right** — query the graph:
  - **Structured english**: `is internal_user:alice related to document:doc_payroll_001 as can_read?`
  - or the explicit fields (subject / action / object), with autocomplete.
  - → **ALLOW/DENY** + a **Cytoscape access graph** of the resolution path
    (green = allowed step, red = denied), with the text tree as a detail.

Two modes (toggle, top-right):

- **Explore** (default) — **engine-direct**, read-only, **any subject** (the
  OpenFGA-playground style — `is user:erik related to …?`).
- **As me (OPA)** — query as the logged-in user **through OPA** (the real PEP
  path; subject comes from your token).

Inputs autocomplete from the engine (`/api/meta/{stores,relations,objects,subjects}`,
a read-only metadata connection).

## Structure

```
playground/
  backend/                   # Go backend-for-frontend
    cmd/playground/          #   main: wiring (config, db, discovery, routes)
    internal/config/         #   env-driven configuration
    internal/oidc/           #   OIDC discovery + token exchange
    internal/server/         #   HTTP layer: sessions, auth, query, meta, explore, static
    go.mod  Dockerfile
  frontend/                  # Lit SPA (no build step — Lit from a CDN)
    index.html  styles.css   # styles.css holds the design tokens
    src/
      api.js                 # thin BFF client
      components/            # custom Lit web components
        pg-app.js            #   root: panes, store, modes, query
        pg-model.js          #   model (describe_model) view
        pg-tuples.js         #   tuples list
        pg-access-graph.js   #   Cytoscape access graph (cytoscape from a CDN)
        pg-explain-tree.js   #   resolution-tree text view
  proxy.conf                 # app.pgauthz.test → BFF (added to the nginx proxy)
compose-playground.yml       # playground-db (sessions) + playground-bff
keycloak/terraform/client.playground.tf   # the confidential auth-code+PKCE client
```

## Developing

The SPA is **volume-mounted** and served statically with **no bundler** — edit
anything under `frontend/` and **reload the browser** (hard-reload if cached). Only Go
(`backend/`) changes need a rebuild: `docker compose … build playground-bff`.

Styling is structured with **design tokens** (`frontend/styles.css` `:root`): primitive
tokens (palette, spacing, radii, type) → semantic tokens (`--pg-allow-fg`, …).
Components — including the shadow-DOM `pg-explain-tree` — consume the semantic
tokens, and dark mode is a token override.

## Security notes (demo)

Demo-grade: dev client secret (`playground-bff-demo-secret`), the metadata
connection reuses the engine superuser (use a read-only role in production), and
the BFF session cookie is http-only + `Secure` (served via the TLS proxy). The
SPA never receives a token. Not for production as-is.
