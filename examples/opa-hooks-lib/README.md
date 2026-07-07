# Operator extension libraries for policy hooks

Shared helper **functions** your hooks may import — the reserved
`authz.hooks.lib.v1.ext.<name>` subtree of the platform hook library
([ADR 0011](../../docs/adr/0011-opa-policy-hooks.md)). Use one when the same
logic (time windows, org role conventions, id classification) would otherwise
be copy-pasted into several hooks.

```rego
# your library (this directory's acme.rego is the runnable reference)
package authz.hooks.lib.v1.ext.acme

within_utc_hours(evaluated_at_ns, from_h, to_h) if { ... }
is_operator(actor) if keycloak.has_realm_role(actor, "ops")  # platform modules compose
```

```rego
# any of your hooks
import data.authz.hooks.lib.v1.ext.acme

deny contains {"code": "quiet_hours"} if {
    not acme.within_utc_hours(input.evaluated_at, 6, 22)
}
```

## The contract (validator-enforced)

Validate every library directory before mounting — same rule as hooks:

```bash
scripts/validate-hooks.sh --lib ./my-libs
```

- **Namespace**: every package must be `authz.hooks.lib.v1.ext.<name>` —
  the un-suffixed `authz.hooks.lib.v1.<module>` modules (`keycloak`, …) are
  platform-owned and ship with the platform policy.
- **Functions only**: a plain rule in a shared library would be shared
  ambient state evaluated in every caller's context; the validator rejects it.
- **Always pure — no `http.send`, ever**: there is deliberately no
  `--allow-http` for libraries. A shared lib with network access would hand
  it to every caller, including store hooks, which are network-free by
  contract.
- Libraries may import and compose the platform modules
  (`data.authz.hooks.lib.v1.keycloak`).

When validating **hooks** that call your libraries, tell the validator where
they live — a call into an absent or misspelled function is then a
validation error instead of a runtime surprise:

```bash
HOOK_EXTRA_LIBS=./my-libs scripts/validate-hooks.sh --global ./hooks/global
```

## Deploying

- **compose** — two options:
  1. *Own directory + overlay* (recommended — keeps your code out of the
     pgauthz checkout): validate, then mount onto the shipped mountpoint
     (`opa/policies/hooks-lib/` exists in-tree exactly so this nested
     read-only bind works):

     ```yaml
     # my-overlay.yml
     services:
       opa:
         volumes:
           - ./my-libs:/policies/hooks-lib:ro
     ```

     Append it to your compose file list
     (`docker compose -f compose.yml -f compose-opa.yml -f my-overlay.yml up -d`);
     with the default file discovery (no `-f` flags), naming it
     `compose.override.yml` merges automatically. There's a commented
     template on the `opa` service in `compose-opa.yml`.
  2. *Drop-in*: copy `.rego` files into `opa/policies/hooks-lib/` — the
     whole `./opa/policies` tree is already mounted, and OPA (running with
     `--watch` in the dev stack) hot-reloads them.
- **Helm**: `opa.extraLibsConfigMap` — mounted at `/policies/hooks-lib` and
  included in the deploy-time `opa check` initContainers.
- **Signed bundles** (delegated-tenant deployments): libraries are
  operator-trust code — build and sign them together with your global hooks.

## Trust model, in one line

Shared code executes inside every consumer's evaluation, so extension
libraries are **operator-trust tier by construction** — tenants cannot mount
them (store ConfigMaps are pinned to the store's own namespace); review a
library like you review platform policy.

## Testing

`acme_test.rego` shows the pattern: test the functions directly with
constructed actors (the test package must live OUTSIDE `authz.hooks.*`).
Run with the platform policies loaded:

```bash
opa test opa/policies examples/opa-hooks-lib -v
```
