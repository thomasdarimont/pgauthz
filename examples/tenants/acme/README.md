# The ACME tenant

A tenant of the platform as [ADR 0017](../../../docs/adr/0017-store-groups.md)
describes one: the store group **`acme`** with three stores — `acme_fileshare`
(the [fileshare](../../models/fileshare) model), `acme_todo`
([todo](../../models/todo)) and `acme_tax` (the [demo](../../models/demo)
model) — its **own identity provider**, the Keycloak realm `acme`
(issuer `https://id.pgauthz.test/realms/acme`, provisioned by
[`keycloak/terraform/realm.acme.tf`](../../../keycloak/terraform/realm.acme.tf))
trusted as a *group issuer* with the alias `acme`, and four people whose
realm role is what the group grants them in the console:

| User | Realm role | On `group:acme` | What that is |
|---|---|---|---|
| `acme-admin` | `acme_group_admin` | `admin` | the store group's admin: every store, its admins, its identity provider |
| `acme-iam` | `acme_iam_lead` | `issuer_admin`, `publisher` | the IAM team lead: the identity provider (Platform → Issuers), the models and their rollout |
| `acme-auditor` | `acme_auditor` | `auditor` | activity and decisions of the group's stores, read-only |
| `acme-dev` | `acme_developer` | `viewer`, `tester` | the models, and tests of their own access |

Password for all: `password` (`demo_user_password`). The console signs them
in through the realm's `console-bff` client, registered as a sign-in
provider of the group (`Sign in with ACME`, or the deep link
`https://app.pgauthz.test/console/?login=acme`), and pgauthzd's admin API
takes their tokens under a delegated rule — the console store decides.

```bash
./start.sh --console                      # the demo stack with Keycloak and the console
./tests/test.sh                           # loads the example models the tenant's stores are built from
(cd keycloak/terraform && terraform apply) # the acme realm next to the pgauthz realm
./examples/tenants/acme/setup.sh           # group, stores, models, group issuer, console grants, sign-in
REALM=acme eval "$(./keycloak/get-token.sh acme-dev)"   # a token of the tenant's realm
```

`setup.sql` is the pgauthz side on its own (idempotent); `seed.sql` the test
data — the example models' seeds replayed into the tenant's stores (the
demo's engagement `eng_42` with its tax team and client org is the tax
story; the todo lists; the fileshare folders with an expiring share), plus
the tenant's people: `acme-dev` on the tax team and editing `todo-1`,
`acme-admin` the engagement's advisor and owner of the `projects` folder,
`acme-auditor` reading everything under `root`; `setup.sh` runs both and
adds the console's sign-in registration (the realm's client secret from
`terraform output`). The platform operator allow-lists the tenant's identity-provider
host for both services (`GROUP_ISSUER_HOSTS`, `CONSOLE_OUTBOUND_HOSTS`;
`env.sh` lists `id.pgauthz.test` for the demo).
