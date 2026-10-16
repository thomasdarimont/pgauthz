# AuthZEN conformance tests

Runs pgauthzd against the [OpenID conformance suite](https://gitlab.com/openid/conformance-suite)'s
**AuthZEN 1.0 PDP test plans** ([Conformance Testing for OpenID AuthZEN](https://openid.net/certification/authzen_testing/)).
The suite plays the PEP: it sends the requests of the certification profile
([openid/authzen #433](https://github.com/openid/authzen/issues/433)) to the PDP's endpoints and
checks decisions, search results and error handling. pgauthzd answers from the `authzen_cert`
store — the fixture in [`examples/models/authzen-cert/`](../examples/models/authzen-cert) — selected
by the tenant path `/stores/authzen_cert`. A Go module of its own (`thomasdarimont.de/authz/conformance`),
so the Docker client it needs stays out of pgauthzd; the suite bootstrap is the one of
[easyssf-go](https://github.com/easyssf/easyssf-go)'s conformance module.

## Running

```sh
./start.sh && ./init.sh          # the demo stack: pgauthzd-decision on :8090, ALLOW_SUBJECT_OVERRIDE=true (env.sh)
./tests/test-conformance.sh      # loads the fixture, starts the suite in Docker, runs every plan
./tests/test-conformance.sh -run TestEvaluationPlan
```

The plan tests are skipped unless `PGAUTHZ_CONFORMANCE_TESTS=true` (the script sets it); a plan
takes a few minutes, and the suite images (about 1.5 GB) are pulled on first use. While the
tests run, the suite's UI at `https://localhost:18444` shows the plans and every module's log;
a failed module fails with the failures and warnings the suite logged and the link to that log.

| Test | Plan | Level |
|---|---|---|
| `TestEvaluationPlan` | `authzen-pdp-evaluation-test-plan` | Basic |
| `TestEvaluationsPlan` | `authzen-pdp-evaluations-test-plan` | Batch |
| `TestSubjectSearchPlan` | `authzen-pdp-subject-search-test-plan` | Search |
| `TestResourceSearchPlan` | `authzen-pdp-resource-search-test-plan` | Search |
| `TestActionSearchPlan` | `authzen-pdp-action-search-test-plan` | Search |
| `TestEvaluationsComprehensivePlan` | `authzen-pdp-evaluations-comprehensive-test-plan` | short-circuit semantics (not certification) |

All plans run with the variant `pdp_auth_type=api_key`, `pdp_server_metadata=static`,
`authzen_support=core`; the configuration is [`suite-config/authzen-core.json`](suite-config/authzen-core.json)
with the PDP identifier, the endpoints and the key filled in at run time.

## How the pieces fit

- **The suite** (`suite.go`, `api.go`) is started with [testcontainers-go](https://golang.testcontainers.org):
  MongoDB, the suite and its nginx, pinned by digest in `settings.go`. The suite has to know its
  own URL before it starts, so nginx is bound to a fixed host port. The suite reaches the PDP
  on the Docker host as `host.testcontainers.internal`.
- **The https front** (`proxy.go`): the suite insists on `https` for the PDP identifier and
  every endpoint but does not verify the certificate; pgauthzd's public listener speaks plain
  http. The tests terminate TLS with a certificate made up at start and forward to pgauthzd.
- **The credential** (`token.go`): `pdp_auth_type=none` is impossible, pgauthzd always wants a
  bearer token, so the suite sends an `api_key` — an ES256 JWT minted from the demo key
  (`opa/keys/demo.key.txt`) with the issuer and audience the demo stack trusts. **It names no
  subject.** With `ALLOW_SUBJECT_OVERRIDE=true` the request body's subject wins and a missing
  body subject falls back to the token's; the suite expects a request without a subject to be
  rejected (single evaluation: 400) or answered `decision: false` (batch item), which only a
  subject-less credential gives.
- **The plans** (`plan.go`, `plantest.go`): `RunPlan` creates the plan in the suite and runs
  every module as a subtest; a module passes with `PASSED`, or with `WARNING` unless
  `CTS_STRICT=true` (certification tolerates warnings — they are the spec's SHOULDs — but a new
  one is worth a look, so they are logged).

| Environment variable | Default | |
|---|---|---|
| `CTS_PGAUTHZD_URL` | `http://localhost:8090` | the pgauthzd under test (`decision-only` is enough; `ALLOW_SUBJECT_OVERRIDE=true`) |
| `CTS_STORE` | `authzen_cert` | the store the PDP identifier selects |
| `CTS_PDP_PORT` | `9445` | host port of the https front |
| `CTS_SUITE_PORT` | `18444` | host port of the suite (its UI) |
| `CTS_SIGNING_KEY`, `CTS_KEY_ID`, `CTS_ISSUER`, `CTS_AUDIENCE` | the demo key, `my-kid`, `https://auth.example.com`, `authz-api` | how the api_key is minted |
| `CTS_SUITE_IMAGE`, `CTS_SUITE_NGINX_IMAGE`, `CTS_SUITE_MONGODB_IMAGE` | `release-v5.3.2` by digest, `mongo:9.0.2-noble` by digest | the images (`settings.go` is the single place to change them) |
| `CTS_STRICT` | unset | `true` fails a module the suite finished with WARNING |

## Known suite issues

`known_issues.go` lists defects of the suite itself; a module that fails exactly that way is
skipped with the reason, and reported if it passes, so the entry is removed once the suite is
fixed. As of release-v5.3.2:

- `authzen-pdp-evaluation-invalid-credentials-returns-401` is INTERRUPTED before it calls the
  PDP: `CorruptAuthzenClientCredentials` requires a `client` environment object, but nothing in
  the AuthZEN flow creates one (no condition copies `config.client` into the environment, for
  `api_key` or any other variant). pgauthzd's 401 for a bad token is covered by
  `tests/test-authzen.sh`.

## Not covered yet

- `pdp_server_metadata=discovery`: the suite fetches `<PDP>/.well-known/authzen-configuration`
  and stops when `policy_decision_point` in it differs from the configured one. Behind the https
  front pgauthzd would advertise its own http URL unless `BASE_URL` is set on the instance (the
  front sends `X-Forwarded-Proto`/`-Host`, which pgauthzd does not read yet).
- `authzen_support=properties` (fixture rules 5–8: archived records, the admin role, soft
  delete): pgauthzd does not feed `subject`/`resource`/`action` properties into the engine.
- `client_secret_basic` and `mtls`: pgauthzd authenticates callers by JWT only.
