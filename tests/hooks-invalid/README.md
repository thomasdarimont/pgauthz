# Negative fixtures for `scripts/validate-hooks.sh --allow-http`

Each hook is the shipped `examples/opa-hooks-http/external_restriction.rego`
with one bad destination URL. `tests/test-hook-validator.sh` asserts that the
validator REJECTS every one of them with the expected reason — the
allowlist/canonicalisation contract of ADR 0011 (SECURITY-AUDIT F17/F18):

| File | Destination | Must fail because |
|---|---|---|
| `bad_ipv6.rego` | `https://[2001:db8::1]:8443/…` | host not in `allow_net` — and an IPv6 literal is a bracket glob that once slipped past an unquoted loop under `nullglob` |
| `bad_userinfo.rego` | `https://policy.internal.example@evil.example/…` | userinfo: the allowlisted name is the user, the real host is `evil.example` |
| `bad_plainhttp.rego` | `http://policy.internal.example/…` | https required beyond loopback (passes only with `--allow-plain-http`) |
| `bad_upper.rego` | `https://Policy.Internal.Example/…` | non-canonical host: OPA compares `allow_net` byte-for-byte |

Not mounted anywhere; never load these into a real OPA.
