package authn.config

_env := opa.runtime().env

# Required JWT issuer (iss claim).
# Set via JWT_ISSUER env var on the OPA service.
required_issuer := _env.JWT_ISSUER

# Required JWT audience (aud claim).
# Set via JWT_AUDIENCE env var on the OPA service.
required_audience := _env.JWT_AUDIENCE
