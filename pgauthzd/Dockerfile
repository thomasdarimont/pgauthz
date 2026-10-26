# Build context is the REPO ROOT (compose: `context: .`; Helm start.sh and
# the README build with `-f pgauthzd/Dockerfile .`) because the daemon
# depends on the sibling module pgauthzadm/ (the fixture runner behind
# POST /pgauthz/v1/admin/models/test) via a go.mod replace directive.
FROM golang:1.27.3-alpine AS builder

# Stamped into the binary (main.version), exposed via `pgauthzd -version`.
# start.sh passes --build-arg VERSION=<image tag>; defaults to dev otherwise.
ARG VERSION=dev

WORKDIR /src
COPY pgauthzadm/ ./pgauthzadm/
COPY pgauthzd/go.mod pgauthzd/go.sum ./pgauthzd/
WORKDIR /src/pgauthzd
RUN go mod download

COPY pgauthzd/ ./
# Single binary now — pgauthzd, capability-scoped by PGAUTHORIZER_PROFILE.
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /app ./cmd/pgauthzd

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app

ENTRYPOINT ["/usr/local/bin/app"]
