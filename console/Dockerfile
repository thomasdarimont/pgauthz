# Build context is the REPO ROOT (see compose-console.yml) because the backend
# depends on the sibling module pgauthzadm/ via a go.mod replace directive. The
# image bundles the Go BFF and the Lit SPA (frontend/) into one container.
FROM golang:1.26-alpine AS builder
# compose passes --build-arg VERSION=<tag> (compose-console.yml); dev otherwise.
ARG VERSION=dev
ARG REVISION=
WORKDIR /src
COPY pgauthzadm/ ./pgauthzadm/
COPY console/backend/go.mod console/backend/go.sum ./console/backend/
WORKDIR /src/console/backend
RUN go mod download
COPY console/backend/ ./
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -X main.revision=${REVISION}" -o /app ./cmd/console

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app
# Bundle the SPA so the container is self-contained. (In dev, compose
# bind-mounts the host frontend over /web for live editing.)
COPY console/frontend/ /web/
ENV WEB_DIR=/web
ENTRYPOINT ["/usr/local/bin/app"]
