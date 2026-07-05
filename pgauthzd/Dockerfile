FROM golang:1.26-alpine AS builder

# Stamped into the binary (main.version), exposed via `pgauthzd -version`.
# start.sh passes --build-arg VERSION=<image tag>; defaults to dev otherwise.
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Single binary now — pgauthzd, capability-scoped by PGAUTHORIZER_PROFILE.
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /app ./cmd/pgauthzd

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app

ENTRYPOINT ["/usr/local/bin/app"]
