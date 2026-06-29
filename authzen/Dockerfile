FROM golang:1.26-alpine AS builder

ARG BINARY=authzen-direct
# Stamped into the binary (main.version), exposed via `<binary> -version`.
# start.sh passes --build-arg VERSION=<image tag>; defaults to dev otherwise.
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /app ./cmd/${BINARY}

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app

ENTRYPOINT ["/usr/local/bin/app"]
