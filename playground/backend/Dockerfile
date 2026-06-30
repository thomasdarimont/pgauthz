# Build context is ./playground (see compose) so the image can bundle BOTH the Go
# backend (backend/) and the SPA (frontend/) into one self-contained container.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -o /app ./cmd/playground

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app
# Bundle the SPA so the container is self-contained and runnable standalone.
# (In dev, compose bind-mounts the host frontend over /web for live editing.)
COPY frontend/ /web/
ENV WEB_DIR=/web
ENTRYPOINT ["/usr/local/bin/app"]
