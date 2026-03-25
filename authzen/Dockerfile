FROM golang:1.26-alpine AS builder

ARG BINARY=authzen-direct

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /app ./cmd/${BINARY}

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app

ENTRYPOINT ["/usr/local/bin/app"]
