FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /ghostwire ./cmd/ghostwire

FROM alpine:3.20

RUN apk add --no-cache \
    iproute2 \
    iptables \
    tcpdump \
    curl \
    bash

COPY --from=builder /ghostwire /usr/local/bin/ghostwire

RUN mkdir -p /etc/ghostwire /var/log/ghostwire

ENTRYPOINT ["/usr/local/bin/ghostwire"]
