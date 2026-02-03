# GHOSTWIRE Makefile
BINARY := ghostwire
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -ldflags "-s -w \
	-X github.com/ghostwire/ghostwire/internal/cli.Version=$(VERSION) \
	-X github.com/ghostwire/ghostwire/internal/cli.Commit=$(COMMIT) \
	-X github.com/ghostwire/ghostwire/internal/cli.BuildTime=$(BUILD_TIME)"

.PHONY: all build static test lint clean release

# Default target
all: build

# Build for current platform
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/ghostwire

# Build static binary
static:
	CGO_ENABLED=0 go build $(LDFLAGS) \
		-tags netgo \
		-ldflags "-extldflags '-static'" \
		-o bin/$(BINARY) ./cmd/ghostwire

# Cross-compile for all targets
release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/ghostwire
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 ./cmd/ghostwire
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-amd64 ./cmd/ghostwire
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64 ./cmd/ghostwire
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY)-windows-amd64.exe ./cmd/ghostwire

# Run tests
test:
	go test -v -race ./...

# Run tests with coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...

# Tidy dependencies
tidy:
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Development build and run
dev: build
	./bin/$(BINARY) --help
