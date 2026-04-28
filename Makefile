.PHONY: build test test-int lint install release snapshot clean help

BIN := bin/ora
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

## build: compile the binary for the current platform
build:
	go build -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/ora

## test: run unit tests
test:
	go test ./...

## test-int: run integration tests (macOS only)
test-int:
	go test -tags=integration ./...

## lint: run golangci-lint (requires golangci-lint v2.x)
lint:
	golangci-lint run

## install: install the binary to $GOPATH/bin
install:
	go install -ldflags="$(LDFLAGS)" ./cmd/ora

## release: create a release via GoReleaser (requires GITHUB_TOKEN)
release:
	goreleaser release --clean

## snapshot: build release artifacts locally without publishing or signing
snapshot:
	goreleaser release --snapshot --clean --skip=sign

## clean: remove build artifacts
clean:
	rm -rf bin dist

## help: show this help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'
