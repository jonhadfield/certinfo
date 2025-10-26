VERSION ?= dev

.DEFAULT_GOAL := build

test:
	go fmt ./...
	go vet ./...
	go clean -testcache && go test -cover ./...
.PHONY:test

build: test
	go build -ldflags "-X main.Version=${VERSION}" -mod vendor
.PHONY:build

install: test
	go install -ldflags "-X main.Version=${VERSION}" -mod vendor
.PHONY:install

# Reusable variables
GORELEASER ?= goreleaser
GITHUB_TOKEN ?= $(shell echo $$GITHUB_TOKEN)
GO_VERSION := 1.22-bookworm

release: release-mac release-linux-amd64 release-linux-arm64
	@echo "✅ All artifacts uploaded to the same GitHub release."

# macOS (darwin/arm64) + Windows if you still want it here — adjust as needed
release-mac:
	@echo "🚀 Releasing darwin/arm64 on host..."
	$(GORELEASER) release --clean --config .goreleaser/.goreleaser.darwin-arm64.yml

ifndef GITHUB_TOKEN
$(error GITHUB_TOKEN is not set. Run: export GITHUB_TOKEN=<your PAT with repo scope>)
endif

release-linux-amd64:
	@echo "🐧 Building linux/amd64 in container (goreleaser-cross)..."
	docker run --rm --platform=linux/amd64 \
	  --entrypoint /bin/sh \
	  -e GITHUB_TOKEN=$(GITHUB_TOKEN) \
	  -v "$$(pwd)":/src -w /src ghcr.io/goreleaser/goreleaser-cross:latest \
	  -c '\
	    set -eu ; \
	    apt-get update && apt-get install -y --no-install-recommends libx11-dev pkg-config && \
	    goreleaser release --clean --config .goreleaser/.goreleaser.linux-amd64.yml \
	  '

release-linux-arm64:
	@echo "🐧 Building linux/arm64 in container (goreleaser-cross)..."
	docker run --rm --platform=linux/arm64 \
	  --entrypoint /bin/sh \
	  -e GITHUB_TOKEN=$(GITHUB_TOKEN) \
	  -v "$$(pwd)":/src -w /src ghcr.io/goreleaser/goreleaser-cross:latest \
	  -c '\
	    set -eu ; \
	    apt-get update && apt-get install -y --no-install-recommends libx11-dev pkg-config && \
	    goreleaser release --clean --config .goreleaser/.goreleaser.linux-arm64.yml \
	  '
