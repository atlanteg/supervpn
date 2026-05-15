BUILD        := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
VERSION      := b$(BUILD)
ZIP          := dist/supervpn-dist.zip
RELEASES_REPO := atlanteg/supervpn-releases

.PHONY: all build server client-windows client-darwin-arm64 client-darwin-amd64 \
        zip release test lint clean

# ── default ──────────────────────────────────────────────────────────────────
all: build zip

# ── per-platform builds ───────────────────────────────────────────────────────
server:
	GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/linux/supervpn-server ./cmd/supervpn-server

client-windows:
	GOOS=windows GOARCH=amd64 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/windows/supervpn-client.exe ./cmd/supervpn-client

client-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/macos/supervpn-client-arm64 ./cmd/supervpn-client

client-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/macos/supervpn-client-amd64 ./cmd/supervpn-client

build: server client-windows client-darwin-arm64 client-darwin-amd64

# ── single combined zip ───────────────────────────────────────────────────────
zip: build
	cd dist && zip -r ../$(ZIP) linux windows macos --exclude "**/.DS_Store"
	@echo "Created $(ZIP)"

# ── publish to public releases repo ──────────────────────────────────────────
# Each build gets a unique versioned tag (b75, b76, …) and is marked --latest.
# GitHub's /releases/latest/download/ is a dynamic server-side redirect —
# it is NOT served by the CDN and always resolves to the newest --latest release.
# Reusing a fixed tag (e.g. "latest") would cause CDN to cache the old asset URL;
# versioned tags avoid this completely.
release: zip
	gh release create $(VERSION) $(ZIP) \
		--repo $(RELEASES_REPO) \
		--title "supervpn $(VERSION)" \
		--notes "Build $(VERSION) — commit $$(git rev-parse --short HEAD)" \
		--latest
	@echo ""
	@echo "Build:    $(VERSION)"
	@echo "Download: https://github.com/$(RELEASES_REPO)/releases/latest/download/supervpn-dist.zip"

# ── dev ───────────────────────────────────────────────────────────────────────
test:
	go test -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(ZIP)
