VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
ZIP     := dist/supervpn-dist.zip

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

# ── publish to GitHub Releases (tag: latest) ─────────────────────────────────
release: zip
	gh release delete latest --yes 2>/dev/null || true
	git push origin :refs/tags/latest 2>/dev/null || true
	gh release create latest $(ZIP) \
		--title "supervpn latest ($(VERSION))" \
		--notes "Автосборка: $(VERSION)" \
		--latest
	@echo ""
	@echo "Download: https://github.com/atlanteg/supervpn/releases/latest/download/supervpn-dist.zip"

# ── dev ───────────────────────────────────────────────────────────────────────
test:
	go test -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(ZIP)
