GOPATH_BIN := $(shell go env GOPATH)/bin
VERSION    ?= dev

.PHONY: build server client-windows client-darwin test lint clean

build: server client-windows

server:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/supervpn-server-linux-amd64 ./cmd/supervpn-server

client-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/supervpn-client-windows-amd64.exe ./cmd/supervpn-client

client-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" \
		-o dist/supervpn-client-darwin-amd64 ./cmd/supervpn-client

test:
	go test -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf dist/
