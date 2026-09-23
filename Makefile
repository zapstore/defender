# Deploy runs: make release REF=<ref>
# Writes dist/<name>-<ref>-<arch>. Infra installs that file as releases/<id>-<ref>.

NAME := defender
REF ?=
GOARCH ?= $(shell go env GOARCH)
DIST := dist/$(NAME)-$(or $(REF),dev)-$(GOARCH)

.PHONY: release clean

release:
	mkdir -p dist
	rm -rf $(DIST)
	CGO_ENABLED=1 go build -trimpath \
		-ldflags '-s -w $(if $(REF),-X github.com/zapstore/defender/pkg/server.Version=$(REF))' \
		-o $(DIST) ./cmd/server

clean:
	rm -rf dist
