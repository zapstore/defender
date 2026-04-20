BUILD_DIR := build
LDFLAGS   := -s -w
TAG       ?= $(shell git describe --tags --abbrev=0 2>/dev/null)

.PHONY: all clean defender defender-cli

all: defender defender-cli

defender defender-cli:
	@echo "Building $@ at tag $(TAG)"
	@mkdir -p $(BUILD_DIR)
	@set -e; \
	if [ -z "$(TAG)" ]; then \
		echo "No tags found" >&2; \
		exit 1; \
	fi; \
	if ! git rev-parse -q --verify "refs/tags/$(TAG)" >/dev/null; then \
		echo "Tag $(TAG) not found" >&2; \
		exit 1; \
	fi; \
	ORIG_REF="$$(git rev-parse --abbrev-ref HEAD)"; \
	ORIG_SHA="$$(git rev-parse HEAD)"; \
	RESTORE() { \
		if [ "$$ORIG_REF" = "HEAD" ]; then \
			git checkout -q "$$ORIG_SHA"; \
		else \
			git checkout -q "$$ORIG_REF"; \
		fi; \
	}; \
	trap 'RESTORE' EXIT; \
	git -c advice.detachedHead=false checkout -q "$(TAG)"; \
	if [ "$@" = "defender" ]; then \
		CMD=./cmd/server; \
	else \
		CMD=./cmd/cli; \
	fi; \
	CGO_ENABLED=1 \
		go build -ldflags "$(LDFLAGS) -X github.com/zapstore/defender/pkg/server.Version=$(TAG)" \
		-o $(BUILD_DIR)/$@-$(TAG) $$CMD; \
	echo "Built $@ from commit $$(git rev-parse HEAD), $$(git log -1 --pretty=%s)"

clean:
	rm -rf $(BUILD_DIR)
