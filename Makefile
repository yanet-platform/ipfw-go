# Developer entry points for the gates described in AGENTS.md.
#
# The lint binaries (gofumpt, golangci-lint, gocommentlint, benchstat) are
# installed with `go install` into $GOPATH/bin, which is prepended to PATH
# here so the targets work even when that directory is not on the caller's
# PATH.

export PATH := $(shell go env GOPATH)/bin:$(PATH)

.PHONY: test test-short lint bench bench-run fuzz hooks

# The full test gate, same flags as CI.
test:
	go test -race ./...

# Property tests at one fifth of the checks (rapid divides -rapid.checks
# by five under -short).
test-short:
	go test -short ./...

# The static gate: formatting, vet, golangci-lint, then the comment shape
# of the staged diff. The pre-commit hook runs exactly this target.
# gocommentlint is a local tool: when it is not installed the gate reports
# that and skips it instead of failing (CI and fresh clones stay green).
lint:
	@unformatted="$$(gofumpt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofumpt: files need formatting (run 'gofumpt -w .'):"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...
	golangci-lint run ./...
	@if command -v gocommentlint >/dev/null 2>&1; then gocommentlint; \
	else echo "lint: gocommentlint not installed, skipping the comment gate"; fi

# Compile and smoke-run every benchmark once.
bench:
	go test -run xxx -bench . -benchtime 1x ./...

# The measurement run, feed the output to benchstat.
bench-run:
	go test -run xxx -bench . -benchmem -count 10 ./...

# Run every fuzz target briefly (FUZZTIME overrides the per-target budget).
FUZZTIME ?= 10s
fuzz:
	@for target in $$(grep -ho 'func Fuzz[A-Za-z0-9_]*' $$(find . -name '*_test.go') | sed 's/func //' | sort -u); do \
		pkg=$$(grep -l "func $$target(" $$(find . -name '*_test.go') | head -1 | xargs dirname); \
		echo "== $$target ($$pkg)"; \
		go test -run xxx -fuzz "^$$target$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	done

# Once per clone: route git hooks to the versioned .githooks directory.
hooks:
	git config core.hooksPath .githooks
