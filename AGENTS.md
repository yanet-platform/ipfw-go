# AGENTS.md

Guidance for AI coding agents working on `ipfw`. Facts about the code, build and environment only. `.githooks/` is local and gitignored, depending on locally installed linters.

## Project

`ipfw` (`github.com/yanet-platform/ipfw-go`, Go 1.24) is a **stdlib-only runtime** port of the Rust `ipfw` crate at `../ipfw`: a streaming, zero-copy parser for the FreeBSD/macOS `ipfw(8)` ruleset format plus a virtual machine that evaluates a packet against the ruleset. Package `ipfw` holds the parser, the token types, `State` and the typed layer (`Environment`, `Resolver`, `VMState`), package `vm` the VM. Tests use `testify`, `rapid` and `xnetip`. `README.md` shows the layers and the deviations from the Rust crate and from FreeBSD.

## Layout

Root: `lex.go`, `errors.go`/`diag.go`, `parser.go`, one file per token family (`action`, `proto`, `target`, `port`, `opt`, `ifmask`, `table`), `hooks.go`, `state.go`, `vmstate.go` (typed layer). `vm/`: `vm.go`, `tables.go`, `packet.go`. `internal/synthetic/`: the test ruleset generator. `.agents/`: the comment convention and the skills, symlinked from `.claude/skills/`.

Priorities: **functionality first, performance second** — but the parse path (per line) and the match path (per packet) are allocation-free by design.

## Build, test, lint

```bash
go build ./... && go vet ./...
go test ./...                                   # all tests
go test -run 'Test_Parser_Next_' -v ./...
go test -short ./...                            # rapid checks divided by five
go test -run 'Test_X' -rapid.checks=1000 -rapid.seed=<n> ./...   # more checks / replay a failure
go test -run xxx -bench 'Benchmark_Parser_Next' -benchmem ./...
go test -run xxx -fuzz 'Fuzz_Parser_Next' -fuzztime 30s ./...
make test | make lint | make bench | make fuzz  # wrappers; make lint is the pre-commit hook
make hooks                                      # once per clone: git config core.hooksPath .githooks
```

`make lint` = gofumpt check, `go vet`, `golangci-lint` (`errcheck`, `govet`, `modernize`, `staticcheck`, `testifylint`, `unused`, see `.golangci.yml`), `gopls check -severity=hint` (the editor's hints, e.g. `infertypeargs`). `make lint` skips gopls when it is not installed. All binaries are installed in `$GOPATH/bin`. The module cache has every dependency: use `GOPROXY=off go get …` / `GOPROXY=off go mod tidy`.

## Hard constraints

- **Standard library only in runtime code.** Tests may use `github.com/stretchr/testify`, `pgregory.net/rapid`, `github.com/yanet-platform/xnetip` — nothing else.
- **No `unsafe`, no cgo, no reflection in runtime code.**
- **Zero-copy, allocation-free parse and match paths.** Input is a `string`; every emitted name is a sub-slice of it. Building a VM may allocate. Hot paths carry a `testing.AllocsPerRun == 0` test.
- **Strict parsing.** Unparseable input is a positioned `*ParseError`; never drop or guess a token.
- **Semantics follow the Rust crate** except for the deviations listed in `README.md`. Never edit `../ipfw`.

## Comments and docs — without fanaticism

The policy is `.agents/conventions/comments.md`: a brief of 1–2 lines, then, only when needed, one blank line and a short detailed block, the why and the invariant rather than the code, no semicolons in prose. The `better-comment` skill audits or rewrites the comments of a change against it.

## Code style

- `gofumpt` formatting; loop index `idx`; no abbreviated identifiers beyond `ok`, `err`, `idx`.
- Receivers are **always** named `m`.
- Encapsulation: a method that is called from outside its own type is exported, even on an unexported type. Unexported methods are called only from inside the type's own methods. The same holds for fields: unexported fields are read and written only by the type's own methods, anything needed from outside is an exported field or a getter.
- Parsing functions take the input `string` and return the rest. Failure is atomic: the function returns its input unchanged together with the error (`fail{kind, at}` internally, `at` being the input at the detection point). Never a `*string` cursor — a pointer crossing a function value or an interface call is treated as escaping and heap-allocates the caller's cursor. Public functions return `error`.
- No named result parameters.
- Functional options configure an unexported `xOptions` struct with exported fields (`type XOption func(*xOptions)`), built with defaults by `newXOptions()`. A variadic option parameter is named `options`. `opts` is only the local the constructor accumulates them into before building the value.
- Function ordering: top-down, exported entry points first, helpers below their first caller.
- Dead code is deleted, never commented out.
- Lines stay within 100 columns (`gofumpt` does not wrap). A composite literal or a call that does not fit is written one field or argument per line, table-test cases included.

## Tests

- Names: `Test_<What>_<Case>` (`Test_Parser_Next_Comment`, `Test_ParseOptions_OrGroup`), `Benchmark_<What>_<Case>`, `Fuzz_<What>_<Case>`; examples `Example<Type>_<Method>` (Go fixes that shape).
- Each test carries a one-line `// verifies that …` brief.
- `require` by default, `assert` for several independent checks; `(t, expected, actual)` order. Table cases have self-describing `name:`s.
- Assert the **full** collected state (`ReduceState`/`RuleState` literal) and the exact remaining input / consumed length — the Rust tests do, and it is what catches silent token drops.
- `rapid.Check` for properties with simple oracles; native fuzzing for the parser entry points and `MatchIfMask`; seed corpora are checked in.
- Benchmarks and fuzz targets live in the same `_test.go` file as the unit tests of the code they exercise — no separate `*_bench_test.go` or `fuzz_test.go` files.
- One style per unit. The parser is tested as a black box (`package ipfw_test`) through `Next` and the exported sub-parsers, unexported helpers are covered indirectly. Only the lexer (`lex_test.go`) is white-box, having no exported surface.
- Test data is made up: documentation networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), `example.com` hostnames, invented macro and label names. Never copy strings from real rulesets, comments or tickets.

## Session protocol (TDD, one feature per session)

1. Read the Rust code the feature mirrors fresh, tests included: they are the spec.
2. Write the feature's tests first and watch them fail (a compile error is not a failing test — add the minimal stubs).
3. Implement until `make test` is green, then `make lint`.
4. Commit — one commit per feature.

## Commits

- One commit per feature, directly on `main`, only after `make lint` and `make test` are green. Do not amend or rewrite existing commits.
- Subject: `feat|fix|perf|refactor|test|docs|chore(scope): brief` — lowercase brief, no trailing period; scope = package or area (`parser`, `lexer`, `action`, `target`, `opt`, `rulestate`, `vm`, `docs`). Tests of the change go in the same commit.
- **No AI attribution anywhere**: no `Co-Authored-By`, no "Generated with" footers, in commits or files.
