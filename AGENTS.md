# AGENTS.md

Guidance for AI coding agents working on `ipfw`. Facts about the code, build
and environment only; the work plan and the design live in `.roadmap/`
(local, gitignored — as are `.githooks/`, which depend on locally installed
linters).

## Project

`ipfw` (`github.com/yanet-platform/ipfw`, Go 1.24) is a **stdlib-only
runtime** port of the Rust `ipfw` crate at `../ipfw`: a streaming, zero-copy
parser for the FreeBSD/macOS `ipfw(8)` ruleset format plus a virtual machine
that evaluates a packet against the ruleset. Package `ipfw` holds the parser,
the token types, the `State` interface and the typed `RuleState`; package
`vm` holds the VM. Tests use `testify`, `rapid` and `xnetip` (concrete
network types). Read `.roadmap/README.md` for the design and the canonical
API before touching anything.

Priorities: **functionality first, performance second** — but the parse path
(per line) and the match path (per packet) are allocation-free by design.

## Build, test, lint

```bash
go build ./... && go vet ./...
go test ./...                                   # all tests
go test -run 'Test_Parser_Next_' -v ./...
go test -short ./...                            # rapid checks divided by five
go test -run 'Test_X' -rapid.checks=1000 -rapid.seed=<n> ./...   # more checks / replay a failure
go test -run xxx -bench 'BenchmarkParser_Next' -benchmem ./...
go test -run xxx -fuzz 'FuzzNext' -fuzztime 30s ./...
make test | make lint | make bench | make fuzz  # wrappers; make lint is the pre-commit hook
make hooks                                      # once per clone: git config core.hooksPath .githooks
```

`make lint` = gofumpt check, `go vet`, `golangci-lint` (`errcheck`, `govet`,
`modernize`, `staticcheck`, `testifylint`, `unused`, see `.golangci.yml`),
`gocommentlint` (a local tool; `make lint` skips it when it is not installed;
it inspects the **staged** diff, so `git add -A` before `make lint` — the
pre-commit hook sees the staged files anyway).
All binaries are installed in `$GOPATH/bin`. The module cache
has every dependency: use `GOPROXY=off go get …` / `GOPROXY=off go mod tidy`.

## Hard constraints

- **Standard library only in runtime code.** Tests may use
  `github.com/stretchr/testify`, `pgregory.net/rapid`,
  `github.com/yanet-platform/xnetip` — nothing else.
- **No `unsafe`, no cgo, no reflection in runtime code.**
- **Zero-copy, allocation-free parse and match paths.** Input is a `string`;
  every emitted name is a sub-slice of it. Building a VM may allocate. Hot
  paths carry a `testing.AllocsPerRun == 0` test.
- **Strict parsing.** Unparseable input is a positioned `*ParseError`; never
  drop or guess a token.
- **Semantics follow the Rust crate** except for the deviations listed in
  `.roadmap/README.md`. Never edit `../ipfw`.

## Comments and docs — without fanaticism

- Every exported symbol has a doc comment that opens with its name and says
  what the symbol is for and what its contract is. Options, actions and
  targets paraphrase `ipfw(8)`. That is the whole requirement — no essays.
- Shape (enforced by `gocommentlint` on staged diffs): a brief of 1–2 lines,
  then, only when needed, one blank line and a short detailed block
  (preconditions, failure modes, the correctness argument).
- Comment the *why* and the invariant, not the code. Delete comments that
  restate the line below, describe the obvious, or paraphrase the function
  body. A type's doc never repeats what its field docs say. Unexported
  helpers get a comment only when they carry a non-obvious contract.
  Constants in a documented block need their own line only when the name
  does not say it all. No references to Rust files or line numbers in
  shipped code (they belong in `.roadmap/`). Sentences start with a capital
  letter.
- No semicolons in comment prose: use separate sentences, commas or
  dashes.
- Examples go in `Example*` test functions, not in doc comments.

## Code style

- `gofumpt` formatting; loop index `idx`; no abbreviated identifiers beyond
  `ok`, `err`, `idx`.
- Receivers are **always** named `m`.
- Encapsulation: a method that is called from outside its own type is
  exported, even on an unexported type. Unexported methods are called only
  from inside the type's own methods.
- Parsing functions take the input `string` and return the rest. Failure is
  atomic: the function returns its input unchanged together with the error
  (`fail{kind, at}` internally, `at` being the input at the detection
  point). Never a `*string` cursor — a pointer crossing a function value or
  an interface call is treated as escaping and heap-allocates the caller's
  cursor. Public functions return `error`.
- No named result parameters.
- Function ordering: top-down, exported entry points first, helpers below
  their first caller.
- Dead code is deleted, never commented out.

## Tests

- Names: `Test_<Unit>_<Case>` (`Test_Parser_Next_Comment`,
  `Test_ParseOptions_OrGroup`); benchmarks `Benchmark<Type>_<Method>[_<Shape>]`;
  fuzz `Fuzz<Function>`; examples `Example<Type>_<Method>`.
- Each test carries a one-line `// verifies that …` brief.
- `require` by default, `assert` for several independent checks;
  `(t, expected, actual)` order. Table cases have self-describing `name:`s.
- Assert the **full** collected state (`CollectState`/`RuleState` literal)
  and the exact remaining input / consumed length — the Rust tests do, and it
  is what catches silent token drops.
- `rapid.Check` for properties with simple oracles; native fuzzing for the
  parser entry points and `MatchIfMask`; seed corpora are checked in.

## Session protocol (TDD, one feature per session)

1. Read `.roadmap/README.md`, then the step file; check its dependencies are
   `done`. Read the referenced Rust code fresh.
2. Write the step's tests first and watch them fail (a compile error is not a
   failing test — add the minimal stubs).
3. Implement until `make test` is green, then `make lint`.
4. Mark the step `done` with the commit hash in `.roadmap/README.md` and
   commit — one commit per step.

## Commits

- One commit per roadmap step, directly on `main`, only after `make lint`
  and `make test` are green. Do not amend or rewrite existing commits.
- Subject: `feat|fix|perf|refactor|test|docs|chore(scope): brief` — lowercase
  brief, no trailing period; scope = package or area (`parser`, `lexer`,
  `action`, `target`, `opt`, `rulestate`, `vm`, `docs`). Tests of the change
  go in the same commit.
- **No AI attribution anywhere**: no `Co-Authored-By`, no "Generated with"
  footers, in commits or files.
