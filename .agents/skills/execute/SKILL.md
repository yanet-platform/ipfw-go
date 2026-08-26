---
name: execute
description: Execute one roadmap step from .roadmap/ end to end — read the plan and the Rust reference, TDD, gates, commit, mark done. Use with a step number, e.g. /execute 051.
argument-hint: <step number, e.g. 051>
disable-model-invocation: true
---

Execute roadmap step `$ARGUMENTS` of this repository from scratch, as one
self-contained session. The step number is the three-digit prefix of a file
in `.roadmap/` (`051` → `.roadmap/051-action-pass.md`). Never do more than one
step.

## 1. Locate and validate the step

- Resolve `.roadmap/$ARGUMENTS-*.md`. If no file matches, or several match,
  list `.roadmap/` and stop.
- Open `.roadmap/README.md` and check the status table:
  - the step must be `todo` (or `later` if the user explicitly asked for it);
    if it is `done` (its file is gone by then), say so and stop;
  - every lower-numbered step must be `done`. If one is not, stop and report
    which — do not skip ahead.
- `git status` must be clean (no staged or unstaged changes). If it is not,
  stop and report.

## 2. Load the context, fresh

Read in this order, fully, even if you think you remember them:

1. `.roadmap/README.md` — design, canonical API sketch, rules, deviations.
2. `AGENTS.md` — constraints, comment policy, test naming, commit rules.
3. The step file — goal, API, behaviour, tests to write first, acceptance.
4. The Rust code the step's **Rust reference** names, under `../ipfw/src/`
   (`/home/esafronov/code/ipfw`). Read the referenced functions *and their
   tests*; the tests are the spec of the exact expected structures and the
   exact remaining input.
5. The existing Go code the step touches (`go doc ./...`, the files named
   in the README source map).

## 3. TDD, strictly

1. Write the tests the step lists (names per `AGENTS.md`:
   `Test_<Unit>_<Case>`, one `// verifies that …` brief each), asserting the
   **full** collected state / record and the exact remaining input or
   consumed length. Port the referenced Rust tests one to one.
2. Add only the minimal stubs needed to compile, then run
   `go test ./... 2>&1 | head -60` and confirm every new test **fails for the
   right reason** (an assertion or an expected error — not a compile error,
   not a panic in the harness). Quote the failure in your notes.
3. Implement the behaviour exactly as the step specifies (semantics 1:1 with
   the Rust crate unless the step or the README deviations say otherwise).
   Keep the parse and match paths allocation-free; no `unsafe`; no new
   non-test dependencies (`GOPROXY=off go get …` + `GOPROXY=off go mod tidy`
   only for the three allowed test modules).
4. Iterate until `go test ./...` is green. Add the `AllocsPerRun`, `rapid`
   and fuzz tests the step asks for. Do not weaken a test to make it pass —
   if the plan and the Rust code disagree, see step 5.

## 4. Gates

Run, in order, and fix everything they report:

```bash
gofumpt -w .
make test        # go test -race ./...
make lint        # gofumpt check, go vet, golangci-lint, gocommentlint
```

If the step added a fuzz target: `go test -run xxx -fuzz '^Fuzz<Name>$' -fuzztime 10s <pkg>`.
If the step added benchmarks: `make bench` must compile and run them.

## 5. When the plan is wrong

If implementing reveals a real conflict (the Rust code does something the
step did not anticipate, an API in the README cannot work, a later step's
assumption breaks), do **not** improvise silently:

- fix the design in `.roadmap/README.md` and/or the affected step files
  (they are local, gitignored);
- explain the change in the commit body;
- if the conflict changes an agreed decision (a README "Design" item or a
  deviation), stop before committing and ask the user with the options.

## 6. Commit

- Subject: the **Commit subject** line of the step file. Body: what and why,
  one short paragraph; benchmark numbers if the step measured anything.
- English. No `Co-Authored-By`, no "Generated with", no AI attribution.
- `git add -A` (the roadmap and `.githooks/` are gitignored — never force-add
  them) and commit; the pre-commit hook runs `make lint` again. Do not amend
  older commits.

## 7. Mark done and report

- In `.roadmap/README.md` set the step's row to `done` with the short hash
  and drop the link from the row, then delete the step file (`git rm` is not
  needed — the roadmap is untracked). A finished step leaves only its row
  and its commit. These edits are local and are not committed.
- Report to the user: the commit hash, what was implemented, how many tests
  were added, any plan change made in step 5, and anything the acceptance
  criteria left uncovered. Then stop — the next step is a new session.
