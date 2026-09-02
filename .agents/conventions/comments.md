# Comment conventions

The single source of comment policy in this repository, read by whoever writes or reviews comments. The `better-comment` skill audits or rewrites the comments of a change against it.

## Shape

Every comment, a `//` line above a statement or a doc comment, has two parts: a brief, then, only when needed, one blank line and a detailed block.

```
<brief>

<detailed>
```

- **Brief**: 1–2 lines, the why or the contract, not a restatement of the code. State the invariant or the reason the code is non-obvious. A comment that only paraphrases the line beneath it is deleted.
- **Blank line**: exactly one, and only when a detailed block follows. Never two.
- **Detailed**: a short block, 6–8 lines as a guideline rather than a gate: preconditions, failure modes, the correctness argument. Prose, not a bulleted spec. A block that outgrows the ceiling documents a function that should be split or a type that should be named.
- **One comment per span**: a brief may stand alone, a detailed block never stands without its brief. Several detached paragraphs above one declaration are folded into one brief and one detailed block, or the code is split.
- **Doc comments** follow the same shape: the brief is the synopsis `go doc` prints and opens with the symbol's name, the detailed block is the body. The blank line is what separates the two for the doc tool.

## Content

- Every exported symbol has a doc comment saying what the symbol is for and what its contract is. Options, actions and targets paraphrase `ipfw(8)`. That is the whole requirement, no essays.
- Comment the why and the invariant, not the code. Delete comments that restate the line below, describe the obvious or paraphrase the function body. A type's doc never repeats what its field docs say. Unexported helpers get a comment only when they carry a non-obvious contract. Constants in a documented block need their own line only when the name does not say it all.
- No code identifiers in prose: a comment states intent, invariants and contracts in domain terms and never names internal functions, fields, variables or locals, which restates the code and rots on every rename. Write "a failed update leaves the prior config intact", not "if update returns err, the config is unchanged". Two exceptions: a doc comment opens with its own symbol's name, and another symbol is named when the relationship to it is the contract, the `ErrorKind` a parser fails with or the `TargetKind` a token gets being part of it.
- No comment is a substitute for a name: if the brief is "this returns the foo", rename the symbol instead.
- No references to Rust files or line numbers in shipped code. Examples go in `Example*` test functions, not in doc comments.

## Prose

- Sentences start with a capital letter. No semicolons: use separate sentences, commas or dashes.
- Lines stay within 100 columns, `gofumpt` does not rewrap.
- Directives such as `//go:` and `//nolint` are not prose and stay exactly as written.
