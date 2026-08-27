# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), the versions [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

The first release: the parser, the typed layer and the virtual machine.

### Added

- `Parser`: a streaming, zero-copy, allocation-free parser of the `ipfw(8)` ruleset format, one `Record` per line, the rule body pushed into a `State` as sub-slices of the input. `Next` for one line, `Records` for an iterator, `Reset` to read another input.
- Rules: the actions `pass`, `deny`, `count`, `skipto` (label, number, tablearg) and `check-state`, rule numbers, `log [logamount N]`, `tag N`, inline `//` comments, protocols by name, number or IP keyword, targets `any`, `me`, `me6`, networks of both families, hostnames, `table(NAME)` and macros, ports and ranges by number or service name, and the options `in`, `out`, `established`, `frag`, `diverted`, `antispoof`, `keep-state`, `icmptypes`, `icmp6types`, `tcpflags`, `src-port`, `dst-port`, `proto` and `via`, with `not` and `{ a or b }` groups throughout. `table NAME create|add`, `:LABEL` lines and `#` comments are records of their own.
- `ParseError` with a line, a column and the offending text, and `Diag`, which renders it the way rustc does, optionally coloured through a `DiagStyle` (`ColorDiagStyle`, `DiagStyleFor`).
- The typed layer: `Resolver`, a `State` that resolves every name within an `Environment` (networks with the consumer's own types, protocols and services into numbers, hostnames and macros into networks) and hands typed tokens to a `VMState`, and `ReduceVMState`, which collects them.
- Extension points: `WithCommandHook` and `WithOptionHook` on the parser, the exported sub-parsers a hook builds on, and the resolver interfaces.
- Package `vm`: `Build` reads a ruleset into a `VM`, `Check` and `CheckTrace` run a `Packet` through it in a `Context` (direction, interface, the host's own addresses), with tables, jumps, a tracer, a default verdict and a matcher for custom options. `RawIPv4Packet` and `RawIPv6Packet` implement `Packet` over raw bytes.

[Unreleased]: https://github.com/yanet-platform/ipfw/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yanet-platform/ipfw/releases/tag/v0.1.0
