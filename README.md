# ipfw-go

A streaming parser for the FreeBSD/macOS [`ipfw(8)`](https://man.freebsd.org/cgi/man.cgi?ipfw(8)) ruleset format and a virtual machine that evaluates a packet against the ruleset. The runtime uses the standard library only.

```sh
go get github.com/yanet-platform/ipfw-go
```

Licensed under the Apache License 2.0, see [LICENSE](LICENSE).

## What it gives you

- **Nothing allocates on the hot paths.**

  Parsing a line and checking a packet allocate zero bytes, and `testing.AllocsPerRun` guards both. The input is one string and every token is a sub-slice of it, so a 27 MB ruleset parses at 184 MB/s without touching the heap.

- **No dependencies.**

  The runtime is the standard library. Tests reach for testify, rapid and xnetip, your build does not.

- **Your network types, not ours.**

  The typed layer is generic over the IPv4 and IPv6 types you already use, plugged in with a literal. Nothing forces a wrapper on you.

- **Strict parsing with errors that point.**

  No token is dropped or guessed. A line that does not fit the grammar is a `*ParseError` with a line, a column and the text, rendered by `Diag` with a caret under the offending token, coloured when a terminal is watching.

- **Names are yours to resolve.**

  Protocols, services, hostnames and custom targets go through your resolvers. You can use
  `/etc/services`, a DNS cache or your own target registry. An unresolvable name fails the line.

- **The grammar is extensible.**

  A command or an option the format does not know goes to a hook that reuses the exported sub-parsers, and the VM asks your matcher what it means.

- **The way back to text.**

  Records you collected render into canonical ruleset text: aliases folded, whitespace normalized, order stable, the round trip parse-equivalent and idempotent. Appending into a destination with room for it allocates nothing.

- **A virtual machine, not only a parser.**

  Build a ruleset once and check packets against it: protocols, addresses, ports, tables, interfaces, ICMP types, TCP flags, jumps and labels, a configurable default verdict, and a tracer that reports every rule a check evaluated.

- **Tested where it counts.**

  Property tests, fuzzing with a checked-in corpus, allocation guards, race tests, and regression runs over production rulesets of 115k rules.

## How it fits together

```
ipfw.Parser ──► ipfw.State  ──► ipfw.Resolver  ──► ipfw.VMState ──► vm.VM
one line        raw tokens      names within       numbers and      checks
at a time       of the body     an Environment     networks         packets
```

Alongside the tokens the parser hands back a `Record` for the line, saying whether it held a rule,
a table command, a label or a comment. The parser handles grammar and borrows every token from
the input. It delegates name lookup and address parsing to the supplied `State`, so parsing into
a warmed-up state costs no allocation. A `ProtoChecker` given to the parser supplies the protocol
knowledge used to choose between legacy and option-only rule bodies.

## Parsing

`Next` reads one line, returns its `Record` and pushes the rule body — protocols, targets, ports, options — into a `State`.

```go
parser := ipfw.NewParser("add 100 deny log tcp from 192.0.2.0/24 to any 22 // bots\n")
var state ipfw.ReduceState
for {
	rec, err := parser.Next(&state)
	if err != nil {
		fmt.Fprint(os.Stderr, ipfw.NewDiag(err, ipfw.WithDiagPath("fw.conf")))
		return
	}
	if rec.Kind == ipfw.RecordEOF {
		break
	}
	fmt.Println(rec.Line, rec.Instruction.Action, state.Sources, state.DestinationPorts)
	state.Reset()
}
```

Every token keeps its text: a network is `Target{Kind: TargetNetwork4, Text: "192.0.2.0/24"}`, a service is `Port{Name: "ssh"}`. See `ExampleParser_Next`.

Every token also carries its place in the match, in the terms of ipfw(8). A rule holds when every or-block of it does, an or-block when one of its match patterns does, and a pattern when one of its members does, its `not` aside. A source or a destination is one or-block, so a `Target` carries only its `Pattern`: the alternatives of `{ a or b }` count up and the members of an address list share one. Options carry `Opt.Block` as well, so `in { not dst-port 22,80 or out }` gives `in` in block 0, both ports in block 1 pattern 0 under one `not`, and `out` in block 1 pattern 1, which is how a FreeBSD instruction holds a whole port list.

Rules can use existing options as the complete body by default, as in
[FreeBSD](https://github.com/freebsd/freebsd-src/blob/2350f75acb0da0271ccff1fb22381f7e8c5948f8/sbin/ipfw/ipfw.8#L1371).
For example, `add 110 allow in proto tcp via vlan17` matches incoming TCP packets of either
address family on `vlan17`. Without a legacy header, omitted protocols and addresses impose no
restriction: the parser emits no `OnIPProto` or `OnProto` callbacks, then emits one `TargetAny`
source and one `TargetAny` destination before the options.
Ordinary actions still require a body, which may consist of a `//` comment.

With `WithProtoChecker` the first protocol selects the grammar, following
[FreeBSD's criterion](https://github.com/freebsd/freebsd-src/blob/a54f83544eea2a9804ac7940d35b26ffcb34dfb3/sbin/ipfw/ipfw2.c#L4937).
An IP keyword, a numeric protocol or a name the checker knows commits to the legacy grammar, even
if `from` is missing. Any other first name selects options. An unknown later protocol in a
group, or a rejected state callback, remains an error without trying another grammar.
Thus `add allow in` requires a legacy header if the checker knows a protocol named `in`.
Unknown initial names use option diagnostics: a `tcp` the checker does not know produces
`ErrUnknownOption` at the start of the body. Protocol names inside a selected legacy header or a
`proto` option still produce `ErrUnresolvedProto` when the resolver does not know them.

```go
parser := ipfw.NewParser(src, ipfw.WithProtoChecker(ipfw.ProtoCheckerFunc(func(name string) bool {
	_, ok := protocols.ResolveProto(name) // the ipfw.ProtoResolver of the Environment
	return ok
})))
```

The choice belongs to the parser alone, so a `ReduceState`, a `Resolver` and any wrapper around
them parse a line with the same grammar. `vm.Build` reads the parser it is given, so pass the
option there as well.

Without a proto checker, a complete `PROTO from SRC [PORT] to DST` header takes precedence over
options. Otherwise a recognized option start selects options, and other starts select legacy
parsing. Thus `add 160 allow in from any to any` keeps `in` as a protocol name, while
`add allow tcp` reports an incomplete legacy header.

A line is the unit of the format, as in FreeBSD file input. No token crosses a newline: a brace group, an address list and an option list all end where their line does, and a group left open is an error rather than a continuation onto the next line. The exported sub-parsers hold to the same rule, so a command hook can pass one the line it was handed without trimming it first.

The first `#` on a physical line starts a comment before the command is parsed, as in FreeBSD file
input. It may stand alone or follow a rule, table command or label, even without separating
whitespace.
`Record.Comment` borrows the payload after `#`, preserving leading space and trimming trailing
whitespace. `Record.Text` keeps the complete original line, including both comment markers and
payloads, without leading or trailing whitespace.

Rule comments introduced by `//` are an option, as in FreeBSD: `State.OnOption` receives an
`OptComment` whose `Text` follows the same payload whitespace rules. The comment takes the rest of
the line, so it is the last option, and inside a `{ … }` group it leaves the group unclosed.
A negated comment is accepted as upstream and makes the rule never match.
In `add pass ip from any to any // rule # metadata`, the comment text is ` rule` and the hash
payload is ` metadata`. The first hash separates the line even inside quoted text.
Standalone `//` and slash comments after tables or labels are not enabled by this behavior.

Comment-only rules such as `add 100 // note` are supported by default, as in
[FreeBSD](https://github.com/freebsd/freebsd-src/blob/88e7371d9dc26f85dfc1b008cbe59ebc7e4a33da/sbin/ipfw/ipfw.8#L1622).
They produce an `ActionCount` instruction with implicit `TargetAny` source and destination
callbacks followed by the comment option. The VM matches the rule and continues to the next one.
Any hash metadata stays in `Record.Comment`.
The `//` action must be a complete token, so `add //note` is rejected.

LF, CRLF and a final line without a newline each produce one record. Copy the returned `Record`
before the next `Next` or `Reset` if it must be kept. Its strings continue to borrow the original
input.
A reusable `State` must be reset explicitly between records, including after a parse error.

### Parser configuration

The default parser follows FreeBSD syntax. Project label declarations (`:NEXT`) and symbolic
jumps (`skipto :NEXT`) require `WithLabels()`. Existing callers that use these forms must pass
the option when constructing the parser, including parsers passed to `vm.Build`.

| Option | Without the option | What it enables |
|---|---|---|
| `WithLabels()` | Label declarations and symbolic `skipto` are rejected | `:NAME` declarations and `skipto :NAME` jumps |
| `WithCommandHook(hook)` | Unknown command lines are rejected | The hook parses unknown commands using the existing sub-parsers |
| `WithOptionHook(hook)` | Unknown rule options are rejected | The hook parses unknown option keywords and their arguments |
| `WithProtoChecker(checker)` | A rule body's grammar goes by its shape | The first protocol selects a legacy or option-only body, as in FreeBSD |

`Reset` retains the configured options. Hooks own the syntax they consume and must report
how much input they used. Enabled built-in syntax takes precedence over command hooks.
A command hook can supply a `RecordLabel` explicitly when built-in labels are disabled.

Numeric `skipto`, `skipto tablearg`, `check-state :flow` and `keep-state :flow` keep their
default behavior. FreeBSD supports numbered jumps and named dynamic states. Symbolic rule
labels are a project extension. See the upstream
[jump syntax](https://github.com/freebsd/freebsd-src/blob/88e7371d9dc26f85dfc1b008cbe59ebc7e4a33da/sbin/ipfw/ipfw.8#L1062)
and [named state syntax](https://github.com/freebsd/freebsd-src/blob/88e7371d9dc26f85dfc1b008cbe59ebc7e4a33da/sbin/ipfw/ipfw2.c#L4338).

Table values remain raw text, including `:NEXT` and `::1`. In the VM, a numeric tablearg
value names a rule number, and a symbolic one can resolve to a label supplied by an enabled
declaration or a command hook. It does not need a separate VM option. See
`ExampleBuild_labels`.

## Errors

A line the grammar does not accept is a `*ParseError` carrying the line, the column and the text, which `Diag` renders:

```
error: unknown option
  --> fw.conf:2:42
   |
 2 | add pass tcp from 192.0.2.0/24 to any 22 frobnicate
   |                                          ^^^^^^^^^^
```

`WithDiagStyle(ipfw.DiagStyleFor(os.Stderr))` colours it when a terminal is watching and leaves it plain when the output is a file. `WithDiagWidth` cuts a long line around the caret.

## Serialization

A `Formatter` renders records you collected back into canonical ruleset text: aliases folded (`allow` into `pass`), whitespace and line endings normalized, address lists under one negation, ICMP types ascending, TCP flags in a fixed order. Canonical output is parse-equivalent rather than byte-for-byte equal to the source, and formatting canonical output again returns identical bytes.

```go
parser := ipfw.NewParser(src)
var state ipfw.ReduceState
var ruleset []ipfw.ParsedRecord
for {
	rec, err := parser.Next(&state)
	if err != nil {
		return err
	}
	if rec.Kind == ipfw.RecordEOF {
		break
	}
	ruleset = append(ruleset, ipfw.NewParsedRecord(rec, &state))
	state.Reset()
}
text, err := ipfw.NewFormatter().AppendRuleset(nil, ruleset)
```

Both the record and the body belong to the parser and the state, so `NewParsedRecord` copies them before the next `Next` call and remembers whether an instruction used a legacy, native option-only, or comment-only body. Collecting a ruleset allocates by design; `AppendRecord` and `AppendRuleset` themselves append without allocating once the destination has capacity. A value the parser cannot produce — an unknown kind, a broken `or` chain, a stray field — is rejected with an `ErrorKind`. On error, the append methods preserve the destination's length and visible bytes, though unused capacity may contain attempted output. `WithCustomOptAppender` reconstructs `OptCustom` and a hook-produced option whose built-in spelling cannot preserve its position, such as a grouped `OptComment`.

Replaying accepted input is the other direction: every `Record.Text` holds its line without leading and trailing whitespace, so appending the texts with a newline per record plays the accepted lines back. The whitespace the parser trimmed stays gone, and the replay always ends with a newline the source may not have had. See `ExampleFormatter_AppendRuleset`.

## Names into values

A `Resolver` is the `State` that resolves every name within an `Environment` — networks into the caller's own types, protocols and services into numbers, hostnames and custom targets into the networks they stand for — and hands the typed tokens to a `VMState`, which `ReduceVMState` collects. A name no resolver turns into a value fails the line where the name stands.

Plugging [xnetip](https://github.com/yanet-platform/xnetip) in is one literal:

```go
env := ipfw.Environment[xnetip.Network4, xnetip.Network6]{
	Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
		Parse4: xnetip.ParseNetwork4,
		Parse6: xnetip.ParseNetwork6,
	},
	Protos:   protocols, // ipfw.ProtoResolver, e.g. /etc/protocols
	Services: services,  // ipfw.ServiceResolver, e.g. /etc/services
	Targets:  hosts,     // ipfw.TargetResolver: names → networks
}
var typed ipfw.ReduceVMState[xnetip.Network4, xnetip.Network6]
rec, err := ipfw.NewParser(src).Next(ipfw.NewResolver(&typed, env))
```

See `ExampleNewResolver`.

## The virtual machine

`vm.Build` reads a whole ruleset into a `VM` and `Check` runs a packet through it. What the packet bytes do not carry — the direction, the interface, the host's own addresses for `me` and `me6` — travels in a `Context` next to the packet.

```go
machine, err := vm.Build(ipfw.NewParser(src), vm.Config[xnetip.Network4, xnetip.Network6]{
	Environment:    env,
	DefaultVerdict: ipfw.Action{Kind: ipfw.ActionDeny}, // the zero value means deny
})
ctx := &vm.Context{
	Direction:  vm.In,
	IfName:     "vlan42",
	LocalAddrs: localAddrs,
}
packet := vm.NewIPv4Packet(src, dst).WithTCP(ipfw.TCPSyn, 40000, 22) // or your own vm.Packet
verdict := machine.Check(ctx, packet)                                // ipfw.Action: pass or deny
action, matched := machine.CheckTrace(ctx, packet, tracer)           // every rule evaluated
```

A rule without a number is numbered one past the previous rule, where FreeBSD adds `net.inet.ip.fw.autoinc_step`, 100 by default: rulesets that leave most rules unnumbered and number a few, as YANET rulesets do, rely on it. An explicit number may not go back. A numeric `skipto`, and a `skipto tablearg` whose table value is a number, lands as in FreeBSD on the first later rule numbered at or after the target, the next rule when the target is not past the jumping rule's own number. A static jump no later rule reaches is a build error, or falls through under `UnresolvedJumpsFallThrough`, and a tablearg one ends the search with the default verdict.

A `table NAME create type` line says what the keys of the table are: an address table takes networks and, through the target resolver, hostnames and custom targets, an interface table takes interface names. A table never created is an address table, as in `ipfw(8)`. An address lookup finds the most specific network holding the address, as the radix tables of FreeBSD do, so a network type gives its `NumHostBits` next to `ContainsAddr`. A `skipto tablearg` jumps where the entry of the last lookup of the rule that found one says, looked up as `ipfw_chk` does: the source address, then the destination, then the options in order.

`Packet` is an interface over the header fields the matchers read, so a structure of your own, a decoded protobuf message for one, is checked without copying. The VM decides which fields mean something, as `ipfw_chk` does: it asks for ports only of TCP, UDP, SCTP and UDP-Lite, for flags only of TCP, for the type only of ICMP and ICMPv6, and for none of them on a non-first fragment, so an implementation just reports what its headers hold. `RawIPv4Packet` and `RawIPv6Packet` implement it over raw bytes, read the way `ipfw_chk` reads them: past IPv4 options and IPv6 extension headers, an IPv6 fragment header included. `NewIPv4Packet`, `NewIPv6Packet` and their `With` methods build such packets for tests, each returning a copy. See `ExampleBuild` and `ExampleVM_CheckTrace`.

## Extension points

Everything the format leaves to the site — what a name means, what a keyword the grammar does not know is — is yours to supply.

**Names**

| | |
|---|---|
| `NetworkParser` | network text into your own types, `NetworkParserFuncs` to plug a library in one literal |
| `ProtoResolver` | protocol names into numbers |
| `ServiceResolver` | service names into ports |
| `TargetResolver` | a hostname or custom target into any number of networks of both families |

**Grammar**

| | |
|---|---|
| `WithCommandHook` | a line the grammar does not know, the hook parsing it out of the exported sub-parsers |
| `WithOptionHook` | an option the grammar does not know, the hook consuming its arguments |
| `WithProtoChecker` | which names are protocols, choosing between a legacy and an option-only rule body |
| `State`, `VMState` | your own consumer of the tokens, raw or typed |

**Evaluation**

| | |
|---|---|
| `vm.Config.OptionMatcher` | what a custom option means to a packet |
| `vm.TableRegistry` | where tables live, `vm.DefaultTableRegistry` being the one a build fills |
| `vm.Config.UnresolvedJumps` | a jump nothing satisfies: an error at build, or a fall-through |
| `vm.Tracer` | every rule a check evaluates |

## Performance

The parse path, per line, and the match path, per packet, allocate nothing, which `testing.AllocsPerRun` guards. Building a VM allocates.

| | |
|---|---|
| the simplest rule | 0.4 µs |
| a rule with ten networks | 1.3 µs |
| a rule with ten options | 2.6 µs |
| a rule that does not match a packet | 30 ns |
| a check whose first rule matches | 90 ns |
| a thousand jumps | 41 µs |
| a ruleset of 10k lines, built | 34 ms |

Over a production ruleset of 27 MB and 115k rules the parser runs at 184 MB/s without allocating, the VM builds in 0.3 s, and a packet that matches nothing is checked against every rule in 2.2 ms. Keep the packet as a `vm.Packet` value across checks: turning a raw byte slice into the interface on every call is the one allocation a check can incur.

```sh
make test        # go test -race ./...
make lint        # gofumpt, go vet, golangci-lint, gopls hints
make bench       # compile and smoke-run every benchmark
make bench-run   # measure, feed to benchstat
make fuzz        # every fuzz target briefly
```
