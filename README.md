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
a warmed-up state costs no allocation. A resolving state also supplies the protocol knowledge
used to choose between legacy and option-only rule bodies.

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

Rules can use existing options as the complete body by default, as in
[FreeBSD](https://github.com/freebsd/freebsd-src/blob/2350f75acb0da0271ccff1fb22381f7e8c5948f8/sbin/ipfw/ipfw.8#L1371).
For example, `add 110 allow in proto tcp via vlan17` matches incoming TCP packets of either
address family on `vlan17`. Without a legacy header, omitted protocols and addresses impose no
restriction: the parser emits no `OnIPProto` or `OnProto` callbacks, then emits one `TargetAny`
source and one `TargetAny` destination before the options.
Ordinary actions still require a body, which may consist of a `//` comment.

When the supplied `State` implements `ProtoResolver`, as `Resolver` does, the first protocol
selects the grammar, following
[FreeBSD's criterion](https://github.com/freebsd/freebsd-src/blob/a54f83544eea2a9804ac7940d35b26ffcb34dfb3/sbin/ipfw/ipfw2.c#L4937).
An IP keyword, a numeric protocol or a resolved name commits to the legacy grammar, even if
`from` is missing. An unknown first name selects options. An unknown later protocol in a
group, or a rejected state callback, remains an error without trying another grammar.
Thus `add allow in` requires a legacy header if the environment defines a protocol named `in`.
Unknown initial names use option diagnostics, including when no protocol resolver is configured.
For example, an unresolved `tcp` at the start produces `ErrUnknownOption`. Protocol names inside
a selected legacy header or a `proto` option still produce `ErrUnresolvedProto` when unknown.

A raw `State` such as `ReduceState` has no protocol registry. A complete
`PROTO from SRC [PORT] to DST` header takes precedence over options. Otherwise a recognized
option start selects options, and other starts select legacy parsing. Thus
`add 160 allow in from any to any` keeps `in` as a protocol name, while `add allow tcp` reports
an incomplete legacy header.

Wrappers around a resolving state must forward `ResolveProto` along with the `State` callbacks
to preserve grammar selection. Embedding only the `State` interface hides this capability.

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

`Reset` retains the configured options. Hooks own the syntax they consume and must report
how much input they used. Enabled built-in syntax takes precedence over command hooks.
A command hook can supply a `RecordLabel` explicitly when built-in labels are disabled.

Numeric `skipto`, `skipto tablearg`, `check-state :flow` and `keep-state :flow` keep their
default behavior. FreeBSD supports numbered jumps and named dynamic states. Symbolic rule
labels are a project extension. See the upstream
[jump syntax](https://github.com/freebsd/freebsd-src/blob/88e7371d9dc26f85dfc1b008cbe59ebc7e4a33da/sbin/ipfw/ipfw.8#L1062)
and [named state syntax](https://github.com/freebsd/freebsd-src/blob/88e7371d9dc26f85dfc1b008cbe59ebc7e4a33da/sbin/ipfw/ipfw2.c#L4338).

Table values remain raw text, including `:NEXT` and `::1`. In the VM, a symbolic tablearg
can resolve to a label supplied by an enabled declaration or a command hook. It does not need
a separate VM option. See `ExampleBuild_labels`.

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

A `table NAME create type` line says what the keys of the table are: an address table takes networks and, through the target resolver, hostnames and custom targets, an interface table takes interface names. A table never created is an address table, as in `ipfw(8)`.

`Packet` is an interface over the fields the matchers read. `RawIPv4Packet` and `RawIPv6Packet` implement it over raw bytes and double as builders in tests. See `ExampleBuild` and `ExampleVM_CheckTrace`.

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
