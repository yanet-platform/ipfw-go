# ipfw-go

A streaming parser for the FreeBSD/macOS [`ipfw(8)`](https://man.freebsd.org/cgi/man.cgi?ipfw(8)) ruleset format and a virtual machine that evaluates a packet against the ruleset. The runtime uses the standard library only.

```sh
go get github.com/yanet-platform/ipfw-go
```

Licensed under the Apache License 2.0, see [LICENSE](LICENSE).

## What it gives you

- **Nothing allocates on the hot paths.** Parsing a line and checking a packet allocate zero bytes, and `testing.AllocsPerRun` guards both. The input is one string and every token is a sub-slice of it, so a 27 MB ruleset parses at 184 MB/s without touching the heap.
- **No dependencies.** The runtime is the standard library. Tests reach for testify, rapid and xnetip, your build does not.
- **Your network types, not ours.** The typed layer is generic over the IPv4 and IPv6 types you already use, plugged in with a literal. Nothing forces a wrapper on you.
- **Strict parsing with errors that point.** No token is dropped or guessed. A line that does not fit the grammar is a `*ParseError` with a line, a column and the text, rendered by `Diag` with a caret under the offending token, coloured when a terminal is watching.
- **Names are yours to resolve.** Protocols, services, hostnames and macros go through your resolvers, so `/etc/services`, a DNS cache or a macro expander plug in where you need them, and an unresolvable name fails the line instead of matching quietly.
- **The grammar is extensible.** A command or an option the format does not know goes to a hook that reuses the exported sub-parsers, and the VM asks your matcher what it means.
- **A virtual machine, not only a parser.** Build a ruleset once and check packets against it: protocols, addresses, ports, tables, interfaces, ICMP types, TCP flags, jumps and labels, a configurable default verdict, and a tracer that reports every rule a check evaluated.
- **Tested where it counts.** Property tests, fuzzing with a checked-in corpus, allocation guards, race tests, and regression runs over production rulesets of 115k rules.

## How it fits together

```
        ipfw.Parser ─────────────► ipfw.State ────────────► ipfw.Resolver ──────► ipfw.VMState
        one line at a time         raw tokens of the        names into values     numbers and
        │                          rule body                within an             networks
        └─► ipfw.Record            (ReduceState collects,   Environment           (vm builds
            what the line is       DiscardState drops)                            from these)
```

The parser knows the grammar and nothing else. It never parses an address, never resolves a name, and every token it hands over is a sub-slice of the input, so a line costs no allocation at all. Turning text into values is the next layer's business, and evaluating packets the layer after that.

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

A `Resolver` is the `State` that resolves every name within an `Environment` — networks into the caller's own types, protocols and services into numbers, hostnames and macros into the networks they stand for — and hands the typed tokens to a `VMState`, which `ReduceVMState` collects. A name no resolver turns into a value fails the line where the name stands.

Plugging [xnetip](https://github.com/yanet-platform/xnetip) in is one literal:

```go
env := ipfw.Environment[xnetip.Network4, xnetip.Network6]{
	Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
		Parse4:    xnetip.ParseNetwork4,
		Parse6:    xnetip.ParseNetwork6,
		FromAddr4: xnetip.Network4FromAddr,
		FromAddr6: xnetip.Network6FromAddr,
	},
	Protos:   protocols, // ipfw.ProtoResolver, e.g. /etc/protocols
	Services: services,  // ipfw.ServiceResolver, e.g. /etc/services
	Targets:  hosts,     // ipfw.TargetResolver: hostnames and macros → networks
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

`Packet` is an interface over the fields the matchers read. `RawIPv4Packet` and `RawIPv6Packet` implement it over raw bytes and double as builders in tests. See `ExampleBuild` and `ExampleVM_CheckTrace`.

## Extension points

Everything the format leaves to the site — what a name means, what a keyword the grammar does not know is — is yours to supply.

**Names**

| | |
|---|---|
| `NetworkParser` | network text into your own types, `NetworkParserFuncs` to plug a library in one literal |
| `ProtoResolver` | protocol names into numbers |
| `ServiceResolver` | service names into ports |
| `TargetResolver` | a hostname or a macro into any number of networks of both families |

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
make lint        # gofumpt, go vet, golangci-lint, gopls hints, gocommentlint
make bench       # compile and smoke-run every benchmark
make bench-run   # measure, feed to benchstat
make fuzz        # every fuzz target briefly
```
