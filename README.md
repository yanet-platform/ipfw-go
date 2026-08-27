# ipfw

A Go port of the Rust [`ipfw`](../ipfw) crate: a streaming, zero-copy parser for the FreeBSD/macOS [`ipfw(8)`](https://man.freebsd.org/cgi/man.cgi?ipfw(8)) ruleset format and a virtual machine that evaluates a packet against the ruleset. Runtime code uses the standard library only.

```sh
go get github.com/yanet-platform/ipfw
```

## Parsing

The parser reads one line at a time, returns a `Record` for it and pushes the rule body — protocols, targets, ports, options — as string sub-slices of the input into a `State`. `ReduceState` collects them, `DiscardState` drops them.

```go
parser := ipfw.NewParser("add 100 deny log tcp from 192.0.2.0/24 to any 22 // bots\nadd pass ip from any to any\n")
var state ipfw.ReduceState
for {
	rec, err := parser.Next(&state) // err is a *ipfw.ParseError with line, column and text
	if err != nil {
		fmt.Println(ipfw.NewDiagnostic(err)) // rustc-style rendering
		return
	}
	if rec.Kind == ipfw.RecordEOF {
		break
	}
	fmt.Println(rec.Line, rec.Instruction.Action, state.Sources, state.DestinationPorts, state.Options)
	state.Reset()
}
```

Every token keeps its text: a network is `Target{Kind: TargetNetwork4, Text: "192.0.2.0/24"}`, a service is `Port{Name: "ssh"}`. Nothing is resolved or validated beyond the grammar, so the parser needs no network library. See `ExampleParser_Next`.

## Names into values

A `Resolver` is a `State` that resolves every name within an `Environment` and hands typed tokens to a `VMState`: networks in the caller's own types, protocols and services as numbers, hostnames and macros as the networks they stand for. `ReduceVMState` collects them; a nil resolver makes the names it would resolve a positioned error. Plugging [xnetip](https://github.com/yanet-platform/xnetip) in is one literal:

```go
env := ipfw.Environment[xnetip.Network4, xnetip.Network6]{
	Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
		Parse4: xnetip.ParseNetwork4, Parse6: xnetip.ParseNetwork6,
		FromAddr4: xnetip.Network4FromAddr, FromAddr6: xnetip.Network6FromAddr,
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

`vm.Build` reads the whole ruleset into a `VM`; `Check` runs a packet through it. What the packet bytes do not carry — the direction, the interface, the host's own addresses for `me`/`me6` — travels in a `Context` next to the packet.

```go
machine, err := vm.Build(ipfw.NewParser(src), vm.Config[xnetip.Network4, xnetip.Network6]{
	Environment:    env,
	DefaultVerdict: ipfw.Action{Kind: ipfw.ActionDeny}, // the zero value means deny
})
ctx := &vm.Context{Direction: vm.In, IfName: "vlan42", LocalAddrs: localAddrs}
packet := vm.NewIPv4Packet(src, dst).WithTCP(ipfw.TCPSyn, 40000, 22) // or your own vm.Packet
verdict := machine.Check(ctx, packet)                                // ipfw.Action: pass or deny
action, matched := machine.CheckTrace(ctx, packet, tracer)           // every rule evaluated
```

`Packet` is an interface over the fields the matchers read; `RawIPv4Packet` and `RawIPv6Packet` implement it over raw bytes and double as builders in tests. See `ExampleBuild` and `ExampleVM_CheckTrace` in package `vm`.

## Extension points

| What | Where |
|------|-------|
| network types and parsers | `ipfw.NetworkParser` or `ipfw.NetworkParserFuncs` |
| protocol and service names | `ipfw.ProtoResolver`, `ipfw.ServiceResolver` |
| hostnames and macros (`_NAME_`) | `ipfw.TargetResolver`: one name → any number of networks of both families |
| custom commands | `ipfw.WithCommandHook`: the hook parses the line, may call the exported sub-parsers |
| custom options | `ipfw.WithOptionHook` on the parser and `vm.Config.OptionMatcher` at check time |
| tables | `vm.TableRegistry`, `vm.Tables` as the default, may be pre-filled or changed after the build |
| unresolved jumps | `vm.Config.UnresolvedJumps`: an error at build or a fall-through |
| tracing | `vm.Tracer` per rule evaluated |
| your own consumer | implement `ipfw.State` (raw tokens) or `ipfw.VMState` (typed) |

## Supported syntax

- `add [N] ACTION [log [logamount N]] [tag N] BODY [// comment]` with the actions `allow|accept|pass|permit`, `deny|drop`, `count`, `skipto :LABEL|N|tablearg`, `check-state [:flow]`.
- Protocols by name or number, `ip|all|ip4|ipv4|ip6|ipv6`, `not`, `{ a or b }`.
- Targets `any`, `me`, `me6`, networks of both families, hostnames (plain and `` `quoted' ``), `table(NAME)`, macros as custom tokens, `not`, `{ a or b }`.
- Ports and ranges by number or service name, comma lists, `not`, `ftp\-data` escapes.
- Options `in`, `out`, `established`, `frag`, `diverted`, `antispoof`, `keep-state [:flow]`, `icmptypes`, `icmp6types`, `tcpflags`, `src-port`, `dst-port`, `proto`, `via NAME|MASK|table(NAME[,VALUE])`, `not`, `{ a or b }` groups, custom options through the hook.
- `table NAME create [type T]`, `table NAME add KEY [VALUE]` with network and interface keys, `:LABEL` lines, `#` comments.

## Deviations

From the Rust crate: no panics — every misuse is a positioned `*ParseError` or a `vm.BuildError`; names are resolved by the consumer's resolvers (an unresolvable one is an error, a name standing for no network never matches); `not a,b` on a port list and `not host` on a multi-address name mean "none of them"; a non-first IPv4 fragment carries no transport header; the VM never loops (jumps go forward only); the default verdict is configurable; the Rust `extra` feature (macros, `inet`, `ALLOW_FROM_*` commands) is not built in but representable through the hooks and resolvers.

From FreeBSD: `skipto N` needs a rule numbered exactly `N`; the VM is stateless, so `keep-state` and `check-state` keep and check nothing (a matching `keep-state` rule simply matches, `check-state` never does); `diverted` never matches, `antispoof` matches outgoing packets only; actions beyond the five above are rejected.

## Performance

The parse path (per line) and the match path (per packet) allocate nothing, which `testing.AllocsPerRun` guards. Building a VM allocates. On a developer box: the simplest rule parses in about 0.4 µs, a rule with ten networks in 1.4 µs, one with ten options in 3 µs; a check costs about 45 ns per rule that does not match and 75 ns when the first rule matches, a thousand jumps 66 µs; a 10k-line ruleset builds in 36 ms. Over the Rust crate's production corpus (27 MB, 115k rules) the parser runs at 184 MB/s without allocating, the VM builds in 0.4 s and a packet that matches nothing is checked against every rule in 8 ms. Keep the packet as a `vm.Packet` value across checks: converting a raw byte slice to the interface on every call is the one allocation a check can incur.

```sh
make test        # go test -race ./...
make lint        # gofumpt, go vet, golangci-lint, gopls hints, gocommentlint
make bench       # compile and smoke-run every benchmark
make bench-run   # measure, feed to benchstat
make fuzz        # every fuzz target briefly
```

The corpus tests and benchmarks (`Test_Corpus_*`, `Benchmark_Corpus_*`) read `../ipfw/.assets` and the system protocol and service databases, and skip when those are absent.
