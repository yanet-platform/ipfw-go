package vm_test

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw-go"
	"github.com/yanet-platform/ipfw-go/vm"
)

type (
	net4 = xnetip.Network4
	net6 = xnetip.Network6
)

type networkParserError struct {
	text string
}

func (m *networkParserError) Error() string {
	return m.text
}

// nets plugs xnetip into the VM.
var nets = ipfw.NetworkParserFuncs[net4, net6]{
	Parse4: xnetip.ParseNetwork4,
	Parse6: xnetip.ParseNetwork6,
}

// fakeProtos resolves the three protocol names the tests use.
type fakeProtos struct{}

// ResolveProto implements ipfw.ProtoResolver.
func (fakeProtos) ResolveProto(name string) (uint8, bool) {
	switch name {
	case "icmp":
		return 1, true
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	}
	return 0, false
}

// protoChecker knows the protocols the resolver resolves.
func protoChecker(resolver ipfw.ProtoResolver) ipfw.ProtoCheckerFunc {
	return func(name string) bool {
		_, ok := resolver.ResolveProto(name)
		return ok
	}
}

// fakeServices resolves the two service names the tests use.
type fakeServices struct{}

// ResolveService implements ipfw.ServiceResolver.
func (fakeServices) ResolveService(name string) (uint16, bool) {
	switch name {
	case "ssh":
		return 22, true
	case "smtp":
		return 25, true
	}
	return 0, false
}

// fakeTargets stands one hostname for a network of each family, `custom:first` for
// two IPv4 networks and the empty hostnames for nothing.
type fakeTargets struct{}

// ResolveTarget implements ipfw.TargetResolver.
func (fakeTargets) ResolveTarget(target ipfw.Target) ([]net4, []net6, error) {
	switch target.Text {
	case "host.example.com":
		return []net4{parse4("192.0.2.1/32")}, []net6{parse6("2001:db8::1/128")}, nil
	case "custom:first":
		return []net4{parse4("192.0.2.0/24"), parse4("198.51.100.0/24")}, nil, nil
	case "nothing.example.com", "empty.example.com":
		return nil, nil, nil
	}
	return nil, nil, ipfw.ErrExpectedTarget
}

// parse4 parses an IPv4 network the test wrote itself.
func parse4(s string) net4 {
	network, err := xnetip.ParseNetwork4(s)
	if err != nil {
		panic(err)
	}
	return network
}

// parse6 parses an IPv6 network the test wrote itself.
func parse6(s string) net6 {
	network, err := xnetip.ParseNetwork6(s)
	if err != nil {
		panic(err)
	}
	return network
}

// resolving parses networks with xnetip and resolves the fake protocols.
var resolving = ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}}

// resolvingTargets is resolving with the fake targets too.
var resolvingTargets = ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}, Targets: fakeTargets{}}

// resolvingServices is resolving with the fake services too.
var resolvingServices = ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}, Services: fakeServices{}}

// networksOnly parses networks and resolves no name.
var networksOnly = ipfw.Environment[net4, net6]{Networks: nets}

// none is the configuration with nothing set.
var none = vm.Config[net4, net6]{}

// ruleset drops the newline after the opening backtick of an indented rule
// literal, so that the lines of a trace count from the first rule.
func ruleset(text string) string {
	return strings.TrimPrefix(text, "\n")
}

// build builds a VM from src with the fake resolvers, failing the test on
// any error.
func build(
	t *testing.T,
	src string,
	cfg vm.Config[net4, net6],
	options ...ipfw.ParserOption,
) *vm.VM[net4, net6] {
	t.Helper()
	cfg.Environment = resolving
	machine, err := vm.Build(ipfw.NewParser(src, options...), cfg)
	require.NoError(t, err)
	return machine
}

var (
	pass = ipfw.Action{Kind: ipfw.ActionPass}
	deny = ipfw.Action{Kind: ipfw.ActionDeny}
)

// tcp4 is a TCP SYN from src to dst over IPv4.
func tcp4(src, dst string) vm.Packet {
	return vm.NewIPv4Packet(netip.MustParseAddr(src), netip.MustParseAddr(dst)).WithTCP(ipfw.TCPSyn, 50000, 22)
}

// raw6 is an IPv6 packet laid out by hand, for the addresses the builder
// rejects on purpose, such as an IPv4-mapped one.
func raw6(src, dst string) vm.RawIPv6Packet {
	packet := make(vm.RawIPv6Packet, 64)
	packet[0], packet[6] = 6<<4, 59
	from, to := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(packet[8:24], from[:])
	copy(packet[24:40], to[:])
	return packet
}

// verifies the compat matchers over two-rule rulesets: the protocol, the
// source, the destination and both, for IPv4 and IPv6 packets.
func Test_VM_Check_Compat(t *testing.T) {
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "IPv4 by protocol, tcp",
			rules: ruleset(`
				add pass tcp from any to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name: "IPv4 by protocol, other",
			rules: ruleset(`
				add pass tcp from any to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")),
			verdict: deny,
		},
		{
			name: "IPv6 by protocol, tcp",
			rules: ruleset(`
				add pass tcp from any to any
				add deny ip from any to any
			`),
			packet: vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::1")).
				WithTCP(ipfw.TCPSyn, 50000, 22),
			verdict: pass,
		},
		{
			name: "IPv6 by protocol, other",
			rules: ruleset(`
				add pass tcp from any to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::1")),
			verdict: deny,
		},
		{
			name: "by source address, match",
			rules: ruleset(`
				add pass tcp from 192.0.2.1 to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name: "by source address, mismatch",
			rules: ruleset(`
				add pass tcp from 192.0.2.1 to any
				add deny ip from any to any
			`),
			packet:  tcp4("198.51.100.1", "192.0.2.1"),
			verdict: deny,
		},
		{
			name: "by destination address, match",
			rules: ruleset(`
				add pass tcp from any to 192.0.2.1
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name: "by destination address, mismatch",
			rules: ruleset(`
				add pass tcp from any to 192.0.2.1
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "198.51.100.1"),
			verdict: deny,
		},
		{
			name: "by both addresses, match",
			rules: ruleset(`
				add pass tcp from 192.0.2.1 to 192.0.2.1
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name: "by both addresses, mismatch",
			rules: ruleset(`
				add pass tcp from 192.0.2.1 to 192.0.2.1
				add deny ip from any to any
			`),
			packet:  tcp4("198.51.100.1", "192.0.2.1"),
			verdict: deny,
		},
		{
			name: "network and negation",
			rules: ruleset(`
				add deny ip from not 192.0.2.0/24 to any
				add pass ip from 192.0.2.0/24 to { 2001:db8::/32 or 198.51.100.0/24 }
			`),
			packet:  tcp4("192.0.2.77", "198.51.100.9"),
			verdict: pass,
		},
		{
			name: "IPv4 network never matches an IPv6 packet",
			rules: ruleset(`
				add pass ip from 0.0.0.0/0 to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: deny,
		},
		{
			name: "ip6 keyword against an IPv4 packet",
			rules: ruleset(`
				add pass ip6 from any to any
				add deny ip4 from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that `ip` has no transport predicate, including for protocol zero.
func Test_VM_Check_IPMatchesProtocolZero(t *testing.T) {
	src := ruleset(`
		add pass ip from any to any
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	packet := vm.NewIPv4Packet(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	)
	require.Equal(t, pass, machine.Check(&vm.Context{}, packet))
}

// verifies that an option-only rule restricts direction, protocol and interface in both families.
func Test_VM_Check_OptionOnly(t *testing.T) {
	machine := build(t, "add 610 allow in proto tcp via vlan17", none)
	cases := []struct {
		name    string
		packet  vm.Packet
		context vm.Context
		verdict ipfw.Action
	}{
		{
			name:    "matching IPv4 TCP",
			packet:  tcp4("192.0.2.1", "198.51.100.1"),
			context: vm.Context{Direction: vm.In, IfName: "vlan17"},
			verdict: pass,
		},
		{
			name: "matching IPv6 TCP",
			packet: vm.NewIPv6Packet(
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("2001:db8::2"),
			).WithTCP(ipfw.TCPSyn, 40000, 443),
			context: vm.Context{Direction: vm.In, IfName: "vlan17"},
			verdict: pass,
		},
		{
			name:    "outgoing TCP",
			packet:  tcp4("192.0.2.1", "198.51.100.1"),
			context: vm.Context{Direction: vm.Out, IfName: "vlan17"},
			verdict: deny,
		},
		{
			name: "incoming UDP",
			packet: vm.NewIPv4Packet(
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("198.51.100.1"),
			).WithUDP(40000, 443),
			context: vm.Context{Direction: vm.In, IfName: "vlan17"},
			verdict: deny,
		},
		{
			name:    "TCP on another interface",
			packet:  tcp4("192.0.2.1", "198.51.100.1"),
			context: vm.Context{Direction: vm.In, IfName: "vlan18"},
			verdict: deny,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.verdict, machine.Check(&test.context, test.packet))
		})
	}
}

// verifies that nothing matching yields the default verdict, deny unless
// configured, while tracing reports no rule termination.
func Test_VM_Check_DefaultVerdict(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.1")
	empty := build(t, "", none)
	require.Equal(t, deny, empty.Check(&vm.Context{}, packet))
	require.Equal(t, 0, empty.Len())
	action, terminated := empty.CheckTrace(&vm.Context{}, packet, nopTracer{})
	require.False(t, terminated)
	require.Equal(t, deny, action)

	permissive := build(t, "add deny udp from any to any\n", vm.Config[net4, net6]{DefaultVerdict: pass})
	require.Equal(t, pass, permissive.Check(&vm.Context{}, packet))
	action, terminated = permissive.CheckTrace(&vm.Context{}, packet, nopTracer{})
	require.False(t, terminated)
	require.Equal(t, pass, action)
}

// verifies that the zero configuration and every declared option value pass
// standalone validation.
func Test_Config_Validate_DeclaredValues(t *testing.T) {
	cases := []struct {
		name   string
		config vm.Config[net4, net6]
	}{
		{name: "zero configuration"},
		{
			name: "pass and unresolved-jump error",
			config: vm.Config[net4, net6]{
				DefaultVerdict:  pass,
				UnresolvedJumps: vm.UnresolvedJumpsError,
			},
		},
		{
			name: "deny and unresolved-jump fallthrough",
			config: vm.Config[net4, net6]{
				DefaultVerdict:  deny,
				UnresolvedJumps: vm.UnresolvedJumpsFallThrough,
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			require.NoError(t, testCase.config.Validate())
		})
	}
}

// verifies that invalid configuration is rejected before the parser or table
// registry is touched.
func Test_VM_Build_InvalidConfig(t *testing.T) {
	cases := []struct {
		name    string
		config  vm.Config[net4, net6]
		message string
	}{
		{
			name:    "count default verdict",
			config:  vm.Config[net4, net6]{DefaultVerdict: ipfw.Action{Kind: ipfw.ActionCount}},
			message: "invalid configuration: default verdict action kind 3 is not terminal",
		},
		{
			name:    "skipto default verdict",
			config:  vm.Config[net4, net6]{DefaultVerdict: ipfw.Action{Kind: ipfw.ActionSkipTo}},
			message: "invalid configuration: default verdict action kind 4 is not terminal",
		},
		{
			name: "check-state default verdict",
			config: vm.Config[net4, net6]{
				DefaultVerdict: ipfw.Action{Kind: ipfw.ActionCheckState},
			},
			message: "invalid configuration: default verdict action kind 5 is not terminal",
		},
		{
			name:    "unknown default verdict",
			config:  vm.Config[net4, net6]{DefaultVerdict: ipfw.Action{Kind: 255}},
			message: "invalid configuration: default verdict action kind 255 is not terminal",
		},
		{
			name: "unknown unresolved jump policy",
			config: vm.Config[net4, net6]{
				UnresolvedJumps: vm.UnresolvedJumps(255),
			},
			message: "invalid configuration: unresolved jumps policy 255 is unknown",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			const source = "table t add 192.0.2.0/24\n"
			validationErr := testCase.config.Validate()
			require.ErrorIs(t, validationErr, vm.ErrInvalidConfig)
			require.EqualError(t, validationErr, testCase.message)

			parser := ipfw.NewParser(source)
			tables := vm.NewDefaultTableRegistry[net4, net6]()
			testCase.config.Environment = resolving
			testCase.config.Tables = tables

			machine, err := vm.Build(parser, testCase.config)
			require.Nil(t, machine)
			require.ErrorIs(t, err, vm.ErrInvalidConfig)
			require.EqualError(t, err, testCase.message)
			_, ok := tables.LookupNetwork("t", netip.MustParseAddr("192.0.2.1"))
			require.False(t, ok)

			record, parseErr := parser.Next(ipfw.DiscardState{})
			require.Nil(t, parseErr)
			require.Equal(t, ipfw.Record{
				Line: 1,
				Text: "table t add 192.0.2.0/24",
				Kind: ipfw.RecordTable,
				Table: ipfw.Table{
					Name: "t",
					Kind: ipfw.TableAdd,
					Key: ipfw.TableKey{
						Kind: ipfw.TableKeyNetwork4,
						Text: "192.0.2.0/24",
					},
				},
			}, *record)
		})
	}
}

// nopTracer ignores every rule.
type nopTracer struct{}

// Trace implements vm.Tracer.
func (nopTracer) Trace(*ipfw.Record, ipfw.Action, bool) {}

// traced is one rule seen by the recording tracer.
type traced struct {
	line    int
	action  ipfw.ActionKind
	matched bool
}

// recordingTracer keeps every rule it sees.
type recordingTracer struct {
	seen []traced
}

// Trace implements vm.Tracer.
func (m *recordingTracer) Trace(rec *ipfw.Record, action ipfw.Action, matched bool) {
	m.seen = append(m.seen, traced{line: rec.Line, action: action.Kind, matched: matched})
}

// verifies that the tracer sees every rule up to the terminating one with
// its match flag, and every rule when none terminates.
func Test_VM_CheckTrace_ReportsEveryOp(t *testing.T) {
	src := ruleset(`
		add deny udp from any to any
		# c
		add deny ip from 198.51.100.0/24 to any
		add pass tcp from any to any
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	require.Equal(t, 4, machine.Len())

	tracer := &recordingTracer{}
	action, matched := machine.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1"), tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionDeny, matched: false},
		{line: 3, action: ipfw.ActionDeny, matched: false},
		{line: 4, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)

	tracer = &recordingTracer{}
	icmp := vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")).WithICMP6(128, 0)
	_, matched = build(t, "add pass tcp from any to any\n", none).CheckTrace(&vm.Context{}, icmp, tracer)
	require.False(t, matched)
	require.Equal(t, []traced{{line: 1, action: ipfw.ActionPass, matched: false}}, tracer.seen)
}

// verifies that a matching count rule is traced as matched and the search
// goes on with the next rule.
func Test_VM_Check_Count(t *testing.T) {
	src := ruleset(`
		add count ip from any to any
		add count tcp from 198.51.100.0/24 to any
		add pass ip from any to any
	`)
	machine := build(t, src, none)
	tracer := &recordingTracer{}
	action, matched := machine.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1"), tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionCount, matched: true},
		{line: 2, action: ipfw.ActionCount, matched: false},
		{line: 3, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)

	counting := build(t, "add count ip from any to any\n", vm.Config[net4, net6]{DefaultVerdict: pass})
	require.Equal(t, pass, counting.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1")))
}

// verifies that numbered comment-only rules accept jumps and count both families before continuing.
func Test_VM_Check_CommentOnlyRule(t *testing.T) {
	machine := build(t, ruleset(`
		add 50 skipto 100 ip from any to any
		add 75 deny ip from any to any
		add 100 // note
		add 200 pass ip from any to any
	`), none)
	require.Equal(t, 4, machine.Len())
	packets := []vm.Packet{
		tcp4("192.0.2.1", "198.51.100.1"),
		vm.NewIPv6Packet(
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("2001:db8::2"),
		).WithTCP(ipfw.TCPSyn, 40000, 443),
	}
	for _, packet := range packets {
		tracer := &recordingTracer{}
		action, matched := machine.CheckTrace(&vm.Context{}, packet, tracer)
		require.True(t, matched)
		require.Equal(t, pass, action)
		require.Equal(t, []traced{
			{line: 1, action: ipfw.ActionSkipTo, matched: true},
			{line: 3, action: ipfw.ActionCount, matched: true},
			{line: 4, action: ipfw.ActionPass, matched: true},
		}, tracer.seen)
	}
	counting := build(t, "add // note\n", vm.Config[net4, net6]{DefaultVerdict: pass})
	require.Equal(t, pass, counting.Check(&vm.Context{}, packets[0]))
}

// verifies that a check-state rule, with or without a flow, never matches
// and is traced as such.
func Test_VM_Check_CheckState(t *testing.T) {
	src := ruleset(`
		add check-state
		add check-state :flow
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	tracer := &recordingTracer{}
	action, matched := machine.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1"), tracer)
	require.True(t, matched)
	require.Equal(t, deny, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionCheckState, matched: false},
		{line: 2, action: ipfw.ActionCheckState, matched: false},
		{line: 3, action: ipfw.ActionDeny, matched: true},
	}, tracer.seen)
}

// verifies that a matching skipto continues at the rule with that number
// and a mismatching one falls through.
func Test_VM_Check_SkipToNumber(t *testing.T) {
	src := ruleset(`
		add skipto 1500 ip from any to 192.0.2.4
		add deny ip from any to any
		add 1500 allow tcp from any to any
	`)
	machine := build(t, src, none)
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.4")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.5")))

	icmp := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.4")).WithICMP(8, 0)
	tracer := &recordingTracer{}
	_, matched := machine.CheckTrace(&vm.Context{}, icmp, tracer)
	require.False(t, matched)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionSkipTo, matched: true},
		{line: 3, action: ipfw.ActionPass, matched: false},
	}, tracer.seen)
}

// verifies that explicit rule numbers place the jump targets: a skipto
// lands on the rule numbered exactly so, the rules between are skipped.
func Test_VM_Check_RuleNumbers(t *testing.T) {
	src := ruleset(`
		add skipto 50 ip from any to 192.0.2.0/24
		add deny ip from any to any
		add 50 count ip from any to any
		add 1500 count ip from any to any
		add pass ip from any to any
	`)
	machine := build(t, src, none)
	require.Equal(t, 5, machine.Len())

	tracer := &recordingTracer{}
	action, matched := machine.CheckTrace(&vm.Context{}, tcp4("198.51.100.1", "192.0.2.9"), tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionSkipTo, matched: true},
		{line: 3, action: ipfw.ActionCount, matched: true},
		{line: 4, action: ipfw.ActionCount, matched: true},
		{line: 5, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)

	tracer = &recordingTracer{}
	action, matched = machine.CheckTrace(&vm.Context{}, tcp4("198.51.100.1", "203.0.113.9"), tracer)
	require.True(t, matched)
	require.Equal(t, deny, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionSkipTo, matched: false},
		{line: 2, action: ipfw.ActionDeny, matched: true},
	}, tracer.seen)
}

// verifies that a numeric skipto lands on the first later rule numbered at or
// after its target, as ipfw(8) jumps, a target at or before the rule's own
// number landing on the next rule, and that a rule without a number is
// numbered one past the previous rule.
func Test_VM_Check_SkipToAtOrAfter(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.2")
	cases := []struct {
		name  string
		rules string
		seen  []traced
	}{
		{
			name: "a gap before the target",
			rules: ruleset(`
				add 100 skipto 150 ip from any to any
				add 120 deny ip from any to any
				add 200 pass ip from any to any
			`),
			seen: []traced{
				{line: 1, action: ipfw.ActionSkipTo, matched: true},
				{line: 3, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			name: "the target numbered implicitly",
			rules: ruleset(`
				add 10 skipto 12 ip from any to any
				add deny ip from any to any
				add pass ip from any to any
			`),
			seen: []traced{
				{line: 1, action: ipfw.ActionSkipTo, matched: true},
				{line: 3, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			name: "its own number",
			rules: ruleset(`
				add 50 skipto 50 ip from any to any
				add pass ip from any to any
			`),
			seen: []traced{
				{line: 1, action: ipfw.ActionSkipTo, matched: true},
				{line: 2, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			name: "backwards",
			rules: ruleset(`
				add 50 count ip from any to any
				add 100 skipto 50 ip from any to any
				add 110 pass ip from any to any
			`),
			seen: []traced{
				{line: 1, action: ipfw.ActionCount, matched: true},
				{line: 2, action: ipfw.ActionSkipTo, matched: true},
				{line: 3, action: ipfw.ActionPass, matched: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			tracer := &recordingTracer{}
			action, matched := machine.CheckTrace(&vm.Context{}, packet, tracer)
			require.True(t, matched)
			require.Equal(t, pass, action)
			require.Equal(t, tc.seen, tracer.seen)
		})
	}
}

// verifies that a table value holding a number sends a skipto tablearg to the
// first later rule numbered at or after it, to the next rule when the number
// is not past the rule's own, and past the last rule to the default verdict.
func Test_VM_Check_TableArgNumber(t *testing.T) {
	src := ruleset(`
		table t create type iface
		table t add vlan1 300
		table t add vlan2 250
		table t add vlan3 50
		table t add vlan4 900
		add 100 skipto tablearg ip from any to any via table(t)
		add 200 deny ip from any to any
		add 300 pass ip from any to any
	`)
	machine := build(t, src, none)
	packet := tcp4("192.0.2.1", "192.0.2.2")
	cases := []struct {
		ifname  string
		matched bool
		seen    []traced
	}{
		{
			ifname:  "vlan1",
			matched: true,
			seen: []traced{
				{line: 6, action: ipfw.ActionSkipTo, matched: true},
				{line: 8, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			ifname:  "vlan2",
			matched: true,
			seen: []traced{
				{line: 6, action: ipfw.ActionSkipTo, matched: true},
				{line: 8, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			ifname:  "vlan3",
			matched: true,
			seen: []traced{
				{line: 6, action: ipfw.ActionSkipTo, matched: true},
				{line: 7, action: ipfw.ActionDeny, matched: true},
			},
		},
		{
			ifname: "vlan4",
			seen:   []traced{{line: 6, action: ipfw.ActionSkipTo, matched: true}},
		},
	}
	for _, tc := range cases {
		tracer := &recordingTracer{}
		_, matched := machine.CheckTrace(&vm.Context{IfName: tc.ifname}, packet, tracer)
		require.Equal(t, tc.matched, matched, tc.ifname)
		require.Equal(t, tc.seen, tracer.seen, tc.ifname)
	}
}

// verifies that a matching skipto to a label continues at the rule after
// the label, a mismatching one at the next rule.
func Test_VM_Check_SkipToLabel(t *testing.T) {
	src := ruleset(`
		add skipto :SECTION tcp from 192.0.2.4 to any
		add deny ip from any to any
		:SECTION
		add pass tcp from any to 203.0.113.1
		add deny ip from any to any
	`)
	machine := build(t, src, none, ipfw.WithLabels())
	require.Equal(t, 4, machine.Len())
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.4", "203.0.113.1")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "203.0.113.1")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("192.0.2.4", "203.0.113.2")))

	tracer := &recordingTracer{}
	_, matched := machine.CheckTrace(&vm.Context{}, tcp4("192.0.2.4", "203.0.113.2"), tracer)
	require.True(t, matched)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionSkipTo, matched: true},
		{line: 4, action: ipfw.ActionPass, matched: false},
		{line: 5, action: ipfw.ActionDeny, matched: true},
	}, tracer.seen)
}

// verifies that a label with no rule after it ends the search, and that
// a jump lands on the first occurrence of a repeated label after it.
func Test_VM_Check_Labels(t *testing.T) {
	src := ruleset(`
		add skipto :END ip from any to any
		add deny ip from any to any
		:END
	`)
	ending := build(t, src, vm.Config[net4, net6]{DefaultVerdict: pass}, ipfw.WithLabels())
	tracer := &recordingTracer{}
	_, matched := ending.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2"), tracer)
	require.False(t, matched)
	require.Equal(t, []traced{{line: 1, action: ipfw.ActionSkipTo, matched: true}}, tracer.seen)
	require.Equal(t, pass, ending.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))

	src = ruleset(`
		add skipto :A ip from any to any
		:A
		add count ip from any to any
		:A
		add pass ip from any to any
	`)
	repeated := build(t, src, none, ipfw.WithLabels())
	tracer = &recordingTracer{}
	action, matched := repeated.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2"), tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionSkipTo, matched: true},
		{line: 3, action: ipfw.ActionCount, matched: true},
		{line: 5, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)
}

// verifies that under the fall-through policy an unresolved skipto, to a
// label or to a number, matches and goes on with the next rule.
func Test_VM_Check_UnresolvedJumpsFallThrough(t *testing.T) {
	cfg := vm.Config[net4, net6]{UnresolvedJumps: vm.UnresolvedJumpsFallThrough}
	src := ruleset(`
		add skipto :NOWHERE ip from any to any
		add skipto 7 ip from any to any
		add pass ip from any to any
	`)
	machine := build(t, src, cfg, ipfw.WithLabels())
	tracer := &recordingTracer{}
	action, matched := machine.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2"), tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionSkipTo, matched: true},
		{line: 2, action: ipfw.ActionSkipTo, matched: true},
		{line: 3, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)
}

// verifies the port matchers of the rule body: a list requires the packet
// to have ports and one of its ranges, negated or not, to hold the port.
func Test_VM_Check_Ports(t *testing.T) {
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "source port, match",
			rules: ruleset(`
				add pass tcp from any 22 to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 22, 50000),
			verdict: pass,
		},
		{
			name: "source port, mismatch",
			rules: ruleset(`
				add pass tcp from any 22 to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 26, 50000),
			verdict: deny,
		},
		{
			name: "destination port over TCP",
			rules: ruleset(`
				add pass ip from any to any 22
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name: "destination port over UDP",
			rules: ruleset(`
				add pass ip from any to any 22
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithUDP(50000, 22),
			verdict: pass,
		},
		{
			name: "destination port against ICMP, which has none",
			rules: ruleset(`
				add pass ip from any to any 22
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithICMP(8, 1),
			verdict: deny,
		},
		{
			name: "both sides, match",
			rules: ruleset(`
				add pass tcp from 192.0.2.0/24 25 to 198.51.100.0/24 25
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")).WithTCP(ipfw.TCPSyn, 25, 25),
			verdict: pass,
		},
		{
			name: "both sides, destination port mismatch",
			rules: ruleset(`
				add pass tcp from 192.0.2.0/24 25 to 198.51.100.0/24 25
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")).WithTCP(ipfw.TCPSyn, 25, 26),
			verdict: deny,
		},
		{
			name: "range and list, inside the range",
			rules: ruleset(`
				add pass tcp from any 1000-2000,22 to any 80,443
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 1500, 443),
			verdict: pass,
		},
		{
			name: "range and list, the single port",
			rules: ruleset(`
				add pass tcp from any 1000-2000,22 to any 80,443
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 22, 80),
			verdict: pass,
		},
		{
			name: "range and list, just outside the range",
			rules: ruleset(`
				add pass tcp from any 1000-2000,22 to any 80,443
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 2001, 80),
			verdict: deny,
		},
		{
			name: "negated list, port outside",
			rules: ruleset(`
				add pass tcp from any not 22,25 to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 23, 50000),
			verdict: pass,
		},
		{
			name: "negated list, port inside",
			rules: ruleset(`
				add pass tcp from any not 22,25 to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 25, 50000),
			verdict: deny,
		},
		{
			name: "IPv6 packet",
			rules: ruleset(`
				add pass tcp from any to any 22
				add deny ip from any to any
			`),
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")).WithTCP(ipfw.TCPSyn, 50000, 22),
			verdict: pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that IP-family and transport members of one protocol group are
// alternatives rather than independent requirements.
func Test_VM_Check_MixedProtocolGroup(t *testing.T) {
	src := ruleset(`
		add pass { ip4 or tcp } from any to any
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	source4 := netip.MustParseAddr("192.0.2.1")
	destination4 := netip.MustParseAddr("192.0.2.2")
	source6 := netip.MustParseAddr("2001:db8::1")
	destination6 := netip.MustParseAddr("2001:db8::2")
	cases := []struct {
		name    string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "IPv4 UDP matches family",
			packet:  vm.NewIPv4Packet(source4, destination4).WithUDP(50000, 22),
			verdict: pass,
		},
		{
			name:    "IPv4 TCP matches both",
			packet:  tcp4("192.0.2.1", "192.0.2.2"),
			verdict: pass,
		},
		{
			name: "IPv6 TCP matches transport",
			packet: vm.NewIPv6Packet(source6, destination6).WithTCP(
				ipfw.TCPSyn,
				50000,
				22,
			),
			verdict: pass,
		},
		{
			name:    "IPv6 UDP matches neither",
			packet:  vm.NewIPv6Packet(source6, destination6).WithUDP(50000, 22),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that service names are resolved into ports on the way in.
func Test_VM_Build_ServiceNames(t *testing.T) {
	src := ruleset(`
		add pass tcp from any ssh-smtp to any smtp
		add deny ip from any to any
	`)
	machine, err := vm.Build(
		ipfw.NewParser(src),
		vm.Config[net4, net6]{Environment: resolvingServices},
	)
	require.NoError(t, err)
	packet := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1"))
	require.Equal(t, pass, machine.Check(&vm.Context{}, packet.WithTCP(ipfw.TCPSyn, 23, 25)))
	require.Equal(t, deny, machine.Check(&vm.Context{}, packet.WithTCP(ipfw.TCPSyn, 26, 25)))
	require.Equal(t, deny, machine.Check(&vm.Context{}, packet.WithTCP(ipfw.TCPSyn, 23, 22)))
}

// tcp4Flags is a TCP packet with the flags from src to dst over IPv4.
func tcp4Flags(flags ipfw.TCPFlag) vm.Packet {
	return vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithTCP(flags, 50000, 22)
}

// verifies that established matches a TCP packet with ACK or RST set and
// nothing else, negated the other way round.
func Test_VM_Check_Established(t *testing.T) {
	src := ruleset(`
		add allow tcp from any to any established
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPSyn)))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPAck)))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPRst)))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPSyn|ipfw.TCPAck)))
	udp := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22)
	require.Equal(t, deny, machine.Check(&vm.Context{}, udp))

	src = ruleset(`
		add allow ip from any to any not established
		add deny ip from any to any
	`)
	negated := build(t, src, none)
	require.Equal(t, pass, negated.Check(&vm.Context{}, tcp4Flags(ipfw.TCPSyn)))
	require.Equal(t, deny, negated.Check(&vm.Context{}, tcp4Flags(ipfw.TCPAck)))
	require.Equal(t, pass, negated.Check(&vm.Context{}, udp))
}

// verifies that via matches the context's interface by exact name or by
// mask, an empty name matching nothing but a mask that takes it.
func Test_VM_Check_Via(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.2")
	cases := []struct {
		name    string
		rules   string
		ifname  string
		verdict ipfw.Action
	}{
		{
			name: "exact, same name",
			rules: ruleset(`
				add pass ip from any to any via eth0
				add deny ip from any to any
			`),
			ifname:  "eth0",
			verdict: pass,
		},
		{
			name: "exact, other name",
			rules: ruleset(`
				add pass ip from any to any via eth0
				add deny ip from any to any
			`),
			ifname:  "eth1",
			verdict: deny,
		},
		{
			name: "exact, no name",
			rules: ruleset(`
				add pass ip from any to any via eth0
				add deny ip from any to any
			`),
			ifname:  "",
			verdict: deny,
		},
		{
			name: "mask, match",
			rules: ruleset(`
				add pass ip from any to any via vlan1???
				add deny ip from any to any
			`),
			ifname:  "vlan1234",
			verdict: pass,
		},
		{
			name: "mask, too short",
			rules: ruleset(`
				add pass ip from any to any via vlan1???
				add deny ip from any to any
			`),
			ifname:  "vlan123",
			verdict: deny,
		},
		{
			name: "mask, other prefix",
			rules: ruleset(`
				add pass ip from any to any via vlan1???
				add deny ip from any to any
			`),
			ifname:  "vlan2234",
			verdict: deny,
		},
		{
			name: "mask class with a leading closing bracket",
			rules: ruleset(`
				add deny ip from any to any via vlan[]0]
				add pass ip from any to any
			`),
			ifname:  "vlan0",
			verdict: deny,
		},
		{
			name: "star mask takes the empty name",
			rules: ruleset(`
				add pass ip from any to any via *
				add deny ip from any to any
			`),
			ifname:  "",
			verdict: pass,
		},
		{
			name: "group, first",
			rules: ruleset(`
				add pass ip from any to any { via eth0 or via eth1 }
				add deny ip from any to any
			`),
			ifname:  "eth0",
			verdict: pass,
		},
		{
			name: "group, second",
			rules: ruleset(`
				add pass ip from any to any { via eth0 or via eth1 }
				add deny ip from any to any
			`),
			ifname:  "eth1",
			verdict: pass,
		},
		{
			name: "group, neither",
			rules: ruleset(`
				add pass ip from any to any { via eth0 or via eth1 }
				add deny ip from any to any
			`),
			ifname:  "eth2",
			verdict: deny,
		},
		{
			name: "negated, same name",
			rules: ruleset(`
				add pass ip from any to any not via eth0
				add deny ip from any to any
			`),
			ifname:  "eth0",
			verdict: deny,
		},
		{
			name: "negated, other name",
			rules: ruleset(`
				add pass ip from any to any not via eth0
				add deny ip from any to any
			`),
			ifname:  "eth1",
			verdict: pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{IfName: tc.ifname}, packet))
		})
	}

	src := ruleset(`
		add allow ip from me to me { via lo0 or via lo1 }
		add deny ip from any to any
	`)
	loopback := build(t, src, none)
	local := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	between := tcp4("192.0.2.1", "192.0.2.1")
	require.Equal(t, deny, loopback.Check(&vm.Context{LocalAddrs: local}, between))
	require.Equal(t, pass, loopback.Check(&vm.Context{LocalAddrs: local, IfName: "lo0"}, between))
	require.Equal(t, pass, loopback.Check(&vm.Context{LocalAddrs: local, IfName: "lo1"}, between))
	require.Equal(t, deny, loopback.Check(&vm.Context{IfName: "lo0"}, between))
}

// verifies that the proto option matches the protocol number, a name
// resolved on the way in, negated the other way round.
func Test_VM_Check_ProtoOption(t *testing.T) {
	udp := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22)
	src := ruleset(`
		add pass ip from any to any proto tcp
		add deny ip from any to any
	`)
	named := build(t, src, none)
	require.Equal(t, pass, named.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
	require.Equal(t, deny, named.Check(&vm.Context{}, udp))

	src = ruleset(`
		add pass ip from any to any not proto 6
		add deny ip from any to any
	`)
	negated := build(t, src, none)
	require.Equal(t, deny, negated.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
	require.Equal(t, pass, negated.Check(&vm.Context{}, udp))

	src = ruleset(`
		add pass ip from any to any { proto 17 or proto 1 }
		add deny ip from any to any
	`)
	numeric, err := vm.Build(ipfw.NewParser(src), vm.Config[net4, net6]{Environment: networksOnly})
	require.NoError(t, err)
	require.Equal(t, pass, numeric.Check(&vm.Context{}, udp))
	require.Equal(t, deny, numeric.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
}

// verifies the src-port and dst-port options: the packet's port must be
// present and in a range, a list is any of its ranges, a negated list none.
func Test_VM_Check_PortOptions(t *testing.T) {
	tcp := func(src, dst uint16) vm.Packet {
		return vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithTCP(ipfw.TCPSyn, src, dst)
	}
	cases := []struct {
		name    string
		rules   string
		context vm.Context
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "src-port, match",
			rules: ruleset(`
				add pass tcp from any to any src-port 25
				add deny ip from any to any
			`),
			packet:  tcp(25, 50000),
			verdict: pass,
		},
		{
			name: "src-port, mismatch",
			rules: ruleset(`
				add pass tcp from any to any src-port 25
				add deny ip from any to any
			`),
			packet:  tcp(26, 50000),
			verdict: deny,
		},
		{
			name: "two dst-port rules, first",
			rules: ruleset(`
				add pass tcp from any to any dst-port 22
				add pass tcp from any to any dst-port 25
				add deny ip from any to any
			`),
			packet:  tcp(50000, 22),
			verdict: pass,
		},
		{
			name: "two dst-port rules, second",
			rules: ruleset(`
				add pass tcp from any to any dst-port 22
				add pass tcp from any to any dst-port 25
				add deny ip from any to any
			`),
			packet:  tcp(50000, 25),
			verdict: pass,
		},
		{
			name: "two dst-port rules, neither",
			rules: ruleset(`
				add pass tcp from any to any dst-port 22
				add pass tcp from any to any dst-port 25
				add deny ip from any to any
			`),
			packet:  tcp(50000, 26),
			verdict: deny,
		},
		{
			name: "dst-port over UDP",
			rules: ruleset(`
				add pass ip from any to any dst-port 22
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22),
			verdict: pass,
		},
		{
			name: "dst-port against ICMP",
			rules: ruleset(`
				add pass ip from any to any dst-port 22
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithICMP(8, 1),
			verdict: deny,
		},
		{
			name: "dst-port list, first",
			rules: ruleset(`
				add pass tcp from any to any dst-port 22,80
				add deny ip from any to any
			`),
			packet:  tcp(50000, 22),
			verdict: pass,
		},
		{
			name: "dst-port list, second",
			rules: ruleset(`
				add pass tcp from any to any dst-port 22,80
				add deny ip from any to any
			`),
			packet:  tcp(50000, 80),
			verdict: pass,
		},
		{
			name: "dst-port list, neither",
			rules: ruleset(`
				add pass tcp from any to any dst-port 22,80
				add deny ip from any to any
			`),
			packet:  tcp(50000, 443),
			verdict: deny,
		},
		{
			name: "negated dst-port list, inside",
			rules: ruleset(`
				add pass tcp from any to any not dst-port 22,80
				add deny ip from any to any
			`),
			packet:  tcp(50000, 22),
			verdict: deny,
		},
		{
			name: "negated dst-port list, outside",
			rules: ruleset(`
				add pass tcp from any to any not dst-port 22,80
				add deny ip from any to any
			`),
			packet:  tcp(50000, 443),
			verdict: pass,
		},
		{
			name: "outbound destination first list member is denied",
			rules: ruleset(`
				add pass tcp from any to any { not dst-port 22,80 or in }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(50000, 22),
			verdict: deny,
		},
		{
			name: "outbound destination second list member is denied",
			rules: ruleset(`
				add pass tcp from any to any { not dst-port 22,80 or in }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(50000, 80),
			verdict: deny,
		},
		{
			name: "outbound destination port outside list passes",
			rules: ruleset(`
				add pass tcp from any to any { not dst-port 22,80 or in }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(50000, 81),
			verdict: pass,
		},
		{
			name: "outbound source first list member is denied",
			rules: ruleset(`
				add pass tcp from any to any { not src-port 22,80 or in }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(22, 50000),
			verdict: deny,
		},
		{
			name: "outbound source second list member is denied",
			rules: ruleset(`
				add pass tcp from any to any { not src-port 22,80 or in }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(80, 50000),
			verdict: deny,
		},
		{
			name: "outbound source port outside list passes",
			rules: ruleset(`
				add pass tcp from any to any { not src-port 22,80 or in }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(81, 50000),
			verdict: pass,
		},
		{
			name: "later destination list denies its member",
			rules: ruleset(`
				add pass tcp from any to any { in or not dst-port 22,80 }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(50000, 22),
			verdict: deny,
		},
		{
			name: "later destination list passes an outside port",
			rules: ruleset(`
				add pass tcp from any to any { in or not dst-port 22,80 }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(50000, 81),
			verdict: pass,
		},
		{
			name: "adjacent destination option passes its port",
			rules: ruleset(`
				add pass tcp from any to any { not dst-port 22,80 or dst-port 81 }
				add deny ip from any to any
			`),
			context: vm.Context{Direction: vm.Out},
			packet:  tcp(50000, 81),
			verdict: pass,
		},
		{
			name: "range with another option",
			rules: ruleset(`
				add pass tcp from any to any established src-port 1024-65535
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithTCP(ipfw.TCPAck, 1024, 22),
			verdict: pass,
		},
		{
			name: "range with another option, below",
			rules: ruleset(`
				add pass tcp from any to any established src-port 1024-65535
				add deny ip from any to any
			`),
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithTCP(ipfw.TCPAck, 1023, 22),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&tc.context, tc.packet))
		})
	}

	src := ruleset(`
		add pass tcp from any to any dst-port ssh,smtp
		add deny ip from any to any
	`)
	named, err := vm.Build(ipfw.NewParser(src), vm.Config[net4, net6]{Environment: resolvingServices})
	require.NoError(t, err)
	require.Equal(t, pass, named.Check(&vm.Context{}, tcp(50000, 25)))
	require.Equal(t, deny, named.Check(&vm.Context{}, tcp(50000, 26)))
}

// verifies that tcpflags independently requires listed flags set or clear,
// and never matches a packet without TCP flags.
func Test_VM_Check_TCPFlags(t *testing.T) {
	udp := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22)
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "tcp rule, syn and not ack, SYN",
			rules: ruleset(`
				add allow tcp from any to any tcpflags syn,!ack
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name: "tcp rule, syn and not ack, ACK",
			rules: ruleset(`
				add allow tcp from any to any tcpflags syn,!ack
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: deny,
		},
		{
			name: "ip rule, syn and not ack, SYN",
			rules: ruleset(`
				add allow ip from any to any tcpflags syn,!ack
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name: "ip rule, syn and not ack, SYN with ACK",
			rules: ruleset(`
				add allow ip from any to any tcpflags syn,!ack
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPSyn | ipfw.TCPAck),
			verdict: deny,
		},
		{
			name: "ip rule, syn and not ack, SYN with unlisted PSH",
			rules: ruleset(`
				add allow ip from any to any tcpflags syn,!ack
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPSyn | ipfw.TCPPsh),
			verdict: pass,
		},
		{
			name: "contradictory SYN requirements",
			rules: ruleset(`
				add allow tcp from any to any tcpflags syn,!syn
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: deny,
		},
		{
			name: "ip rule, syn and not ack, UDP",
			rules: ruleset(`
				add allow ip from any to any tcpflags syn,!ack
				add deny ip from any to any
			`),
			packet:  udp,
			verdict: deny,
		},
		{
			name: "not tcpflags, UDP",
			rules: ruleset(`
				add allow ip from any to any not tcpflags rst
				add deny ip from any to any
			`),
			packet:  udp,
			verdict: pass,
		},
		{
			name: "not tcpflags, RST",
			rules: ruleset(`
				add allow ip from any to any not tcpflags rst
				add deny ip from any to any
			`),
			packet:  tcp4Flags(ipfw.TCPRst),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that ICMP type options match reported types, with icmp6types
// additionally restricted to IPv6 packets.
func Test_VM_Check_ICMPTypes(t *testing.T) {
	icmp := func(ty uint8) vm.Packet {
		return vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithICMP(ty, 0)
	}
	icmp6 := func(ty uint8) vm.Packet {
		return vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")).WithICMP6(ty, 0)
	}
	icmp6OverIPv4 := vm.NewIPv4Packet(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	)
	icmp6OverIPv4[9], icmp6OverIPv4[20] = 58, 128
	icmpOverIPv6 := vm.NewIPv6Packet(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	)
	icmpOverIPv6[6], icmpOverIPv6[40] = 1, 8
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "icmptypes, type in the set",
			rules: ruleset(`
				add allow icmp from any to { 192.0.2.0/24 } icmptypes 0,7,31
				add deny ip from any to any
			`),
			packet:  icmp(31),
			verdict: pass,
		},
		{
			name: "icmptypes, type outside the set",
			rules: ruleset(`
				add allow icmp from any to { 192.0.2.0/24 } icmptypes 0,7,31
				add deny ip from any to any
			`),
			packet:  icmp(8),
			verdict: deny,
		},
		{
			name: "icmptypes against TCP",
			rules: ruleset(`
				add allow ip from any to any icmptypes 8
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "192.0.2.2"),
			verdict: deny,
		},
		{
			name: "icmptypes against ICMPv6",
			rules: ruleset(`
				add allow ip from any to any icmptypes 8
				add deny ip from any to any
			`),
			packet:  icmp6(8),
			verdict: deny,
		},
		{
			name: "icmptypes against IPv6 protocol one",
			rules: ruleset(`
				add allow ip from any to any icmptypes 8
				add deny ip from any to any
			`),
			packet:  icmpOverIPv6,
			verdict: pass,
		},
		{
			name: "not icmptypes, type in the set",
			rules: ruleset(`
				add allow ip from any to any not icmptypes 7,31
				add deny ip from any to any
			`),
			packet:  icmp(7),
			verdict: deny,
		},
		{
			name: "not icmptypes, type outside the set",
			rules: ruleset(`
				add allow ip from any to any not icmptypes 7,31
				add deny ip from any to any
			`),
			packet:  icmp(30),
			verdict: pass,
		},
		{
			name: "icmp6types, type in the set",
			rules: ruleset(`
				add allow ip from any to { 2001:db8::/32 } icmp6types 0,5,135,150,201
				add deny ip from any to any
			`),
			packet:  icmp6(201),
			verdict: pass,
		},
		{
			name: "icmp6types, type outside the set",
			rules: ruleset(`
				add allow ip from any to { 2001:db8::/32 } icmp6types 0,5,135,150,201
				add deny ip from any to any
			`),
			packet:  icmp6(130),
			verdict: deny,
		},
		{
			name: "icmp6types against ICMP",
			rules: ruleset(`
				add allow ip from any to any icmp6types 128
				add deny ip from any to any
			`),
			packet:  icmp(128),
			verdict: deny,
		},
		{
			name: "icmp6types against IPv4 protocol 58",
			rules: ruleset(`
				add allow ip from any to any icmp6types 128
				add deny ip from any to any
			`),
			packet:  icmp6OverIPv4,
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// fieldPacket is a packet held field by field, as a structure of another
// library would hold it, reporting every transport field it is asked for.
//
// It panics when the VM asks for a field the Packet contract says it never
// asks for, a non-first fragment's ports or a UDP packet's flags among them.
type fieldPacket struct {
	version  vm.IPVersion
	protocol uint8
	fragment bool
	icmpType uint8
}

// Version implements vm.Packet.
func (m fieldPacket) Version() vm.IPVersion {
	return m.version
}

// Protocol implements vm.Packet.
func (m fieldPacket) Protocol() uint8 {
	return m.protocol
}

// SourceAddr implements vm.Packet.
func (m fieldPacket) SourceAddr() netip.Addr {
	if m.version == vm.IPv6 {
		return netip.MustParseAddr("2001:db8::1")
	}
	return netip.MustParseAddr("192.0.2.1")
}

// DestinationAddr implements vm.Packet.
func (m fieldPacket) DestinationAddr() netip.Addr {
	if m.version == vm.IPv6 {
		return netip.MustParseAddr("2001:db8::2")
	}
	return netip.MustParseAddr("192.0.2.2")
}

// IsFragment implements vm.Packet.
func (m fieldPacket) IsFragment() bool {
	return m.fragment
}

// SourcePort implements vm.Packet.
func (m fieldPacket) SourcePort() (uint16, bool) {
	m.expect("ports", 6, 17, 132, 136)
	return 40000, true
}

// DestinationPort implements vm.Packet.
func (m fieldPacket) DestinationPort() (uint16, bool) {
	m.expect("ports", 6, 17, 132, 136)
	return 22, true
}

// TCPFlags implements vm.Packet.
func (m fieldPacket) TCPFlags() (ipfw.TCPFlag, bool) {
	m.expect("TCP flags", 6)
	return ipfw.TCPSyn | ipfw.TCPAck, true
}

// ICMPType implements vm.Packet.
func (m fieldPacket) ICMPType() (uint8, bool) {
	m.expect("the ICMP type", 1, 58)
	return m.icmpType, true
}

// expect panics unless the packet is a first fragment or a whole packet of
// one of the protocols.
func (m fieldPacket) expect(what string, protocols ...uint8) {
	if m.fragment || !slices.Contains(protocols, m.protocol) {
		panic(fmt.Sprintf("asked for %s of protocol %d, fragment %v", what, m.protocol, m.fragment))
	}
}

// verifies that the VM reads a transport field only where ipfw(8) does: ports
// of TCP, UDP, SCTP and UDP-Lite, flags of TCP, the type of ICMP and ICMPv6,
// and none of them for a non-first fragment, whatever the packet reports.
func Test_VM_Check_PacketContract(t *testing.T) {
	cases := []struct {
		name    string
		options string
		packet  fieldPacket
		verdict ipfw.Action
	}{
		{
			name:    "dst-port of TCP",
			options: "dst-port 22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 6},
			verdict: pass,
		},
		{
			name:    "dst-port of UDP",
			options: "dst-port 22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 17},
			verdict: pass,
		},
		{
			name:    "dst-port of SCTP",
			options: "dst-port 22",
			packet:  fieldPacket{version: vm.IPv6, protocol: 132},
			verdict: pass,
		},
		{
			name:    "dst-port of UDP-Lite",
			options: "dst-port 22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 136},
			verdict: pass,
		},
		{
			name:    "dst-port of ICMP",
			options: "dst-port 22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 1},
			verdict: deny,
		},
		{
			name:    "negated dst-port of ICMP",
			options: "not dst-port 22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 1},
			verdict: pass,
		},
		{
			name:    "dst-port of a TCP fragment",
			options: "dst-port 22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 6, fragment: true},
			verdict: deny,
		},
		{
			name:    "src-port of an IPv6 UDP fragment",
			options: "src-port 40000",
			packet:  fieldPacket{version: vm.IPv6, protocol: 17, fragment: true},
			verdict: deny,
		},
		{
			name:    "body port of a TCP fragment",
			options: "22",
			packet:  fieldPacket{version: vm.IPv4, protocol: 6, fragment: true},
			verdict: deny,
		},
		{
			name:    "established of TCP",
			options: "established",
			packet:  fieldPacket{version: vm.IPv4, protocol: 6},
			verdict: pass,
		},
		{
			name:    "established of UDP",
			options: "established",
			packet:  fieldPacket{version: vm.IPv4, protocol: 17},
			verdict: deny,
		},
		{
			name:    "established of a TCP fragment",
			options: "established",
			packet:  fieldPacket{version: vm.IPv4, protocol: 6, fragment: true},
			verdict: deny,
		},
		{
			name:    "tcpflags of SCTP",
			options: "tcpflags syn",
			packet:  fieldPacket{version: vm.IPv4, protocol: 132},
			verdict: deny,
		},
		{
			name:    "icmptypes of ICMP",
			options: "icmptypes 8",
			packet:  fieldPacket{version: vm.IPv4, protocol: 1, icmpType: 8},
			verdict: pass,
		},
		{
			name:    "icmptypes of ICMP over IPv6",
			options: "icmptypes 8",
			packet:  fieldPacket{version: vm.IPv6, protocol: 1, icmpType: 8},
			verdict: pass,
		},
		{
			name:    "icmptypes of ICMPv6",
			options: "icmptypes 8",
			packet:  fieldPacket{version: vm.IPv6, protocol: 58, icmpType: 8},
			verdict: deny,
		},
		{
			name:    "icmptypes of an ICMP fragment",
			options: "icmptypes 8",
			packet:  fieldPacket{version: vm.IPv4, protocol: 1, fragment: true, icmpType: 8},
			verdict: deny,
		},
		{
			name:    "icmp6types of ICMPv6",
			options: "icmp6types 128",
			packet:  fieldPacket{version: vm.IPv6, protocol: 58, icmpType: 128},
			verdict: pass,
		},
		{
			name:    "icmp6types of ICMPv6 over IPv4",
			options: "icmp6types 128",
			packet:  fieldPacket{version: vm.IPv4, protocol: 58, icmpType: 128},
			verdict: deny,
		},
		{
			name:    "icmp6types of ICMP over IPv6",
			options: "icmp6types 128",
			packet:  fieldPacket{version: vm.IPv6, protocol: 1, icmpType: 128},
			verdict: deny,
		},
		{
			name:    "frag of an IPv6 fragment",
			options: "frag",
			packet:  fieldPacket{version: vm.IPv6, protocol: 17, fragment: true},
			verdict: pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "add pass ip from any to any " + tc.options + "\nadd deny ip from any to any\n"
			machine := build(t, src, none)
			require.NotPanics(t, func() {
				require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
			})
		})
	}
}

// verifies that raw packets are matched past IPv4 options and IPv6 extension
// headers, that an IPv6 non-first fragment is a fragment with no ports, and
// that SCTP and UDP-Lite have ports.
func Test_VM_Check_RawLayout(t *testing.T) {
	withOptions := vm.NewIPv4Packet(src4, dst4)
	withOptions[0] = 4<<4 | 6
	withOptions = withOptions.WithTCP(ipfw.TCPSyn, 40000, 22)
	tcpHeader := []byte{0x9c, 0x40, 0x00, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, byte(ipfw.TCPSyn)}
	hopByHop := ipv6(0, []byte{6, 0, 0, 0, 0, 0, 0, 0}, tcpHeader)
	fragment6 := vm.NewIPv6Packet(src6, dst6).WithTCP(ipfw.TCPSyn, 40000, 22).WithFragmentOffset(100)
	udpLite := vm.NewIPv4Packet(src4, dst4).WithUDP(40000, 22)
	udpLite[9] = 136
	sctp := vm.NewIPv6Packet(src6, dst6).WithUDP(40000, 22)
	sctp[6] = 132
	cases := []struct {
		name    string
		options string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{name: "port past IPv4 options", options: "dst-port 22", packet: withOptions, verdict: pass},
		{name: "port past hop-by-hop options", options: "dst-port 22", packet: hopByHop, verdict: pass},
		{name: "flags past hop-by-hop options", options: "tcpflags syn", packet: hopByHop, verdict: pass},
		{name: "IPv6 fragment", options: "frag", packet: fragment6, verdict: pass},
		{name: "port of an IPv6 fragment", options: "dst-port 22", packet: fragment6, verdict: deny},
		{name: "whole IPv6 packet", options: "frag", packet: hopByHop, verdict: deny},
		{name: "port of UDP-Lite", options: "dst-port 22", packet: udpLite, verdict: pass},
		{name: "port of SCTP", options: "dst-port 22", packet: sctp, verdict: pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "add pass ip from any to any " + tc.options + "\nadd deny ip from any to any\n"
			machine := build(t, src, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that frag matches a non-first IPv4 fragment only, which, having
// no transport header, fails a rule with ports first.
func Test_VM_Check_Frag(t *testing.T) {
	src := ruleset(`
		add allow ip from any to any frag
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	fragment := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithFragmentOffset(100)
	require.Equal(t, pass, machine.Check(&vm.Context{}, fragment))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"))))

	src = ruleset(`
		add allow ip from any to any 22 frag
		add deny ip from any to any
	`)
	withPorts := build(t, src, none)
	require.Equal(t, deny, withPorts.Check(&vm.Context{}, fragment))
	require.Equal(t, deny, withPorts.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2").(vm.RawIPv4Packet).WithFragmentOffset(100)))
	require.Equal(t, deny, withPorts.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
}

// verifies that in and out match the direction of the check, that either
// in a group always matches and that not in is out.
func Test_VM_Check_Direction(t *testing.T) {
	in, out := &vm.Context{Direction: vm.In}, &vm.Context{Direction: vm.Out}
	packet := tcp4("192.0.2.1", "192.0.2.2")
	cases := []struct {
		name  string
		rules string
		in    ipfw.Action
		out   ipfw.Action
	}{
		{
			name: "in",
			rules: ruleset(`
				add allow ip from any to any in
				add deny ip from any to any
			`),
			in:  pass,
			out: deny,
		},
		{
			name: "out",
			rules: ruleset(`
				add allow ip from any to any out
				add deny ip from any to any
			`),
			in:  deny,
			out: pass,
		},
		{
			name: "in or out",
			rules: ruleset(`
				add allow ip from any to any { in or out }
				add deny ip from any to any
			`),
			in:  pass,
			out: pass,
		},
		{
			name: "not in",
			rules: ruleset(`
				add allow ip from any to any not in
				add deny ip from any to any
			`),
			in:  deny,
			out: pass,
		},
		{
			name: "in and out never both",
			rules: ruleset(`
				add allow ip from any to any in out
				add deny ip from any to any
			`),
			in:  deny,
			out: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.in, machine.Check(in, packet))
			require.Equal(t, tc.out, machine.Check(out, packet))
		})
	}
}

// verifies the fold over the options: AND between terms, OR inside a
// group, and a rule with no options decided by its body alone.
func Test_VM_Check_OptionFold(t *testing.T) {
	src := ruleset(`
		add pass tcp from any to any established not established
		add count tcp from any to any { not established or established }
		add pass tcp from any to any
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	for _, flags := range []ipfw.TCPFlag{ipfw.TCPSyn, ipfw.TCPAck} {
		tracer := &recordingTracer{}
		action, matched := machine.CheckTrace(&vm.Context{}, tcp4Flags(flags), tracer)
		require.True(t, matched)
		require.Equal(t, pass, action)
		require.Equal(t, []traced{
			{line: 1, action: ipfw.ActionPass, matched: false},
			{line: 2, action: ipfw.ActionCount, matched: true},
			{line: 3, action: ipfw.ActionPass, matched: true},
		}, tracer.seen)
	}
}

// verifies that a check over options allocates nothing.
func Test_VM_Options_NoAllocs(t *testing.T) {
	src := ruleset(`
		add deny tcp from any to any { established or not established } not established
		add pass tcp from any to any established
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	packet := tcp4Flags(ipfw.TCPAck)
	ctx := &vm.Context{}
	verdict := pass
	allocs := testing.AllocsPerRun(100, func() {
		if machine.Check(ctx, packet) != pass {
			verdict = deny
		}
	})
	require.Equal(t, pass, verdict)
	require.Zero(t, allocs)
}

// verifies that a name stands for every network the resolver gives, of
// both families, negated as a whole, and for nothing when it gives none.
func Test_VM_Check_ResolvedTargets(t *testing.T) {
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "hostname, its IPv4 address",
			rules: ruleset(`
				add pass ip from host.example.com to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: pass,
		},
		{
			name: "hostname, its IPv6 address",
			rules: ruleset(`
				add pass ip from host.example.com to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: pass,
		},
		{
			name: "hostname, another address",
			rules: ruleset(`
				add pass ip from host.example.com to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.2", "203.0.113.1"),
			verdict: deny,
		},
		{
			name: "negated hostname, its IPv4 address",
			rules: ruleset(`
				add pass ip from not host.example.com to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: deny,
		},
		{
			name: "negated hostname, its IPv6 address",
			rules: ruleset(`
				add pass ip from not host.example.com to any
				add deny ip from any to any
			`),
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: deny,
		},
		{
			name: "negated hostname, another address",
			rules: ruleset(`
				add pass ip from not host.example.com to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.2", "203.0.113.1"),
			verdict: pass,
		},
		{
			name: "custom token, first network",
			rules: ruleset(`
				add pass ip from any to custom:first
				add deny ip from any to any
			`),
			packet:  tcp4("203.0.113.1", "192.0.2.5"),
			verdict: pass,
		},
		{
			name: "custom token, second network",
			rules: ruleset(`
				add pass ip from any to custom:first
				add deny ip from any to any
			`),
			packet:  tcp4("203.0.113.1", "198.51.100.5"),
			verdict: pass,
		},
		{
			name: "custom token, outside",
			rules: ruleset(`
				add pass ip from any to custom:first
				add deny ip from any to any
			`),
			packet:  tcp4("203.0.113.1", "203.0.113.5"),
			verdict: deny,
		},
		{
			name: "negated custom token, inside",
			rules: ruleset(`
				add pass ip from any to not custom:first
				add deny ip from any to any
			`),
			packet:  tcp4("203.0.113.1", "198.51.100.5"),
			verdict: deny,
		},
		{
			name: "negated custom token in a group with a network",
			rules: ruleset(`
				add pass ip from { 203.0.113.0/24 or not custom:first } to any
				add deny ip from any to any
			`),
			packet:  tcp4("198.51.100.5", "203.0.113.1"),
			verdict: deny,
		},
		{
			name: "name standing for nothing never matches",
			rules: ruleset(`
				add pass tcp from { nothing.example.com } to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: deny,
		},
		{
			name: "negated name standing for nothing never matches either",
			rules: ruleset(`
				add pass tcp from not nothing.example.com to any
				add deny ip from any to any
			`),
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := vm.Build(ipfw.NewParser(tc.rules), vm.Config[net4, net6]{Environment: resolvingTargets})
			require.NoError(t, err)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that a comma-separated address list is one match pattern, so a
// leading not negates membership in the complete list.
func Test_VM_Check_AddressLists(t *testing.T) {
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "second source address",
			rules: "add pass ip from 192.0.2.1,198.51.100.1 to any\n" +
				"add deny ip from any to any\n",
			packet:  tcp4("198.51.100.1", "203.0.113.1"),
			verdict: pass,
		},
		{
			name: "negated list member",
			rules: "add pass ip from not 192.0.2.1,198.51.100.1 to any\n" +
				"add deny ip from any to any\n",
			packet:  tcp4("198.51.100.1", "203.0.113.1"),
			verdict: deny,
		},
		{
			name: "outside negated list",
			rules: "add pass ip from any to not 192.0.2.1,198.51.100.1\n" +
				"add deny ip from any to any\n",
			packet:  tcp4("203.0.113.1", "203.0.113.2"),
			verdict: pass,
		},
		{
			name: "negated IPv6 destination list member",
			rules: "add pass ip6 from any to not 2001:db8::1,2001:db8::2\n" +
				"add deny ip from any to any\n",
			packet: vm.NewIPv6Packet(
				netip.MustParseAddr("2001:db8::3"),
				netip.MustParseAddr("2001:db8::2"),
			),
			verdict: deny,
		},
		{
			name: "or block keeps independent negations",
			rules: "add pass ip from { not 192.0.2.1 or not 198.51.100.1 } to any\n" +
				"add deny ip from any to any\n",
			packet:  tcp4("198.51.100.1", "203.0.113.1"),
			verdict: pass,
		},
		{
			name: "empty first list member stays separate",
			rules: "add pass ip from { 203.0.113.0/24 or " +
				"not empty.example.com,192.0.2.1 } to any\n" +
				"add deny ip from any to any\n",
			packet:  tcp4("198.51.100.1", "203.0.113.1"),
			verdict: pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := vm.Build(
				ipfw.NewParser(tc.rules),
				vm.Config[net4, net6]{Environment: resolvingTargets},
			)
			require.NoError(t, err)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that a check over resolved names allocates nothing.
func Test_VM_Check_Resolved_NoAllocs(t *testing.T) {
	rules := ruleset(`
		add deny ip from not host.example.com,192.0.2.2 to custom:first
		add pass ip from host.example.com to { custom:first or not host.example.com }
		add deny ip from any to any
	`)
	machine, err := vm.Build(
		ipfw.NewParser(rules),
		vm.Config[net4, net6]{Environment: resolvingTargets},
	)
	require.NoError(t, err)
	packet := tcp4("192.0.2.1", "198.51.100.5")
	ctx := &vm.Context{}
	verdict := pass
	allocs := testing.AllocsPerRun(100, func() {
		if machine.Check(ctx, packet) != pass {
			verdict = deny
		}
	})
	require.Equal(t, pass, verdict)
	require.Zero(t, allocs)
}

// verifies that me and me6 match the addresses the context lists, in the
// packet's family only, so one VM gives different verdicts per context.
func Test_VM_Check_Me(t *testing.T) {
	src := ruleset(`
		add pass ip from me to me
		add pass ip from me6 to any
		add deny ip from any to any
	`)
	machine := build(t, src, none)
	local4 := &vm.Context{LocalAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	other4 := &vm.Context{LocalAddrs: []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("192.0.2.1")}}
	local6 := &vm.Context{LocalAddrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
	cases := []struct {
		name    string
		ctx     *vm.Context
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "IPv4 packet between local addresses",
			ctx:     local4,
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name:    "IPv4 packet, local among several",
			ctx:     other4,
			packet:  tcp4("192.0.2.1", "198.51.100.1"),
			verdict: pass,
		},
		{
			name:    "IPv4 packet, destination not local",
			ctx:     local4,
			packet:  tcp4("192.0.2.1", "192.0.2.2"),
			verdict: deny,
		},
		{
			name:    "IPv4 packet, no local addresses",
			ctx:     &vm.Context{},
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: deny,
		},
		{
			name:    "IPv4 packet, only IPv6 addresses local",
			ctx:     local6,
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: deny,
		},
		{
			name:    "IPv6 packet from a local address",
			ctx:     local6,
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: pass,
		},
		{
			name:    "IPv6 packet, me never matches it",
			ctx:     &vm.Context{LocalAddrs: []netip.Addr{netip.MustParseAddr("2001:db8::2")}},
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.verdict, machine.Check(tc.ctx, tc.packet))
		})
	}
}

// verifies that the family of an address decides which targets can match
// it, an address of neither family matching none of them but `any`.
//
// A check takes the family of the addresses once and every target of the
// rules is tested against it, so an IPv4-mapped address, which is an IPv6
// one, and the invalid address of a truncated packet have to be rejected
// exactly where a family test at each target rejects them.
func Test_VM_Check_AddressFamily(t *testing.T) {
	// The invalid address is among the local ones, so only its family keeps
	// `me` and `me6` from matching it.
	local := &vm.Context{LocalAddrs: []netip.Addr{{}, netip.MustParseAddr("192.0.2.1")}}
	mapped := raw6("::ffff:192.0.2.1", "2001:db8::1")
	truncated := vm.RawIPv4Packet{0x45}
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "mapped source is no IPv4 address",
			rules: `
				add pass ip from 192.0.2.0/24 to any
				add deny ip from any to any
			`,
			packet:  mapped,
			verdict: deny,
		},
		{
			name: "mapped source is an IPv6 address",
			rules: `
				add pass ip from ::ffff:0:0/96 to any
				add deny ip from any to any
			`,
			packet:  mapped,
			verdict: pass,
		},
		{
			name: "invalid source is no IPv4 address",
			rules: `
				add pass ip from 0.0.0.0/0 to any
				add deny ip from any to any
			`,
			packet:  truncated,
			verdict: deny,
		},
		{
			name: "invalid source is no IPv6 address",
			rules: `
				add pass ip from ::/0 to any
				add deny ip from any to any
			`,
			packet:  truncated,
			verdict: deny,
		},
		{
			name: "invalid source is not me",
			rules: `
				add pass ip from me to any
				add deny ip from any to any
			`,
			packet:  truncated,
			verdict: deny,
		},
		{
			name: "invalid source is not me6",
			rules: `
				add pass ip from me6 to any
				add deny ip from any to any
			`,
			packet:  truncated,
			verdict: deny,
		},
		{
			name: "invalid source is any",
			rules: `
				add pass ip from any to any
				add deny ip from any to any
			`,
			packet:  truncated,
			verdict: pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, ruleset(tc.rules), none)
			require.Equal(t, tc.verdict, machine.Check(local, tc.packet))
		})
	}
}

// verifies that a table target matches the addresses of its networks of
// either family, negated or not, and that a missing table matches nothing.
func Test_VM_Check_Tables(t *testing.T) {
	rules := ruleset(`
		table t create type addr
		table t add 192.0.2.128/29
		table t add 198.51.100.0/25
		table t add 198.51.100.128/25
		table t add 2001:db8::/32
		add pass tcp from table(t) to table(t)
		add pass ip from not table(t) to 203.0.113.1
		add pass ip from table(none) to any
		add deny ip from any to any
	`)
	cases := []struct {
		name    string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "both in the table",
			packet:  tcp4("198.51.100.1", "192.0.2.128"),
			verdict: pass,
		},
		{
			name:    "source outside the table",
			packet:  tcp4("198.51.99.1", "192.0.2.128"),
			verdict: deny,
		},
		{
			name:    "destination outside the table",
			packet:  tcp4("198.51.100.1", "192.0.2.127"),
			verdict: deny,
		},
		{
			name:    "IPv6 entry",
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:1::1")).WithTCP(ipfw.TCPSyn, 50000, 22),
			verdict: pass,
		},
		{
			name:    "IPv6 outside the table",
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db9::1"), netip.MustParseAddr("2001:db8:1::1")).WithTCP(ipfw.TCPSyn, 50000, 22),
			verdict: deny,
		},
		{
			name:    "negated table",
			packet:  tcp4("203.0.113.9", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "negated table, address inside",
			packet:  tcp4("192.0.2.130", "203.0.113.1"),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that a registry passed in is the one the ruleset fills and the
// VM consults, and that a value loses its leading colon.
func Test_VM_Build_Tables(t *testing.T) {
	tables := vm.NewDefaultTableRegistry[net4, net6]()
	require.NoError(t, tables.AddNetwork4("pre", must4(t, "203.0.113.0/24"), ""))
	src := ruleset(`
		table i create type iface
		table i add vlan1 :LABEL
		table i add vlan2 plain
		table i add vlan3
		table pre add 192.0.2.0/24 :NET
		add pass ip from table(pre) to any
		add deny ip from any to any
	`)
	machine := build(t, src, vm.Config[net4, net6]{Tables: tables})
	require.Same(t, tables, machine.Tables())
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("203.0.113.7", "192.0.2.1")))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.7", "192.0.2.1")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("198.51.100.7", "192.0.2.1")))

	value, ok := machine.Tables().LookupInterface("i", "vlan1")
	require.True(t, ok)
	require.Equal(t, "LABEL", value)
	value, ok = machine.Tables().LookupNetwork("pre", netip.MustParseAddr("192.0.2.7"))
	require.True(t, ok)
	require.Equal(t, "NET", value)
	value, ok = machine.Tables().LookupInterface("i", "vlan2")
	require.True(t, ok)
	require.Equal(t, "plain", value)
	value, ok = machine.Tables().LookupInterface("i", "vlan3")
	require.True(t, ok)
	require.Empty(t, value)

	fresh := build(t, "table t create\n", none)
	require.NotNil(t, fresh.Tables())
	_, ok = fresh.Tables().LookupNetwork("t", netip.MustParseAddr("192.0.2.1"))
	require.False(t, ok)
}

// verifies that the type a create gives a table tells what its keys are, a
// table never created being an address table as in ipfw(8).
//
// An address table takes networks, and hostnames and custom tokens through the
// target resolver, an interface table every key as an interface name. A
// name standing for nothing adds nothing, the resolver's error fails the
// build at the line, and so do a missing resolver and a type the VM cannot
// hold.
func Test_VM_Build_TableTypes(t *testing.T) {
	v6 := func(src, dst string) vm.Packet {
		packet := vm.NewIPv6Packet(netip.MustParseAddr(src), netip.MustParseAddr(dst))
		return packet.WithTCP(ipfw.TCPSyn, 50000, 22)
	}
	src := ruleset(`
		table h create type addr
		table h add host.example.com
		table h add custom:first 7
		table h add nothing.example.com
		table a create
		table a add 2001:db8::/32
		add pass ip from table(h) to any
		add pass ip from any to table(a)
		add deny ip from any to any
	`)
	addr, err := vm.Build(
		ipfw.NewParser(src),
		vm.Config[net4, net6]{Environment: resolvingTargets},
	)
	require.NoError(t, err)
	require.Equal(t, pass, addr.Check(&vm.Context{}, tcp4("192.0.2.1", "203.0.113.1")))
	require.Equal(t, pass, addr.Check(&vm.Context{}, tcp4("198.51.100.7", "203.0.113.1")))
	require.Equal(t, deny, addr.Check(&vm.Context{}, tcp4("203.0.113.9", "203.0.113.1")))
	require.Equal(t, pass, addr.Check(&vm.Context{}, v6("2001:db8::1", "2001:db9::1")))
	require.Equal(t, pass, addr.Check(&vm.Context{}, v6("2001:db9::1", "2001:db8::5")))
	require.Equal(t, deny, addr.Check(&vm.Context{}, v6("2001:db9::1", "2001:db9::5")))
	value, ok := addr.Tables().LookupNetwork("h", netip.MustParseAddr("198.51.100.7"))
	require.True(t, ok)
	require.Equal(t, "7", value)
	value, ok = addr.Tables().LookupNetwork("h", netip.MustParseAddr("2001:db8::1"))
	require.True(t, ok)
	require.Empty(t, value)

	src = ruleset(`
		table i create type iface
		table i add 10 :L
		table i add host.example.com
	`)
	iface, err := vm.Build(
		ipfw.NewParser(src),
		vm.Config[net4, net6]{Environment: resolving},
	)
	require.NoError(t, err)
	value, ok = iface.Tables().LookupInterface("i", "10")
	require.True(t, ok)
	require.Equal(t, "L", value)
	_, ok = iface.Tables().LookupInterface("i", "host.example.com")
	require.True(t, ok)

	failing := []struct {
		name string
		src  string
		env  ipfw.Environment[net4, net6]
		err  error
	}{
		{
			name: "name the resolver rejects",
			src:  "table h add unknown.example.com\n",
			env:  resolvingTargets,
			err:  ipfw.ErrExpectedTarget,
		},
		{
			name: "table never created takes no interface name",
			src:  "table u add vlan1\n",
			env:  resolvingTargets,
			err:  ipfw.ErrExpectedTarget,
		},
		{
			name: "no resolver",
			src:  "table h add host.example.com\n",
			env:  resolving,
			err:  ipfw.ErrUnresolvedTarget,
		},
		{
			name: "number table",
			src:  "table n create type number\n",
			env:  resolving,
			err:  vm.ErrUnsupportedTableType,
		},
		{
			name: "flow table",
			src:  "table f create type flow\n",
			env:  resolving,
			err:  vm.ErrUnsupportedTableType,
		},
		{
			name: "mac table",
			src:  "table m create type mac\n",
			env:  resolving,
			err:  vm.ErrUnsupportedTableType,
		},
	}
	for _, tc := range failing {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vm.Build(
				ipfw.NewParser(tc.src),
				vm.Config[net4, net6]{Environment: tc.env},
			)
			require.ErrorIs(t, err, tc.err)
			var buildErr *vm.BuildError
			require.ErrorAs(t, err, &buildErr)
			require.Equal(t, 1, buildErr.Line)
		})
	}
}

type tableRegistryOperation uint8

const (
	tableRegistryNetwork4 tableRegistryOperation = iota
	tableRegistryNetwork6
	tableRegistryInterface
)

type tableRegistryError struct{}

func (m *tableRegistryError) Error() string {
	return "table registry rejected update"
}

type rejectingTableRegistry struct {
	*vm.DefaultTableRegistry[net4, net6]
	operation tableRegistryOperation
	cause     error
}

func newRejectingTableRegistry(
	operation tableRegistryOperation,
	cause error,
) *rejectingTableRegistry {
	return &rejectingTableRegistry{
		DefaultTableRegistry: vm.NewDefaultTableRegistry[net4, net6](),
		operation:            operation,
		cause:                cause,
	}
}

// AddNetwork4 rejects its selected update and otherwise delegates it.
func (m *rejectingTableRegistry) AddNetwork4(table string, network net4, value string) error {
	if m.operation == tableRegistryNetwork4 {
		return m.cause
	}
	return m.DefaultTableRegistry.AddNetwork4(table, network, value)
}

// AddNetwork6 rejects its selected update and otherwise delegates it.
func (m *rejectingTableRegistry) AddNetwork6(table string, network net6, value string) error {
	if m.operation == tableRegistryNetwork6 {
		return m.cause
	}
	return m.DefaultTableRegistry.AddNetwork6(table, network, value)
}

// AddInterface rejects its selected update and otherwise delegates it.
func (m *rejectingTableRegistry) AddInterface(table, ifname, value string) error {
	if m.operation == tableRegistryInterface {
		return m.cause
	}
	return m.DefaultTableRegistry.AddInterface(table, ifname, value)
}

// verifies that a rejected table update fails the build at its command and
// preserves the registry error.
func Test_VM_Build_TableRegistryError(t *testing.T) {
	cases := []struct {
		name        string
		rules       string
		environment ipfw.Environment[net4, net6]
		operation   tableRegistryOperation
		text        string
	}{
		{
			name: "direct IPv4 network",
			rules: ruleset(`
				table t create type addr
				table t add 192.0.2.0/24
			`),
			environment: resolving,
			operation:   tableRegistryNetwork4,
			text:        "table t add 192.0.2.0/24",
		},
		{
			name: "direct IPv6 network",
			rules: ruleset(`
				table t create type addr
				table t add 2001:db8::/32
			`),
			environment: resolving,
			operation:   tableRegistryNetwork6,
			text:        "table t add 2001:db8::/32",
		},
		{
			name: "resolved IPv4 network",
			rules: ruleset(`
				table t create type addr
				table t add custom:first
			`),
			environment: resolvingTargets,
			operation:   tableRegistryNetwork4,
			text:        "table t add custom:first",
		},
		{
			name: "resolved IPv6 network",
			rules: ruleset(`
				table t create type addr
				table t add host.example.com
			`),
			environment: resolvingTargets,
			operation:   tableRegistryNetwork6,
			text:        "table t add host.example.com",
		},
		{
			name: "interface",
			rules: ruleset(`
				table t create type iface
				table t add vlan1
			`),
			environment: resolving,
			operation:   tableRegistryInterface,
			text:        "table t add vlan1",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cause := &tableRegistryError{}
			machine, err := vm.Build(
				ipfw.NewParser(testCase.rules),
				vm.Config[net4, net6]{
					Environment: testCase.environment,
					Tables:      newRejectingTableRegistry(testCase.operation, cause),
				},
			)
			require.Nil(t, machine)
			require.Error(t, err)
			var buildErr *vm.BuildError
			require.ErrorAs(t, err, &buildErr)
			require.Equal(t, 2, buildErr.Line)
			require.Equal(t, testCase.text, buildErr.Text)
			require.ErrorIs(t, err, cause)
			var registryErr *tableRegistryError
			require.ErrorAs(t, err, &registryErr)
			require.Same(t, cause, registryErr)
		})
	}
}

// verifies that a record or an action of a kind the VM does not know, as
// a command hook may produce, is a build error at its line.
func Test_VM_Build_UnsupportedKinds(t *testing.T) {
	invented := func(line string, _ ipfw.State) (ipfw.Record, int, error) {
		if line[0] == 'f' {
			return ipfw.Record{Kind: 100}, len(line), nil
		}
		return ipfw.Record{
			Kind:        ipfw.RecordInstruction,
			Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: 100}},
		}, len(line), nil
	}
	cases := []struct {
		name  string
		rules string
		cause error
	}{
		{
			name: "record",
			rules: ruleset(`
				add pass ip from any to any
				frobnicate now
			`),
			cause: vm.ErrUnsupportedRecord,
		},
		{
			name: "action",
			rules: ruleset(`
				add pass ip from any to any
				warp somewhere
			`),
			cause: vm.ErrUnsupportedAction,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vm.Build(ipfw.NewParser(tc.rules, ipfw.WithCommandHook(invented)), vm.Config[net4, net6]{Environment: resolving})
			var buildErr *vm.BuildError
			require.ErrorAs(t, err, &buildErr)
			require.Equal(t, 2, buildErr.Line)
			require.ErrorIs(t, err, tc.cause)
		})
	}
}

// verifies that tokens emitted by a command hook for a non-instruction
// record do not become part of the next instruction.
func Test_VM_Build_CommandHookNonInstructionState(t *testing.T) {
	cases := []struct {
		name   string
		record ipfw.Record
	}{
		{
			name:   "empty",
			record: ipfw.Record{Kind: ipfw.RecordEmpty},
		},
		{
			name:   "comment",
			record: ipfw.Record{Kind: ipfw.RecordComment},
		},
		{
			name:   "label",
			record: ipfw.Record{Kind: ipfw.RecordLabel, Label: "HOOK"},
		},
		{
			name: "table",
			record: ipfw.Record{
				Kind:  ipfw.RecordTable,
				Table: ipfw.Table{Name: "hook", Kind: ipfw.TableCreate, Type: ipfw.TableTypeAddr},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := func(line string, state ipfw.State) (ipfw.Record, int, error) {
				if line != "custom" {
					return ipfw.Record{}, 0, nil
				}
				if err := state.OnSourceTarget(ipfw.Target{Kind: ipfw.TargetAny}); err != nil {
					return ipfw.Record{}, 0, err
				}
				return tc.record, len(line), nil
			}
			source := ruleset(`
				custom
				add pass ip from 192.0.2.0/24 to any
				add deny ip from any to any
			`)
			machine, err := vm.Build(
				ipfw.NewParser(source, ipfw.WithCommandHook(hook)),
				vm.Config[net4, net6]{Environment: resolving},
			)
			require.NoError(t, err)
			require.Equal(
				t,
				pass,
				machine.Check(&vm.Context{}, tcp4("192.0.2.1", "203.0.113.1")),
			)
			require.Equal(
				t,
				deny,
				machine.Check(&vm.Context{}, tcp4("198.51.100.1", "203.0.113.1")),
			)
		})
	}
}

// verifies that tokens emitted by a command hook remain part of its instruction.
func Test_VM_Build_CommandHookInstructionState(t *testing.T) {
	hook := func(line string, state ipfw.State) (ipfw.Record, int, error) {
		if line != "custom" {
			return ipfw.Record{}, 0, nil
		}
		if err := state.OnSourceTarget(ipfw.Target{
			Kind: ipfw.TargetNetwork4,
			Text: "192.0.2.0/24",
		}); err != nil {
			return ipfw.Record{}, 0, err
		}
		if err := state.OnDestinationTarget(ipfw.Target{Kind: ipfw.TargetAny}); err != nil {
			return ipfw.Record{}, 0, err
		}
		record := ipfw.Record{
			Kind:        ipfw.RecordInstruction,
			Instruction: ipfw.Instruction{Action: pass},
		}
		return record, len(line), nil
	}
	source := ruleset(`
		custom
		add deny ip from any to any
	`)
	machine, err := vm.Build(
		ipfw.NewParser(source, ipfw.WithCommandHook(hook)),
		vm.Config[net4, net6]{Environment: resolving},
	)
	require.NoError(t, err)
	require.Equal(
		t,
		pass,
		machine.Check(&vm.Context{}, tcp4("192.0.2.1", "203.0.113.1")),
	)
	require.Equal(
		t,
		deny,
		machine.Check(&vm.Context{}, tcp4("198.51.100.1", "203.0.113.1")),
	)
}

// setupHook parses the custom option `setup`.
func setupHook(rest string) (ipfw.Opt, int, error) {
	if strings.HasPrefix(rest, "setup") {
		return ipfw.Opt{Kind: ipfw.OptCustom, Text: "setup"}, len("setup"), nil
	}
	return ipfw.Opt{}, 0, ipfw.ErrUnknownOption
}

// setupMatcher matches `setup` as a TCP packet with SYN and without ACK.
func setupMatcher(opt ipfw.Opt, _ *vm.Context, pkt vm.Packet) bool {
	if opt.Text != "setup" {
		return false
	}
	flags, ok := pkt.TCPFlags()
	return ok && flags&(ipfw.TCPSyn|ipfw.TCPAck) == ipfw.TCPSyn
}

// verifies that a custom option is decided by the configured matcher under
// the fold's negation and grouping, and is a build error without one.
func Test_VM_Check_CustomOption(t *testing.T) {
	withMatcher := vm.Config[net4, net6]{Environment: resolving, OptionMatcher: setupMatcher}
	cases := []struct {
		name    string
		rules   string
		ctx     *vm.Context
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "setup, SYN",
			rules: ruleset(`
				add pass tcp from any to any setup
				add deny ip from any to any
			`),
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name: "setup, SYN with ACK",
			rules: ruleset(`
				add pass tcp from any to any setup
				add deny ip from any to any
			`),
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPSyn | ipfw.TCPAck),
			verdict: deny,
		},
		{
			name: "not setup, SYN",
			rules: ruleset(`
				add pass tcp from any to any not setup
				add deny ip from any to any
			`),
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: deny,
		},
		{
			name: "not setup, ACK",
			rules: ruleset(`
				add pass tcp from any to any not setup
				add deny ip from any to any
			`),
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: pass,
		},
		{
			name: "setup or in, ACK coming in",
			rules: ruleset(`
				add pass tcp from any to any { setup or in }
				add deny ip from any to any
			`),
			ctx:     &vm.Context{Direction: vm.In},
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: pass,
		},
		{
			name: "setup or in, SYN going out",
			rules: ruleset(`
				add pass tcp from any to any { setup or in }
				add deny ip from any to any
			`),
			ctx:     &vm.Context{Direction: vm.Out},
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name: "setup or in, ACK going out",
			rules: ruleset(`
				add pass tcp from any to any { setup or in }
				add deny ip from any to any
			`),
			ctx:     &vm.Context{Direction: vm.Out},
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine, err := vm.Build(ipfw.NewParser(tc.rules, ipfw.WithOptionHook(setupHook)), withMatcher)
			require.NoError(t, err)
			require.Equal(t, tc.verdict, machine.Check(tc.ctx, tc.packet))
		})
	}

	src := ruleset(`
		add pass ip from any to any
		add pass tcp from any to any established setup
	`)
	_, err := vm.Build(ipfw.NewParser(src, ipfw.WithOptionHook(setupHook)), vm.Config[net4, net6]{Environment: resolving})
	var buildErr *vm.BuildError
	require.ErrorAs(t, err, &buildErr)
	require.Equal(t, 2, buildErr.Line)
	require.Equal(t, "add pass tcp from any to any established setup", buildErr.Text)
	require.ErrorIs(t, err, vm.ErrUnsupportedOption)
	var parseErr *ipfw.ParseError
	require.ErrorAs(t, err, &parseErr)
	require.Equal(t, 41, parseErr.Column)
}

// verifies that options fold by the or-blocks and match patterns they carry,
// whoever placed them: every block holds, one pattern of a block holds, and
// the members of a pattern are alternatives under its negation.
func Test_VM_Check_OptionPlaces(t *testing.T) {
	port := func(neg bool, block, pattern, number uint16) ipfw.Opt {
		return ipfw.Opt{
			Neg:     neg,
			Block:   block,
			Pattern: pattern,
			Kind:    ipfw.OptDestinationPort,
			Ports:   ipfw.PortRange{Lo: ipfw.Port{Number: number}, Hi: ipfw.Port{Number: number}},
		}
	}
	packet := func(dst uint16) vm.Packet {
		return vm.NewIPv4Packet(
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("192.0.2.2"),
		).WithTCP(ipfw.TCPSyn, 50000, dst)
	}
	cases := []struct {
		name    string
		options []ipfw.Opt
		context vm.Context
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name: "patterns of one block are alternatives",
			options: []ipfw.Opt{
				{Kind: ipfw.OptIn},
				{Pattern: 1, Kind: ipfw.OptOut},
			},
			context: vm.Context{Direction: vm.Out},
			packet:  packet(22),
			verdict: pass,
		},
		{
			name: "every block has to hold",
			options: []ipfw.Opt{
				{Kind: ipfw.OptIn},
				{Block: 1, Kind: ipfw.OptOut},
			},
			context: vm.Context{Direction: vm.Out},
			packet:  packet(22),
			verdict: deny,
		},
		{
			name:    "a negated pattern rejects any of its members",
			options: []ipfw.Opt{port(true, 0, 0, 22), port(true, 0, 0, 80)},
			packet:  packet(80),
			verdict: deny,
		},
		{
			name:    "a negated pattern holds outside all of its members",
			options: []ipfw.Opt{port(true, 0, 0, 22), port(true, 0, 0, 80)},
			packet:  packet(443),
			verdict: pass,
		},
		{
			name: "a negated pattern then an alternative",
			options: []ipfw.Opt{
				port(true, 0, 0, 22),
				port(true, 0, 0, 80),
				{Pattern: 1, Kind: ipfw.OptIn},
			},
			context: vm.Context{Direction: vm.Out},
			packet:  packet(80),
			verdict: deny,
		},
		{
			name: "members of separate patterns are negated separately",
			options: []ipfw.Opt{
				port(true, 0, 0, 22),
				port(true, 0, 1, 80),
			},
			packet:  packet(80),
			verdict: pass,
		},
		{
			name: "a comment sharing its block stays an alternative",
			options: []ipfw.Opt{
				{Kind: ipfw.OptOut},
				{Pattern: 1, Kind: ipfw.OptComment, Text: "note"},
			},
			packet:  packet(22),
			verdict: pass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := func(line string, state ipfw.State) (ipfw.Record, int, error) {
				if line != "PLACED" {
					return ipfw.Record{}, 0, nil
				}
				if err := state.OnSourceTarget(ipfw.Target{Kind: ipfw.TargetAny}); err != nil {
					return ipfw.Record{}, 0, err
				}
				if err := state.OnDestinationTarget(ipfw.Target{Kind: ipfw.TargetAny}); err != nil {
					return ipfw.Record{}, 0, err
				}
				for _, opt := range tc.options {
					if err := state.OnOption(opt); err != nil {
						return ipfw.Record{}, 0, err
					}
				}
				record := ipfw.Record{
					Kind:        ipfw.RecordInstruction,
					Instruction: ipfw.Instruction{Action: pass},
				}
				return record, len(line), nil
			}
			src := "PLACED\nadd deny ip from any to any\n"
			machine, err := vm.Build(ipfw.NewParser(src, ipfw.WithCommandHook(hook)), none)
			require.NoError(t, err)
			require.Equal(t, tc.verdict, machine.Check(&tc.context, tc.packet))
		})
	}
}

// verifies that a decided option expression does not invoke a later custom matcher.
func Test_VM_Check_OptionShortCircuit_Custom(t *testing.T) {
	calls := 0
	matcher := func(ipfw.Opt, *vm.Context, vm.Packet) bool {
		calls++
		return false
	}
	cases := []struct {
		name      string
		option    string
		direction vm.Direction
		verdict   ipfw.Action
	}{
		{
			name:      "successful OR term",
			option:    "{ in or setup }",
			direction: vm.In,
			verdict:   pass,
		},
		{
			name:      "failed AND term",
			option:    "out setup",
			direction: vm.In,
			verdict:   deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls = 0
			src := ruleset("\nadd pass ip from any to any " + tc.option +
				"\nadd deny ip from any to any\n")
			machine, err := vm.Build(
				ipfw.NewParser(src, ipfw.WithOptionHook(setupHook)),
				vm.Config[net4, net6]{Environment: resolving, OptionMatcher: matcher},
			)
			require.NoError(t, err)
			packet := tcp4("192.0.2.1", "192.0.2.2")
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{Direction: tc.direction}, packet))
			require.Zero(t, calls)
		})
	}
}

// verifies that a check through the custom matcher allocates nothing.
func Test_VM_CustomOption_NoAllocs(t *testing.T) {
	src := ruleset(`
		add deny tcp from any to any not setup
		add pass tcp from any to any { setup or in }
		add deny ip from any to any
	`)
	machine, err := vm.Build(
		ipfw.NewParser(src, ipfw.WithOptionHook(setupHook)),
		vm.Config[net4, net6]{Environment: resolving, OptionMatcher: setupMatcher},
	)
	require.NoError(t, err)
	packet := tcp4Flags(ipfw.TCPSyn)
	ctx := &vm.Context{}
	verdict := pass
	allocs := testing.AllocsPerRun(100, func() {
		if machine.Check(ctx, packet) != pass {
			verdict = deny
		}
	})
	require.Equal(t, pass, verdict)
	require.Zero(t, allocs)
}

// verifies the fixed policy of the options the VM does not emulate:
// keep-state and a comment hold, diverted never, antispoof on the way out.
func Test_VM_Check_PolicyOptions(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.2")
	cases := []struct {
		option string
		in     ipfw.Action
		out    ipfw.Action
	}{
		{option: "keep-state", in: pass, out: pass},
		{option: "not keep-state", in: deny, out: deny},
		{option: "keep-state :flow", in: pass, out: pass},
		{option: "not keep-state :flow", in: deny, out: deny},
		{option: "diverted", in: deny, out: deny},
		{option: "not diverted", in: pass, out: pass},
		{option: "antispoof", in: deny, out: pass},
		{option: "not antispoof", in: pass, out: deny},
		{option: "// note", in: pass, out: pass},
		{option: "not // note", in: deny, out: deny},
	}
	for _, tc := range cases {
		t.Run(tc.option, func(t *testing.T) {
			src := ruleset(`

				add deny ip from any to any
			`)
			parser := ipfw.NewParser("add pass ip from any to any " + tc.option + src)
			machine, err := vm.Build(parser, vm.Config[net4, net6]{Environment: resolving})
			require.NoError(t, err)
			require.Equal(t, tc.in, machine.Check(&vm.Context{Direction: vm.In}, packet))
			require.Equal(t, tc.out, machine.Check(&vm.Context{Direction: vm.Out}, packet))
		})
	}
}

// verifies that a comment holds for every packet and a negated one for none,
// wherever it stands among the options, without allocating on a check.
func Test_VM_Check_CommentOption(t *testing.T) {
	note := func(rest string) (ipfw.Opt, int, error) {
		if strings.HasPrefix(rest, "note") {
			return ipfw.Opt{Kind: ipfw.OptComment, Text: "note"}, len("note"), nil
		}
		return ipfw.Opt{}, 0, ipfw.ErrUnknownOption
	}
	cases := []struct {
		name string
		rule string
		in   ipfw.Action
		out  ipfw.Action
	}{
		{name: "comment-only rule", rule: "add 100 // note", in: deny, out: deny},
		{
			name: "comment after the body",
			rule: "add pass ip from any to any // x",
			in:   pass,
			out:  pass,
		},
		{
			name: "comment after an option",
			rule: "add pass ip from any to any out // x",
			in:   deny,
			out:  pass,
		},
		{
			name: "negated comment",
			rule: "add pass ip from any to any not // x",
			in:   deny,
			out:  deny,
		},
		{name: "negated comment body", rule: "add pass not // x", in: deny, out: deny},
		{
			name: "hook comment opening a group",
			rule: "add pass ip from any to any { note or out }",
			in:   pass,
			out:  pass,
		},
		{
			name: "hook comment closing a group",
			rule: "add pass ip from any to any { out or note }",
			in:   pass,
			out:  pass,
		},
		{
			name: "hook comment before a group",
			rule: "add pass ip from any to any note { out or out }",
			in:   deny,
			out:  pass,
		},
	}
	packet := tcp4("192.0.2.1", "192.0.2.2")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.rule + "\nadd deny ip from any to any\n"
			machine := build(t, src, none, ipfw.WithOptionHook(note))
			require.Equal(t, tc.in, machine.Check(&vm.Context{Direction: vm.In}, packet))
			require.Equal(t, tc.out, machine.Check(&vm.Context{Direction: vm.Out}, packet))
		})
	}
	src := ruleset(`
		add 100 // note
		add pass ip from any to any not // x
		add pass ip from any to any in note { out or out } // x
		add pass ip from any to any { out or note } // x
	`)
	machine := build(t, src, none, ipfw.WithOptionHook(note))
	ctx := &vm.Context{Direction: vm.In}
	verdict := deny
	allocs := testing.AllocsPerRun(100, func() {
		verdict = machine.Check(ctx, packet)
	})
	require.Equal(t, pass, verdict)
	require.Zero(t, allocs)
}

type countingTableRegistry struct {
	vm.TableRegistry[net4, net6]
	lookupInterfaceCalls int
}

// LookupInterface records an interface lookup before delegating it.
func (m *countingTableRegistry) LookupInterface(table, ifname string) (string, bool) {
	m.lookupInterfaceCalls++
	return m.TableRegistry.LookupInterface(table, ifname)
}

// LookupInterfaceCalls returns how many interface lookups were delegated.
func (m *countingTableRegistry) LookupInterfaceCalls() int {
	return m.lookupInterfaceCalls
}

// verifies that a successful OR member suppresses a later tablearg lookup and jump.
func Test_VM_Check_OptionShortCircuit_TableArg(t *testing.T) {
	tables := &countingTableRegistry{
		TableRegistry: vm.NewDefaultTableRegistry[net4, net6](),
	}
	src := ruleset(`
		table jump create type iface
		table jump add vlan0 :ALLOW
		add skipto tablearg ip from any to any { in or via table(jump) }
		add deny ip from any to any
		:ALLOW
		add pass ip from any to any
	`)
	machine := build(t, src, vm.Config[net4, net6]{Tables: tables}, ipfw.WithLabels())
	packet := tcp4("192.0.2.1", "192.0.2.2")
	ctx := &vm.Context{Direction: vm.In, IfName: "vlan0"}
	require.Equal(t, deny, machine.Check(ctx, packet))
	require.Zero(t, tables.LookupInterfaceCalls())
}

// verifies that tablearg uses the last successful lookup that was actually evaluated.
func Test_VM_Check_TableArgLastLookup(t *testing.T) {
	cases := []struct {
		name        string
		options     string
		secondValue string
		first       string
		second      string
		verdict     ipfw.Action
	}{
		{
			name:        "second hit replaces negated first hit",
			options:     "{ not via table(first) or via table(second) }",
			secondValue: ":SECOND",
			first:       "deny",
			second:      "pass",
			verdict:     pass,
		},
		{
			name:        "miss preserves first hit",
			options:     "{ not via table(first) or not via table(missing) }",
			secondValue: ":SECOND",
			first:       "pass",
			second:      "deny",
			verdict:     pass,
		},
		{
			name:        "skipped second hit preserves first hit",
			options:     "{ via table(first) or via table(second) }",
			secondValue: ":SECOND",
			first:       "pass",
			second:      "deny",
			verdict:     pass,
		},
		{
			name:        "unresolved second hit clears first hit",
			options:     "{ not via table(first) or via table(second) }",
			secondValue: ":MISSING",
			first:       "pass",
			second:      "deny",
			verdict:     deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := ruleset("\ntable first create type iface\n" +
				"table second create type iface\n" +
				"table first add vlan0 :FIRST\n" +
				"table second add vlan0 " + tc.secondValue + "\n" +
				"add skipto tablearg ip from any to any " + tc.options + "\n" +
				"add deny ip from any to any\n" +
				":FIRST\nadd " + tc.first + " ip from any to any\n" +
				":SECOND\nadd " + tc.second + " ip from any to any\n")
			machine := build(t, src, none, ipfw.WithLabels())
			packet := tcp4("192.0.2.1", "192.0.2.2")
			ctx := &vm.Context{IfName: "vlan0"}
			require.Equal(t, tc.verdict, machine.Check(ctx, packet))
		})
	}
}

// verifies that skipto tablearg jumps where the last address or via table
// lookup that found an entry names, in the order ipfw_chk looks them up.
//
// The source goes before the destination and both before the options. A
// lookup found under a negation still names the target, a lookup an earlier
// alternative made needless never happens, and an entry naming no rule
// clears the target, falling through.
func Test_VM_Check_TableArgAddress(t *testing.T) {
	src := ruleset(`
		table src add 192.0.2.0/24 :NET
		table src add 192.0.2.128/25 :HALF
		table src add 2001:db8::/32 :NET
		table dst add 203.0.113.0/24 :DST
		table dst add 2001:db8:1::/48 500
		table odd add 203.0.113.0/24 :MISSING
		table i create type iface
		table i add vlan0 :IFACE
		add skipto tablearg ip from %s
		add deny ip from any to any
		:NET
		add pass ip from any to any
		:HALF
		add pass ip from any to any
		:DST
		add pass ip from any to any
		:IFACE
		add pass ip from any to any
		add 500 pass ip from any to any
	`)
	jumped := traced{line: 9, action: ipfw.ActionSkipTo, matched: true}
	fell := traced{line: 10, action: ipfw.ActionDeny, matched: true}
	landed := func(line int) traced {
		return traced{line: line, action: ipfw.ActionPass, matched: true}
	}
	v6 := func(src, dst string) vm.Packet {
		return vm.NewIPv6Packet(netip.MustParseAddr(src), netip.MustParseAddr(dst))
	}
	cases := []struct {
		name   string
		body   string
		packet vm.Packet
		seen   []traced
	}{
		{
			name:   "source entry",
			body:   "table(src) to any",
			packet: tcp4("192.0.2.1", "198.51.100.1"),
			seen:   []traced{jumped, landed(12)},
		},
		{
			name:   "most specific source entry",
			body:   "table(src) to any",
			packet: tcp4("192.0.2.130", "198.51.100.1"),
			seen:   []traced{jumped, landed(14)},
		},
		{
			name:   "IPv6 source entry",
			body:   "table(src) to any",
			packet: v6("2001:db8::1", "2001:db9::1"),
			seen:   []traced{jumped, landed(12)},
		},
		{
			name:   "source not in the table",
			body:   "table(src) to any",
			packet: tcp4("198.51.100.1", "198.51.100.2"),
			seen: []traced{
				{line: 9, action: ipfw.ActionSkipTo},
				fell,
			},
		},
		{
			name:   "numbered destination entry",
			body:   "any to table(dst)",
			packet: v6("2001:db9::1", "2001:db8:1::1"),
			seen:   []traced{jumped, landed(19)},
		},
		{
			name:   "destination replaces source",
			body:   "table(src) to table(dst)",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, landed(16)},
		},
		{
			name:   "destination without lookup keeps source",
			body:   "table(src) to 203.0.113.0/24",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, landed(12)},
		},
		{
			name:   "destination naming no rule clears source",
			body:   "table(src) to table(odd)",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, fell},
		},
		{
			name:   "via table replaces addresses",
			body:   "table(src) to table(dst) via table(i)",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, landed(18)},
		},
		{
			name:   "option without lookup keeps addresses",
			body:   "table(src) to any in",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, landed(12)},
		},
		{
			name:   "negated lookup found names the target",
			body:   "{ not table(src) or 192.0.2.0/24 } to any",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, landed(12)},
		},
		{
			name:   "alternative before the lookup skips it",
			body:   "{ 192.0.2.0/24 or table(src) } to any",
			packet: tcp4("192.0.2.1", "203.0.113.1"),
			seen:   []traced{jumped, fell},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, fmt.Sprintf(src, tc.body), none, ipfw.WithLabels())
			tracer := &recordingTracer{}
			_, matched := machine.CheckTrace(&vm.Context{IfName: "vlan0"}, tc.packet, tracer)
			require.True(t, matched)
			require.Equal(t, tc.seen, tracer.seen)
		})
	}
}

// verifies that table(NAME,VALUE) holds an address only when the entry
// holding it has the value, the most specific entry deciding.
//
// Two numbers compare as numbers and any other value as text, a leading colon
// dropped on either side as the build drops it from an entry's value.
func Test_VM_Check_TableValue(t *testing.T) {
	src := ruleset(`
		table t add 192.0.2.0/24 100
		table t add 192.0.2.128/25 :HALF
		table t add 2001:db8::/32 0100
		add pass ip from %s to any
		add deny ip from any to any
	`)
	v6 := vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"))
	cases := []struct {
		name    string
		target  string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "entry with the value",
			target:  "table(t,100)",
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "more specific entry with another value",
			target:  "table(t,100)",
			packet:  tcp4("192.0.2.130", "203.0.113.1"),
			verdict: deny,
		},
		{
			name:    "label value",
			target:  "table(t,:HALF)",
			packet:  tcp4("192.0.2.130", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "label value without the colon",
			target:  "table(t,HALF)",
			packet:  tcp4("192.0.2.130", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "equal numbers written apart",
			target:  "table(t,0100)",
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "IPv6 entry with an equal number",
			target:  "table(t,100)",
			packet:  v6,
			verdict: pass,
		},
		{
			name:    "no entry",
			target:  "table(t,100)",
			packet:  tcp4("198.51.100.1", "203.0.113.1"),
			verdict: deny,
		},
		{
			name:    "negated, entry with another value",
			target:  "not table(t,100)",
			packet:  tcp4("192.0.2.130", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "negated, entry with the value",
			target:  "not table(t,100)",
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, fmt.Sprintf(src, tc.target), none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that a lookup whose entry has another value than the target asks
// for names no tablearg target, one with the value does.
func Test_VM_Check_TableValueTableArg(t *testing.T) {
	src := ruleset(`
		table j add 192.0.2.0/24 :NET
		add skipto tablearg ip from { not table(j,%s) or 192.0.2.0/24 } to any
		add deny ip from any to any
		:NET
		add pass ip from any to any
	`)
	packet := tcp4("192.0.2.1", "203.0.113.1")
	other := build(t, fmt.Sprintf(src, ":OTHER"), none, ipfw.WithLabels())
	require.Equal(t, deny, other.Check(&vm.Context{}, packet))
	same := build(t, fmt.Sprintf(src, ":NET"), none, ipfw.WithLabels())
	require.Equal(t, pass, same.Check(&vm.Context{}, packet))
}

// verifies that symbolic tablearg resolves labels supplied by an explicit option or command hook.
func Test_VM_Build_TableArgLabelsOptIn(t *testing.T) {
	source := ruleset(`
		table jump create type iface
		table jump add vlan42 :NEXT
		add skipto tablearg ip from any to any via table(jump)
		add deny ip from any to any
		:NEXT
		add pass ip from any to any
	`)
	machine, err := vm.Build(ipfw.NewParser(source), none)
	require.Nil(t, machine)
	require.ErrorIs(t, err, ipfw.ErrExpectedLine)
	var positioned *ipfw.ParseError
	require.ErrorAs(t, err, &positioned)
	require.Equal(t, ipfw.ParseError{
		Kind: ipfw.ErrExpectedLine, Line: 5, Text: ":NEXT",
	}, *positioned)

	machine, err = vm.Build(ipfw.NewParser(source, ipfw.WithLabels()), none)
	require.NoError(t, err)
	packet := tcp4("192.0.2.1", "203.0.113.2")
	require.Equal(t, pass, machine.Check(&vm.Context{IfName: "vlan42"}, packet))
	require.Equal(t, deny, machine.Check(&vm.Context{IfName: "vlan43"}, packet))

	hook := func(line string, _ ipfw.State) (ipfw.Record, int, error) {
		if line != ":NEXT" {
			return ipfw.Record{}, 0, nil
		}
		return ipfw.Record{Kind: ipfw.RecordLabel, Label: line[1:]}, len(line), nil
	}
	machine, err = vm.Build(ipfw.NewParser(source, ipfw.WithCommandHook(hook)), none)
	require.NoError(t, err)
	require.Equal(t, pass, machine.Check(&vm.Context{IfName: "vlan42"}, packet))
	require.Equal(t, deny, machine.Check(&vm.Context{IfName: "vlan43"}, packet))

	withoutLabel := ruleset(`
		table jump create type iface
		table jump add vlan42 :NEXT
		add skipto tablearg ip from any to any via table(jump)
		add deny ip from any to any
		add pass ip from any to any
	`)
	machine, err = vm.Build(ipfw.NewParser(withoutLabel), none)
	require.NoError(t, err)
	require.Equal(t, deny, machine.Check(&vm.Context{IfName: "vlan42"}, packet))
}

// verifies that via table(NAME) matches an interface the table lists and
// that skipto tablearg then continues at the label the entry's value names.
//
// A value naming no label, or a label before the rule, falls through to the
// next rule, and an entry added after the build counts.
func Test_VM_Check_TableArg(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.2")
	src := ruleset(`
		table t create type iface

		add skipto tablearg ip from any to any via table(t) in
		table t add vlan1234 :INBOUND
		add deny ip from any to any

		:INBOUND
		add pass ip from any to any
	`)
	tablearg := build(t, src, none, ipfw.WithLabels())
	require.Equal(t, pass, tablearg.Check(&vm.Context{IfName: "vlan1234"}, packet))
	require.Equal(t, deny, tablearg.Check(&vm.Context{IfName: "eth0"}, packet))
	require.Equal(t, deny, tablearg.Check(&vm.Context{IfName: "vlan1234", Direction: vm.Out}, packet))

	src = ruleset(`
		table j create type iface
		table j add vlan1 :ONE
		table j add vlan2 :TWO
		table j add vlan3 :NOWHERE
		add skipto tablearg ip from any to any via table(j)
		add deny ip from any to any
		:ONE
		add pass ip from any to any
		:TWO
		add count ip from any to any
		add deny ip from any to any
	`)
	two := build(t, src, none, ipfw.WithLabels())
	cases := []struct {
		ifname  string
		verdict ipfw.Action
		seen    []traced
	}{
		{
			ifname:  "vlan1",
			verdict: pass,
			seen: []traced{
				{line: 5, action: ipfw.ActionSkipTo, matched: true},
				{line: 8, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			ifname:  "vlan2",
			verdict: deny,
			seen: []traced{
				{line: 5, action: ipfw.ActionSkipTo, matched: true},
				{line: 10, action: ipfw.ActionCount, matched: true},
				{line: 11, action: ipfw.ActionDeny, matched: true},
			},
		},
		{
			ifname:  "vlan3",
			verdict: deny,
			seen: []traced{
				{line: 5, action: ipfw.ActionSkipTo, matched: true},
				{line: 6, action: ipfw.ActionDeny, matched: true},
			},
		},
		{
			ifname:  "vlan4",
			verdict: deny,
			seen: []traced{
				{line: 5, action: ipfw.ActionSkipTo, matched: false},
				{line: 6, action: ipfw.ActionDeny, matched: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.ifname, func(t *testing.T) {
			tracer := &recordingTracer{}
			action, matched := two.CheckTrace(&vm.Context{IfName: tc.ifname}, packet, tracer)
			require.True(t, matched)
			require.Equal(t, tc.verdict, action)
			require.Equal(t, tc.seen, tracer.seen)
		})
	}

	require.NoError(t, two.Tables().AddInterface("j", "vlan4", "ONE"))
	require.Equal(t, pass, two.Check(&vm.Context{IfName: "vlan4"}, packet))

	src = ruleset(`
		table j create type iface
		add count ip from any to any
		:BACK
		table j add vlan1 :BACK
		add skipto tablearg ip from any to any via table(j)
		add pass ip from any to any
	`)
	backward := build(t, src, none, ipfw.WithLabels())
	tracer := &recordingTracer{}
	action, matched := backward.CheckTrace(&vm.Context{IfName: "vlan1"}, packet, tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 2, action: ipfw.ActionCount, matched: true},
		{line: 5, action: ipfw.ActionSkipTo, matched: true},
		{line: 6, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)

	src = ruleset(`
		table t create type iface
		table t add eth0 whatever
		add pass ip from any to any via table(t)
		add pass ip from any to any not via table(t) in
		add deny ip from any to any
	`)
	plain := build(t, src, none)
	require.Equal(t, pass, plain.Check(&vm.Context{IfName: "eth0"}, packet))
	require.Equal(t, pass, plain.Check(&vm.Context{IfName: "eth1"}, packet))
	require.Equal(t, deny, plain.Check(&vm.Context{IfName: "eth1", Direction: vm.Out}, packet))
	require.Equal(t, pass, plain.Check(&vm.Context{IfName: "eth0", Direction: vm.Out}, packet))
}

// verifies that a check through a table jump allocates nothing.
func Test_VM_TableArg_NoAllocs(t *testing.T) {
	src := ruleset(`
		table j create type iface
		table j add vlan1 :ONE
		add skipto tablearg ip from any to any via table(j)
		add deny ip from any to any
		:ONE
		add pass ip from any to any
	`)
	machine := build(t, src, none, ipfw.WithLabels())
	packet := tcp4("192.0.2.1", "192.0.2.2")
	ctx := &vm.Context{IfName: "vlan1"}
	verdict := pass
	allocs := testing.AllocsPerRun(100, func() {
		if machine.Check(ctx, packet) != pass {
			verdict = deny
		}
	})
	require.Equal(t, pass, verdict)
	require.Zero(t, allocs)
}

// verifies that every build error is located at its line and wraps its
// cause.
//
// A line that does not parse, an action, ports and options the VM does not
// take yet, a protocol name with no resolver, a hostname, table entries.
func Test_VM_Build_Errors(t *testing.T) {
	cases := []struct {
		name        string
		rules       string
		environment ipfw.Environment[net4, net6]
		options     []ipfw.ParserOption
		line        int
		text        string
		cause       error
	}{
		{
			name: "parse error",
			rules: ruleset(`
				add pass ip from any to any
				add foobar :any
			`),
			environment: resolving,
			line:        2,
			text:        "add foobar :any",
			cause:       ipfw.ErrExpectedAction,
		},
		{
			name:        "table value by name",
			rules:       "add pass ip from any to table(t,skipto=100)\n",
			environment: resolving,
			line:        1,
			text:        "add pass ip from any to table(t,skipto=100)",
			cause:       vm.ErrUnsupportedTableValue,
		},
		{
			name: "rule number going backwards",
			rules: ruleset(`
				add 100 pass ip from any to any
				add 50 deny ip from any to any
			`),
			environment: resolving,
			line:        2,
			text:        "add 50 deny ip from any to any",
			cause:       vm.ErrRuleNumberOrder,
		},
		{
			name: "rule number repeated",
			rules: ruleset(`
				add 100 pass ip from any to any
				add 100 deny ip from any to any
			`),
			environment: resolving,
			line:        2,
			text:        "add 100 deny ip from any to any",
			cause:       vm.ErrRuleNumberOrder,
		},
		{
			name: "rule after the largest rule number",
			rules: ruleset(`
				add 4294967295 count ip from any to any
				add pass ip from any to any
			`),
			environment: resolving,
			line:        2,
			text:        "add pass ip from any to any",
			cause:       vm.ErrRuleNumberOrder,
		},
		{
			name: "skipto to a number that never appears",
			rules: ruleset(`
				add deny udp from any to any
				add skipto 7 ip from any to any
				add pass ip from any to any
			`),
			environment: resolving,
			line:        2,
			text:        "add skipto 7 ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name: "skipto its own number as the last rule",
			rules: ruleset(`
				add pass udp from any to any
				add 50 skipto 50 ip from any to any
			`),
			environment: resolving,
			line:        2,
			text:        "add 50 skipto 50 ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name: "skipto backwards as the last rule",
			rules: ruleset(`
				add 50 pass udp from any to any
				add 100 skipto 50 ip from any to any
			`),
			environment: resolving,
			line:        2,
			text:        "add 100 skipto 50 ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name: "skipto to a label that never appears",
			rules: ruleset(`
				add skipto :NOWHERE ip from any to any
				add pass ip from any to any
			`),
			environment: resolving,
			options:     []ipfw.ParserOption{ipfw.WithLabels()},
			line:        1,
			text:        "add skipto :NOWHERE ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name: "skipto to a label before it",
			rules: ruleset(`
				add count ip from any to any
				:BACK
				add skipto :BACK ip from any to any
			`),
			environment: resolving,
			options:     []ipfw.ParserOption{ipfw.WithLabels()},
			line:        3,
			text:        "add skipto :BACK ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name:        "service name without a resolver",
			rules:       "add pass tcp from any ssh to any\n",
			environment: resolving,
			line:        1,
			text:        "add pass tcp from any ssh to any",
			cause:       ipfw.ErrUnresolvedService,
		},
		{
			name:        "unresolved service name",
			rules:       "add pass tcp from any to any 22,bogus\n",
			environment: resolvingServices,
			line:        1,
			text:        "add pass tcp from any to any 22,bogus",
			cause:       ipfw.ErrUnresolvedService,
		},
		{
			name:        "proto option name without a resolver",
			rules:       "add pass ip from any to any proto tcp\n",
			environment: networksOnly,
			line:        1,
			text:        "add pass ip from any to any proto tcp",
			cause:       ipfw.ErrUnresolvedProto,
		},
		{
			name: "IPv4 table entry that does not parse",
			rules: ruleset(`
				table t add 192.0.2.0/24
				table t add 192.0.2.0/33
			`),
			environment: resolving,
			line:        2,
			text:        "table t add 192.0.2.0/33",
			cause:       ipfw.ErrExpectedIPv4Network,
		},
		{
			name:        "IPv6 table entry that does not parse",
			rules:       "table t add 2001:db8::/129\n",
			environment: resolving,
			line:        1,
			text:        "table t add 2001:db8::/129",
			cause:       ipfw.ErrExpectedIPv6Network,
		},
		{
			name:        "unresolved protocol without a resolver",
			rules:       "add pass tcp from any to any\n",
			environment: networksOnly,
			line:        1,
			text:        "add pass tcp from any to any",
			cause:       ipfw.ErrUnresolvedProto,
		},
		{
			name:        "unresolved protocol name",
			rules:       "add pass gre from any to any\n",
			environment: resolving,
			line:        1,
			text:        "add pass gre from any to any",
			cause:       ipfw.ErrUnresolvedProto,
		},
		{
			name:        "protocol unknown to the proto checker",
			rules:       "add pass gre from any to any\n",
			environment: resolving,
			options:     []ipfw.ParserOption{ipfw.WithProtoChecker(protoChecker(fakeProtos{}))},
			line:        1,
			text:        "add pass gre from any to any",
			cause:       ipfw.ErrUnknownOption,
		},
		{
			name:        "hostname without a resolver",
			rules:       "add pass ip from host.example.com to any\n",
			environment: resolving,
			line:        1,
			text:        "add pass ip from host.example.com to any",
			cause:       ipfw.ErrUnresolvedTarget,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vm.Build(
				ipfw.NewParser(tc.rules, tc.options...),
				vm.Config[net4, net6]{Environment: tc.environment},
			)
			require.Error(t, err)
			var buildErr *vm.BuildError
			require.ErrorAs(t, err, &buildErr)
			require.Equal(t, tc.line, buildErr.Line)
			require.Equal(t, tc.text, buildErr.Text)
			require.ErrorIs(t, err, tc.cause)
			require.Equal(t, strconv.Itoa(tc.line)+": "+tc.text+": "+buildErr.Err.Error(), err.Error())
		})
	}
}

// verifies that a parse error keeps its position inside the build error.
func Test_VM_Build_ParseError(t *testing.T) {
	src := ruleset(`
		add pass ip from any to any
		  add foobar :any
	`)
	_, err := vm.Build(ipfw.NewParser(src), vm.Config[net4, net6]{Environment: resolving})
	var parseErr *ipfw.ParseError
	require.ErrorAs(t, err, &parseErr)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedAction,
		Line:   2,
		Column: 4,
		Text:   "add foobar :any",
	}, *parseErr)
}

// verifies that network parser causes survive rule and table build errors.
func Test_VM_Build_NetworkErrorCause(t *testing.T) {
	cases := []struct {
		name       string
		rules      string
		kind       ipfw.ErrorKind
		parseError bool
	}{
		{
			name:       "IPv4 rule",
			rules:      "add pass ip from 192.0.2.1 to any\n",
			kind:       ipfw.ErrExpectedIPv4Network,
			parseError: true,
		},
		{
			name:       "IPv6 rule",
			rules:      "add pass ip from any to 2001:db8::1\n",
			kind:       ipfw.ErrExpectedIPv6Network,
			parseError: true,
		},
		{
			name:  "IPv4 table key",
			rules: "table t add 192.0.2.1\n",
			kind:  ipfw.ErrExpectedIPv4Network,
		},
		{
			name:  "IPv6 table key",
			rules: "table t add 2001:db8::1\n",
			kind:  ipfw.ErrExpectedIPv6Network,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause := &networkParserError{text: "network parser failed"}
			environment := ipfw.Environment[net4, net6]{
				Networks: ipfw.NetworkParserFuncs[net4, net6]{
					Parse4: func(string) (net4, error) { return net4{}, cause },
					Parse6: func(string) (net6, error) { return net6{}, cause },
				},
			}
			_, err := vm.Build(
				ipfw.NewParser(tc.rules),
				vm.Config[net4, net6]{Environment: environment},
			)
			require.Error(t, err)
			var buildErr *vm.BuildError
			require.ErrorAs(t, err, &buildErr)
			require.ErrorIs(t, err, tc.kind)
			require.ErrorIs(t, err, cause)
			var kind ipfw.ErrorKind
			require.ErrorAs(t, err, &kind)
			require.Equal(t, tc.kind, kind)
			var parserErr *networkParserError
			require.ErrorAs(t, err, &parserErr)
			require.Same(t, cause, parserErr)
			var parseErr *ipfw.ParseError
			require.Equal(t, tc.parseError, errors.As(err, &parseErr))
			if tc.parseError {
				require.Equal(t, tc.kind, parseErr.Kind)
			}
		})
	}
}

// verifies that a numeric protocol needs no resolver.
func Test_VM_Build_NumericProto(t *testing.T) {
	src := ruleset(`
		add pass 6 from any to any
		add deny ip from any to any
	`)
	machine, err := vm.Build(
		ipfw.NewParser(src),
		vm.Config[net4, net6]{Environment: networksOnly},
	)
	require.NoError(t, err)
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1")))
}

// anyTargets stands every hostname and custom token for one network of each
// family.
type anyTargets struct{}

// ResolveTarget implements ipfw.TargetResolver.
func (anyTargets) ResolveTarget(ipfw.Target) ([]net4, []net6, error) {
	return []net4{parse4("192.0.2.0/28")}, []net6{parse6("2001:db8::/64")}, nil
}

// everyMatcher is a ruleset touching every matcher of the VM, so that a
// check of it reaches all of them whatever the packet is.
var everyMatcher = ruleset(`
	table t add 203.0.113.0/24
	table i create type iface
	table i add vlan1234 :SECTION
	add deny udp from 198.51.100.0/24 to table(t) 53
	add count ip from any to any icmptypes 0,7,8,31
	add count ip from any to any icmp6types 0,5,128,129,150,201
	add deny tcp from any 1-1023 to me6 not established
	add deny ip from host.example.com to custom:first frag
	add count tcp from any to any tcpflags syn,!ack dst-port 8080,8443
	add count ip from any to any { proto 17 or out } keep-state :flow
	add skipto tablearg ip from any to any via table(i) in
	:SECTION
	add deny ip from not me to { table(t) or 2001:db8::/32 } antispoof
	add pass tcp from 192.0.2.0/24 not 25 to any 443 via vlan1??? established
	add deny ip from any to any
`)

// everyMatcherVM builds the ruleset above, whose jump goes to its label
// and whose names any resolver serves.
func everyMatcherVM(t *testing.T) *vm.VM[net4, net6] {
	t.Helper()
	machine, err := vm.Build(ipfw.NewParser(everyMatcher, ipfw.WithLabels()), vm.Config[net4, net6]{
		Environment: ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}, Targets: anyTargets{}},
	})
	require.NoError(t, err)
	return machine
}

// syntheticContext is a check environment exercising me, via and in.
var syntheticContext = &vm.Context{
	Direction:  vm.In,
	IfName:     "vlan1234",
	LocalAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
}

// syntheticPackets are packets of every shape the matchers look at.
var syntheticPackets = map[string]vm.Packet{
	"tcp4 syn":  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.5")).WithTCP(ipfw.TCPSyn, 40000, 443),
	"tcp4 ack":  vm.NewIPv4Packet(netip.MustParseAddr("198.51.100.5"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPAck, 22, 40000),
	"tcp4 pass": vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.5")).WithTCP(ipfw.TCPAck, 40000, 443),
	"udp4":      vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.200")).WithUDP(53, 53),
	"icmp4":     vm.NewIPv4Packet(netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("192.0.2.1")).WithICMP(8, 0),
	"fragment4": vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.5")).WithFragmentOffset(100),
	"tcp6":      vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("2001:db8:1::5")).WithTCP(ipfw.TCPSyn|ipfw.TCPAck, 40000, 80),
	"icmp6":     vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")).WithICMP6(128, 0),

	"icmp4 numeric upper bound": vm.NewIPv4Packet(
		netip.MustParseAddr("203.0.113.9"),
		netip.MustParseAddr("192.0.2.1"),
	).WithICMP(31, 0),
	"icmp6 numeric upper bound": vm.NewIPv6Packet(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	).WithICMP6(201, 0),
}

// verifies that a check touching every matcher, traced or not, allocates
// nothing for a packet of any shape.
func Test_VM_Check_NoAllocs(t *testing.T) {
	machine := everyMatcherVM(t)
	for name, packet := range syntheticPackets {
		t.Run(name, func(t *testing.T) {
			expected := machine.Check(syntheticContext, packet)
			mismatches := 0
			allocs := testing.AllocsPerRun(100, func() {
				if machine.Check(syntheticContext, packet) != expected {
					mismatches++
				}
			})
			require.Zero(t, mismatches)
			require.Zero(t, allocs)

			allocs = testing.AllocsPerRun(100, func() {
				action, _ := machine.CheckTrace(syntheticContext, packet, nopTracer{})
				if action != expected {
					mismatches++
				}
			})
			require.Zero(t, mismatches)
			require.Zero(t, allocs)
		})
	}
}

// verifies that one VM serves checks from several goroutines at once,
// every one seeing the verdicts of a lone check.
func Test_VM_Check_Concurrent(t *testing.T) {
	machine := everyMatcherVM(t)
	expected := map[string]ipfw.Action{}
	for name, packet := range syntheticPackets {
		expected[name] = machine.Check(syntheticContext, packet)
	}
	for idx := range 8 {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			t.Parallel()
			for range 200 {
				for name, packet := range syntheticPackets {
					require.Equal(t, expected[name], machine.Check(syntheticContext, packet))
				}
			}
		})
	}
}

// benchmarkRuleset is n rules that never match the benchmark packet, then
// the tail.
func benchmarkRuleset(n int, tail string) string {
	var b strings.Builder
	for range n {
		b.WriteString("add deny tcp from 203.0.113.0/24 to any 22\n")
	}
	b.WriteString(tail)
	return b.String()
}

// benchmarkCheck measures Check over the ruleset with the benchmark packet.
func benchmarkCheck(b *testing.B, ruleset string, options ...ipfw.ParserOption) {
	b.Helper()
	machine, err := vm.Build(ipfw.NewParser(ruleset, options...), vm.Config[net4, net6]{
		Environment:     ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}, Targets: anyTargets{}},
		UnresolvedJumps: vm.UnresolvedJumpsFallThrough,
	})
	if err != nil {
		b.Fatal(err)
	}
	packet := syntheticPackets["tcp4 syn"]
	b.ReportAllocs()
	for b.Loop() {
		machine.Check(syntheticContext, packet)
	}
}

func Benchmark_VM_Check_FirstRule(b *testing.B) {
	benchmarkCheck(b, benchmarkRuleset(0, "add pass ip from any to any\n")+benchmarkRuleset(1000, ""))
}

func Benchmark_VM_Check_LastRule(b *testing.B) {
	benchmarkCheck(b, benchmarkRuleset(1000, "add pass ip from any to any\n"))
}

func Benchmark_VM_Check_NoRule(b *testing.B) {
	benchmarkCheck(b, benchmarkRuleset(1000, ""))
}

// Benchmark_VM_Check_SourceReject measures scans that reject every rule by source address.
func Benchmark_VM_Check_SourceReject(b *testing.B) {
	cases := []struct {
		name   string
		rule   string
		packet vm.Packet
	}{
		{
			name:   "IPv4",
			rule:   "add pass tcp from 198.51.100.0/24 to any\n",
			packet: syntheticPackets["tcp4 syn"],
		},
		{
			name:   "IPv6",
			rule:   "add pass tcp from 2001:db8:ffff::/48 to any\n",
			packet: syntheticPackets["tcp6"],
		},
	}
	for _, testCase := range cases {
		for _, count := range []int{1, 64, 1024} {
			b.Run(testCase.name+"/"+strconv.Itoa(count), func(b *testing.B) {
				machine, err := vm.Build(
					ipfw.NewParser(strings.Repeat(testCase.rule, count)),
					vm.Config[net4, net6]{Environment: resolving},
				)
				require.NoError(b, err)
				require.Equal(b, count, machine.Len())
				require.Equal(b, deny, machine.Check(syntheticContext, testCase.packet))
				b.ReportAllocs()
				for b.Loop() {
					machine.Check(syntheticContext, testCase.packet)
				}
			})
		}
	}
}

// Benchmark_VM_Check_SourceList measures late matches and negation over 64 source alternatives.
func Benchmark_VM_Check_SourceList(b *testing.B) {
	addresses := make([]string, 64)
	for idx := range addresses {
		addresses[idx] = "192.0.2." + strconv.Itoa(idx+1)
	}
	list := strings.Join(addresses, ",")
	member := tcp4("192.0.2.64", "203.0.113.1")
	outside := tcp4("198.51.100.1", "203.0.113.1")
	cases := []struct {
		name    string
		targets string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "OrLast",
			targets: "{ " + strings.Join(addresses, " or ") + " }",
			packet:  member,
			verdict: pass,
		},
		{
			name:    "ListLast",
			targets: list,
			packet:  member,
			verdict: pass,
		},
		{
			name:    "NegatedMember",
			targets: "not " + list,
			packet:  member,
			verdict: deny,
		},
		{
			name:    "NegatedOutside",
			targets: "not " + list,
			packet:  outside,
			verdict: pass,
		},
	}
	for _, testCase := range cases {
		b.Run(testCase.name, func(b *testing.B) {
			source := "add pass tcp from " + testCase.targets + " to any\n"
			machine, err := vm.Build(
				ipfw.NewParser(source),
				vm.Config[net4, net6]{Environment: resolving},
			)
			require.NoError(b, err)
			require.Equal(b, testCase.verdict, machine.Check(syntheticContext, testCase.packet))
			b.ReportAllocs()
			for b.Loop() {
				machine.Check(syntheticContext, testCase.packet)
			}
		})
	}
}

// Benchmark_VM_Check_Options measures option folds of every shape, 1024 rules
// whose last or-block fails for the benchmark packet.
func Benchmark_VM_Check_Options(b *testing.B) {
	cases := []struct {
		name    string
		options string
	}{
		{name: "Keywords", options: "in via vlan1234 proto tcp not frag established"},
		{name: "PortList", options: "dst-port 21,22,23,25,53,80,110,143"},
		{name: "NegatedPortList", options: "not dst-port 21,22,23,25,53,80,110,443"},
		{name: "OrBlock", options: "{ dst-port 21,22 or src-port 21,22 or established or frag }"},
		{name: "NegatedListInBlock", options: "{ not dst-port 21,443 or out } in"},
		{name: "Comment", options: "in not frag established // a commented rule"},
	}
	for _, testCase := range cases {
		b.Run(testCase.name, func(b *testing.B) {
			rule := "add pass tcp from any to any " + testCase.options + "\n"
			machine, err := vm.Build(
				ipfw.NewParser(strings.Repeat(rule, 1024)),
				vm.Config[net4, net6]{Environment: resolving},
			)
			require.NoError(b, err)
			require.Equal(b, deny, machine.Check(syntheticContext, syntheticPackets["tcp4 syn"]))
			packet := syntheticPackets["tcp4 syn"]
			b.ReportAllocs()
			for b.Loop() {
				machine.Check(syntheticContext, packet)
			}
		})
	}
}

// Benchmark_VM_CheckTrace_SourceReject includes tracing every rule of a 1024-rule scan.
func Benchmark_VM_CheckTrace_SourceReject(b *testing.B) {
	source := strings.Repeat("add pass tcp from 198.51.100.0/24 to any\n", 1024)
	machine, err := vm.Build(
		ipfw.NewParser(source),
		vm.Config[net4, net6]{Environment: resolving},
	)
	require.NoError(b, err)
	packet := syntheticPackets["tcp4 syn"]
	tracer := &recordingTracer{}
	action, terminated := machine.CheckTrace(syntheticContext, packet, tracer)
	require.Equal(b, deny, action)
	require.False(b, terminated)
	require.Len(b, tracer.seen, 1024)
	b.ReportAllocs()
	for b.Loop() {
		machine.CheckTrace(syntheticContext, packet, nopTracer{})
	}
}

func Benchmark_VM_Check_Jumps(b *testing.B) {
	section := ruleset(`
		add skipto :S%d ip from any to any
		add deny ip from any to any
		:S%d
	`)
	var rules strings.Builder
	for idx := range 1000 {
		fmt.Fprintf(&rules, section, idx, idx)
	}
	rules.WriteString("add pass ip from any to any\n")
	benchmarkCheck(b, rules.String(), ipfw.WithLabels())
}

func Benchmark_VM_Check_EveryMatcher(b *testing.B) {
	benchmarkCheck(b, strings.Repeat(everyMatcher, 100), ipfw.WithLabels())
}

func Benchmark_VM_Build_Large(b *testing.B) {
	src := strings.Repeat(everyMatcher, 100)
	cfg := vm.Config[net4, net6]{
		Environment:     ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}, Targets: anyTargets{}},
		UnresolvedJumps: vm.UnresolvedJumpsFallThrough,
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if _, err := vm.Build(ipfw.NewParser(src, ipfw.WithLabels()), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleBuild() {
	ruleset := "add deny ip from 198.51.100.0/24 to any\n" +
		"add pass ip from 192.0.2.0/24 to any 22\n" +
		"add deny ip from any to any\n"
	machine, err := vm.Build(ipfw.NewParser(ruleset), vm.Config[xnetip.Network4, xnetip.Network6]{
		Environment: ipfw.Environment[xnetip.Network4, xnetip.Network6]{
			Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
				Parse4: xnetip.ParseNetwork4,
				Parse6: xnetip.ParseNetwork6,
			},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	ctx := &vm.Context{}
	ssh := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.1")).WithTCP(ipfw.TCPSyn, 40000, 22)
	fmt.Println(machine.Check(ctx, ssh))
	other := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("203.0.113.1")).WithTCP(ipfw.TCPSyn, 40000, 80)
	fmt.Println(machine.Check(ctx, other))
	// Output:
	//
	// pass
	// deny
}
