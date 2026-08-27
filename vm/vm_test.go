package vm_test

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw"
	"github.com/yanet-platform/ipfw/vm"
)

type (
	net4 = xnetip.Network4
	net6 = xnetip.Network6
)

// nets plugs xnetip into the VM.
var nets = ipfw.NetworkParserFuncs[net4, net6]{
	Parse4:    xnetip.ParseNetwork4,
	Parse6:    xnetip.ParseNetwork6,
	FromAddr4: xnetip.Network4FromAddr,
	FromAddr6: xnetip.Network6FromAddr,
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

// fakeTargets stands one hostname for a network of each family, `_NETS_`
// for two IPv4 networks and `nothing.example.com` for nothing.
type fakeTargets struct{}

// ResolveTarget implements ipfw.TargetResolver.
func (fakeTargets) ResolveTarget(target ipfw.Target) ([]net4, []net6, error) {
	switch target.Text {
	case "host.example.com":
		return []net4{parse4("192.0.2.1/32")}, []net6{parse6("2001:db8::1/128")}, nil
	case "_NETS_":
		return []net4{parse4("192.0.2.0/24"), parse4("198.51.100.0/24")}, nil, nil
	case "nothing.example.com":
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

// build builds a VM from src with the fake resolvers, failing the test on
// any error.
func build(t *testing.T, src string, cfg vm.Config[net4, net6]) *vm.VM[net4, net6] {
	t.Helper()
	cfg.Environment = resolving
	machine, err := vm.Build(ipfw.NewParser(src), cfg)
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
			name:    "IPv4 by protocol, tcp",
			rules:   "add pass tcp from any to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name:    "IPv4 by protocol, other",
			rules:   "add pass tcp from any to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")),
			verdict: deny,
		},
		{
			name:  "IPv6 by protocol, tcp",
			rules: "add pass tcp from any to any\nadd deny ip from any to any\n",
			packet: vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::1")).
				WithTCP(ipfw.TCPSyn, 50000, 22),
			verdict: pass,
		},
		{
			name:    "IPv6 by protocol, other",
			rules:   "add pass tcp from any to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::1")),
			verdict: deny,
		},
		{
			name:    "by source address, match",
			rules:   "add pass tcp from 192.0.2.1 to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name:    "by source address, mismatch",
			rules:   "add pass tcp from 192.0.2.1 to any\nadd deny ip from any to any\n",
			packet:  tcp4("198.51.100.1", "192.0.2.1"),
			verdict: deny,
		},
		{
			name:    "by destination address, match",
			rules:   "add pass tcp from any to 192.0.2.1\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name:    "by destination address, mismatch",
			rules:   "add pass tcp from any to 192.0.2.1\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "198.51.100.1"),
			verdict: deny,
		},
		{
			name:    "by both addresses, match",
			rules:   "add pass tcp from 192.0.2.1 to 192.0.2.1\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name:    "by both addresses, mismatch",
			rules:   "add pass tcp from 192.0.2.1 to 192.0.2.1\nadd deny ip from any to any\n",
			packet:  tcp4("198.51.100.1", "192.0.2.1"),
			verdict: deny,
		},
		{
			name:    "network and negation",
			rules:   "add deny ip from not 192.0.2.0/24 to any\nadd pass ip from 192.0.2.0/24 to { 2001:db8::/32 or 198.51.100.0/24 }\n",
			packet:  tcp4("192.0.2.77", "198.51.100.9"),
			verdict: pass,
		},
		{
			name:    "IPv4 network never matches an IPv6 packet",
			rules:   "add pass ip from 0.0.0.0/0 to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: deny,
		},
		{
			name:    "ip6 keyword against an IPv4 packet",
			rules:   "add pass ip6 from any to any\nadd deny ip4 from any to any\n",
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

// verifies that nothing matching yields the default verdict, deny unless
// configured, and that CheckTrace reports no termination then.
func Test_VM_Check_DefaultVerdict(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.1")
	empty := build(t, "", none)
	require.Equal(t, deny, empty.Check(&vm.Context{}, packet))
	require.Equal(t, 0, empty.Len())

	permissive := build(t, "add deny udp from any to any\n", vm.Config[net4, net6]{DefaultVerdict: pass})
	require.Equal(t, pass, permissive.Check(&vm.Context{}, packet))
	action, matched := permissive.CheckTrace(&vm.Context{}, packet, nopTracer{})
	require.False(t, matched)
	require.Equal(t, ipfw.Action{}, action)
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
	machine := build(t, "add deny udp from any to any\n# c\nadd deny ip from 198.51.100.0/24 to any\nadd pass tcp from any to any\nadd deny ip from any to any\n", none)
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
	machine := build(t, "add count ip from any to any\nadd count tcp from 198.51.100.0/24 to any\nadd pass ip from any to any\n", none)
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

// verifies that a check-state rule, with or without a flow, never matches
// and is traced as such.
func Test_VM_Check_CheckState(t *testing.T) {
	machine := build(t, "add check-state\nadd check-state :flow\nadd deny ip from any to any\n", none)
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
	machine := build(t, "add skipto 1500 ip from any to 192.0.2.4\nadd deny ip from any to any\nadd 1500 allow tcp from any to any\n", none)
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
	machine := build(t, "add skipto 50 ip from any to 192.0.2.0/24\nadd deny ip from any to any\nadd 50 count ip from any to any\nadd 1500 count ip from any to any\nadd pass ip from any to any\n", none)
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

// verifies that a matching skipto to a label continues at the rule after
// the label, a mismatching one at the next rule.
func Test_VM_Check_SkipToLabel(t *testing.T) {
	machine := build(t, "add skipto :SECTION tcp from 192.0.2.4 to any\nadd deny ip from any to any\n:SECTION\nadd pass tcp from any to 203.0.113.1\nadd deny ip from any to any\n", none)
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
	ending := build(t, "add skipto :END ip from any to any\nadd deny ip from any to any\n:END\n", vm.Config[net4, net6]{DefaultVerdict: pass})
	tracer := &recordingTracer{}
	_, matched := ending.CheckTrace(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2"), tracer)
	require.False(t, matched)
	require.Equal(t, []traced{{line: 1, action: ipfw.ActionSkipTo, matched: true}}, tracer.seen)
	require.Equal(t, pass, ending.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))

	repeated := build(t, "add skipto :A ip from any to any\n:A\nadd count ip from any to any\n:A\nadd pass ip from any to any\n", none)
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
	machine := build(t, "add skipto :NOWHERE ip from any to any\nadd skipto 7 ip from any to any\nadd pass ip from any to any\n", cfg)
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
			name:    "source port, match",
			rules:   "add pass tcp from any 22 to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 22, 50000),
			verdict: pass,
		},
		{
			name:    "source port, mismatch",
			rules:   "add pass tcp from any 22 to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 26, 50000),
			verdict: deny,
		},
		{
			name:    "destination port over TCP",
			rules:   "add pass ip from any to any 22\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "192.0.2.1"),
			verdict: pass,
		},
		{
			name:    "destination port over UDP",
			rules:   "add pass ip from any to any 22\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithUDP(50000, 22),
			verdict: pass,
		},
		{
			name:    "destination port against ICMP, which has none",
			rules:   "add pass ip from any to any 22\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithICMP(8, 1),
			verdict: deny,
		},
		{
			name:    "both sides, match",
			rules:   "add pass tcp from 192.0.2.0/24 25 to 198.51.100.0/24 25\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")).WithTCP(ipfw.TCPSyn, 25, 25),
			verdict: pass,
		},
		{
			name:    "both sides, destination port mismatch",
			rules:   "add pass tcp from 192.0.2.0/24 25 to 198.51.100.0/24 25\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")).WithTCP(ipfw.TCPSyn, 25, 26),
			verdict: deny,
		},
		{
			name:    "range and list, inside the range",
			rules:   "add pass tcp from any 1000-2000,22 to any 80,443\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 1500, 443),
			verdict: pass,
		},
		{
			name:    "range and list, the single port",
			rules:   "add pass tcp from any 1000-2000,22 to any 80,443\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 22, 80),
			verdict: pass,
		},
		{
			name:    "range and list, just outside the range",
			rules:   "add pass tcp from any 1000-2000,22 to any 80,443\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 2001, 80),
			verdict: deny,
		},
		{
			name:    "negated list, port outside",
			rules:   "add pass tcp from any not 22,25 to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 23, 50000),
			verdict: pass,
		},
		{
			name:    "negated list, port inside",
			rules:   "add pass tcp from any not 22,25 to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.1")).WithTCP(ipfw.TCPSyn, 25, 50000),
			verdict: deny,
		},
		{
			name:    "IPv6 packet",
			rules:   "add pass tcp from any to any 22\nadd deny ip from any to any\n",
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

// verifies that service names are resolved into ports on the way in.
func Test_VM_Build_ServiceNames(t *testing.T) {
	machine, err := vm.Build(
		ipfw.NewParser("add pass tcp from any ssh-smtp to any smtp\nadd deny ip from any to any\n"),
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
	machine := build(t, "add allow tcp from any to any established\nadd deny ip from any to any\n", none)
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPSyn)))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPAck)))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPRst)))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4Flags(ipfw.TCPSyn|ipfw.TCPAck)))
	udp := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22)
	require.Equal(t, deny, machine.Check(&vm.Context{}, udp))

	negated := build(t, "add allow ip from any to any not established\nadd deny ip from any to any\n", none)
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
			name:    "exact, same name",
			rules:   "add pass ip from any to any via eth0\nadd deny ip from any to any\n",
			ifname:  "eth0",
			verdict: pass,
		},
		{
			name:    "exact, other name",
			rules:   "add pass ip from any to any via eth0\nadd deny ip from any to any\n",
			ifname:  "eth1",
			verdict: deny,
		},
		{
			name:    "exact, no name",
			rules:   "add pass ip from any to any via eth0\nadd deny ip from any to any\n",
			ifname:  "",
			verdict: deny,
		},
		{
			name:    "mask, match",
			rules:   "add pass ip from any to any via vlan1???\nadd deny ip from any to any\n",
			ifname:  "vlan1234",
			verdict: pass,
		},
		{
			name:    "mask, too short",
			rules:   "add pass ip from any to any via vlan1???\nadd deny ip from any to any\n",
			ifname:  "vlan123",
			verdict: deny,
		},
		{
			name:    "mask, other prefix",
			rules:   "add pass ip from any to any via vlan1???\nadd deny ip from any to any\n",
			ifname:  "vlan2234",
			verdict: deny,
		},
		{
			name:    "star mask takes the empty name",
			rules:   "add pass ip from any to any via *\nadd deny ip from any to any\n",
			ifname:  "",
			verdict: pass,
		},
		{
			name:    "group, first",
			rules:   "add pass ip from any to any { via eth0 or via eth1 }\nadd deny ip from any to any\n",
			ifname:  "eth0",
			verdict: pass,
		},
		{
			name:    "group, second",
			rules:   "add pass ip from any to any { via eth0 or via eth1 }\nadd deny ip from any to any\n",
			ifname:  "eth1",
			verdict: pass,
		},
		{
			name:    "group, neither",
			rules:   "add pass ip from any to any { via eth0 or via eth1 }\nadd deny ip from any to any\n",
			ifname:  "eth2",
			verdict: deny,
		},
		{
			name:    "negated, same name",
			rules:   "add pass ip from any to any not via eth0\nadd deny ip from any to any\n",
			ifname:  "eth0",
			verdict: deny,
		},
		{
			name:    "negated, other name",
			rules:   "add pass ip from any to any not via eth0\nadd deny ip from any to any\n",
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

	loopback := build(t, "add allow ip from me to me { via lo0 or via lo1 }\nadd deny ip from any to any\n", none)
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
	named := build(t, "add pass ip from any to any proto tcp\nadd deny ip from any to any\n", none)
	require.Equal(t, pass, named.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
	require.Equal(t, deny, named.Check(&vm.Context{}, udp))

	negated := build(t, "add pass ip from any to any not proto 6\nadd deny ip from any to any\n", none)
	require.Equal(t, deny, negated.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
	require.Equal(t, pass, negated.Check(&vm.Context{}, udp))

	numeric, err := vm.Build(ipfw.NewParser("add pass ip from any to any { proto 17 or proto 1 }\nadd deny ip from any to any\n"), vm.Config[net4, net6]{Environment: networksOnly})
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
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "src-port, match",
			rules:   "add pass tcp from any to any src-port 25\nadd deny ip from any to any\n",
			packet:  tcp(25, 50000),
			verdict: pass,
		},
		{
			name:    "src-port, mismatch",
			rules:   "add pass tcp from any to any src-port 25\nadd deny ip from any to any\n",
			packet:  tcp(26, 50000),
			verdict: deny,
		},
		{
			name:    "two dst-port rules, first",
			rules:   "add pass tcp from any to any dst-port 22\nadd pass tcp from any to any dst-port 25\nadd deny ip from any to any\n",
			packet:  tcp(50000, 22),
			verdict: pass,
		},
		{
			name:    "two dst-port rules, second",
			rules:   "add pass tcp from any to any dst-port 22\nadd pass tcp from any to any dst-port 25\nadd deny ip from any to any\n",
			packet:  tcp(50000, 25),
			verdict: pass,
		},
		{
			name:    "two dst-port rules, neither",
			rules:   "add pass tcp from any to any dst-port 22\nadd pass tcp from any to any dst-port 25\nadd deny ip from any to any\n",
			packet:  tcp(50000, 26),
			verdict: deny,
		},
		{
			name:    "dst-port over UDP",
			rules:   "add pass ip from any to any dst-port 22\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22),
			verdict: pass,
		},
		{
			name:    "dst-port against ICMP",
			rules:   "add pass ip from any to any dst-port 22\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithICMP(8, 1),
			verdict: deny,
		},
		{
			name:    "dst-port list, first",
			rules:   "add pass tcp from any to any dst-port 22,80\nadd deny ip from any to any\n",
			packet:  tcp(50000, 22),
			verdict: pass,
		},
		{
			name:    "dst-port list, second",
			rules:   "add pass tcp from any to any dst-port 22,80\nadd deny ip from any to any\n",
			packet:  tcp(50000, 80),
			verdict: pass,
		},
		{
			name:    "dst-port list, neither",
			rules:   "add pass tcp from any to any dst-port 22,80\nadd deny ip from any to any\n",
			packet:  tcp(50000, 443),
			verdict: deny,
		},
		{
			name:    "negated dst-port list, inside",
			rules:   "add pass tcp from any to any not dst-port 22,80\nadd deny ip from any to any\n",
			packet:  tcp(50000, 22),
			verdict: deny,
		},
		{
			name:    "negated dst-port list, outside",
			rules:   "add pass tcp from any to any not dst-port 22,80\nadd deny ip from any to any\n",
			packet:  tcp(50000, 443),
			verdict: pass,
		},
		{
			name:    "range with another option",
			rules:   "add pass tcp from any to any established src-port 1024-65535\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithTCP(ipfw.TCPAck, 1024, 22),
			verdict: pass,
		},
		{
			name:    "range with another option, below",
			rules:   "add pass tcp from any to any established src-port 1024-65535\nadd deny ip from any to any\n",
			packet:  vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithTCP(ipfw.TCPAck, 1023, 22),
			verdict: deny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := build(t, tc.rules, none)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}

	named, err := vm.Build(ipfw.NewParser("add pass tcp from any to any dst-port ssh,smtp\nadd deny ip from any to any\n"), vm.Config[net4, net6]{Environment: resolvingServices})
	require.NoError(t, err)
	require.Equal(t, pass, named.Check(&vm.Context{}, tcp(50000, 25)))
	require.Equal(t, deny, named.Check(&vm.Context{}, tcp(50000, 26)))
}

// verifies that tcpflags matches a TCP packet whose examined flags are
// exactly the ones to be set, and never a packet without TCP flags.
func Test_VM_Check_TCPFlags(t *testing.T) {
	udp := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithUDP(50000, 22)
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "tcp rule, syn and not ack, SYN",
			rules:   "add allow tcp from any to any tcpflags syn,!ack\nadd deny ip from any to any\n",
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name:    "tcp rule, syn and not ack, ACK",
			rules:   "add allow tcp from any to any tcpflags syn,!ack\nadd deny ip from any to any\n",
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: deny,
		},
		{
			name:    "ip rule, syn and not ack, SYN",
			rules:   "add allow ip from any to any tcpflags syn,!ack\nadd deny ip from any to any\n",
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name:    "ip rule, syn and not ack, SYN with ACK",
			rules:   "add allow ip from any to any tcpflags syn,!ack\nadd deny ip from any to any\n",
			packet:  tcp4Flags(ipfw.TCPSyn | ipfw.TCPAck),
			verdict: deny,
		},
		{
			name:    "ip rule, syn and not ack, SYN with PSH outside the mask",
			rules:   "add allow ip from any to any tcpflags syn,!ack\nadd deny ip from any to any\n",
			packet:  tcp4Flags(ipfw.TCPSyn | ipfw.TCPPsh),
			verdict: pass,
		},
		{
			name:    "ip rule, syn and not ack, UDP",
			rules:   "add allow ip from any to any tcpflags syn,!ack\nadd deny ip from any to any\n",
			packet:  udp,
			verdict: deny,
		},
		{
			name:    "not tcpflags, UDP",
			rules:   "add allow ip from any to any not tcpflags rst\nadd deny ip from any to any\n",
			packet:  udp,
			verdict: pass,
		},
		{
			name:    "not tcpflags, RST",
			rules:   "add allow ip from any to any not tcpflags rst\nadd deny ip from any to any\n",
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

// verifies that icmptypes and icmp6types match the type of an ICMP packet
// of their family when it is in the set, and nothing else.
func Test_VM_Check_ICMPTypes(t *testing.T) {
	icmp := func(ty uint8) vm.Packet {
		return vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithICMP(ty, 0)
	}
	icmp6 := func(ty uint8) vm.Packet {
		return vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")).WithICMP6(ty, 0)
	}
	cases := []struct {
		name    string
		rules   string
		packet  vm.Packet
		verdict ipfw.Action
	}{
		{
			name:    "icmptypes, type in the set",
			rules:   "add allow icmp from any to { 192.0.2.0/24 } icmptypes 0,8,3,11,12\nadd deny ip from any to any\n",
			packet:  icmp(8),
			verdict: pass,
		},
		{
			name:    "icmptypes, type outside the set",
			rules:   "add allow icmp from any to { 192.0.2.0/24 } icmptypes 0,8,3,11,12\nadd deny ip from any to any\n",
			packet:  icmp(1),
			verdict: deny,
		},
		{
			name:    "icmptypes against TCP",
			rules:   "add allow ip from any to any icmptypes 8\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "192.0.2.2"),
			verdict: deny,
		},
		{
			name:    "icmptypes against ICMPv6",
			rules:   "add allow ip from any to any icmptypes 8\nadd deny ip from any to any\n",
			packet:  icmp6(8),
			verdict: deny,
		},
		{
			name:    "not icmptypes, type in the set",
			rules:   "add allow ip from any to any not icmptypes 8\nadd deny ip from any to any\n",
			packet:  icmp(8),
			verdict: deny,
		},
		{
			name:    "not icmptypes, type outside the set",
			rules:   "add allow ip from any to any not icmptypes 8\nadd deny ip from any to any\n",
			packet:  icmp(0),
			verdict: pass,
		},
		{
			name:    "icmp6types, type in the set",
			rules:   "add allow ip from any to { 2001:db8::/32 } icmp6types 1,2,3,4,128,129,133,134,135,136\nadd deny ip from any to any\n",
			packet:  icmp6(135),
			verdict: pass,
		},
		{
			name:    "icmp6types, type outside the set",
			rules:   "add allow ip from any to { 2001:db8::/32 } icmp6types 1,2,3,4,128,129,133,134,135,136\nadd deny ip from any to any\n",
			packet:  icmp6(130),
			verdict: deny,
		},
		{
			name:    "icmp6types against ICMP",
			rules:   "add allow ip from any to any icmp6types 128\nadd deny ip from any to any\n",
			packet:  icmp(128),
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

// verifies that frag matches a non-first IPv4 fragment only, which, having
// no transport header, fails a rule with ports first.
func Test_VM_Check_Frag(t *testing.T) {
	machine := build(t, "add allow ip from any to any frag\nadd deny ip from any to any\n", none)
	fragment := vm.NewIPv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")).WithFragmentOffset(100)
	require.Equal(t, pass, machine.Check(&vm.Context{}, fragment))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.2")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"))))

	withPorts := build(t, "add allow ip from any to any 22 frag\nadd deny ip from any to any\n", none)
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
			name:  "in",
			rules: "add allow ip from any to any in\nadd deny ip from any to any\n",
			in:    pass,
			out:   deny,
		},
		{
			name:  "out",
			rules: "add allow ip from any to any out\nadd deny ip from any to any\n",
			in:    deny,
			out:   pass,
		},
		{
			name:  "in or out",
			rules: "add allow ip from any to any { in or out }\nadd deny ip from any to any\n",
			in:    pass,
			out:   pass,
		},
		{
			name:  "not in",
			rules: "add allow ip from any to any not in\nadd deny ip from any to any\n",
			in:    deny,
			out:   pass,
		},
		{
			name:  "in and out never both",
			rules: "add allow ip from any to any in out\nadd deny ip from any to any\n",
			in:    deny,
			out:   deny,
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
	machine := build(t, "add pass tcp from any to any established not established\nadd count tcp from any to any { not established or established }\nadd pass tcp from any to any\nadd deny ip from any to any\n", none)
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
	machine := build(t, "add deny tcp from any to any { established or not established } not established\nadd pass tcp from any to any established\nadd deny ip from any to any\n", none)
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
			name:    "hostname, its IPv4 address",
			rules:   "add pass ip from host.example.com to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "hostname, its IPv6 address",
			rules:   "add pass ip from host.example.com to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: pass,
		},
		{
			name:    "hostname, another address",
			rules:   "add pass ip from host.example.com to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.2", "203.0.113.1"),
			verdict: deny,
		},
		{
			name:    "negated hostname, its IPv4 address",
			rules:   "add pass ip from not host.example.com to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: deny,
		},
		{
			name:    "negated hostname, its IPv6 address",
			rules:   "add pass ip from not host.example.com to any\nadd deny ip from any to any\n",
			packet:  vm.NewIPv6Packet(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
			verdict: deny,
		},
		{
			name:    "negated hostname, another address",
			rules:   "add pass ip from not host.example.com to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.2", "203.0.113.1"),
			verdict: pass,
		},
		{
			name:    "macro, first network",
			rules:   "add pass ip from any to _NETS_\nadd deny ip from any to any\n",
			packet:  tcp4("203.0.113.1", "192.0.2.5"),
			verdict: pass,
		},
		{
			name:    "macro, second network",
			rules:   "add pass ip from any to _NETS_\nadd deny ip from any to any\n",
			packet:  tcp4("203.0.113.1", "198.51.100.5"),
			verdict: pass,
		},
		{
			name:    "macro, outside",
			rules:   "add pass ip from any to _NETS_\nadd deny ip from any to any\n",
			packet:  tcp4("203.0.113.1", "203.0.113.5"),
			verdict: deny,
		},
		{
			name:    "negated macro, inside",
			rules:   "add pass ip from any to not _NETS_\nadd deny ip from any to any\n",
			packet:  tcp4("203.0.113.1", "198.51.100.5"),
			verdict: deny,
		},
		{
			name:    "negated macro in a group with a network",
			rules:   "add pass ip from { 203.0.113.0/24 or not _NETS_ } to any\nadd deny ip from any to any\n",
			packet:  tcp4("198.51.100.5", "203.0.113.1"),
			verdict: deny,
		},
		{
			name:    "name standing for nothing never matches",
			rules:   "add pass tcp from { nothing.example.com } to any\nadd deny ip from any to any\n",
			packet:  tcp4("192.0.2.1", "203.0.113.1"),
			verdict: deny,
		},
		{
			name:    "negated name standing for nothing never matches either",
			rules:   "add pass tcp from not nothing.example.com to any\nadd deny ip from any to any\n",
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

// verifies that a check over resolved names allocates nothing.
func Test_VM_Check_Resolved_NoAllocs(t *testing.T) {
	machine, err := vm.Build(
		ipfw.NewParser("add deny ip from not host.example.com to _NETS_\nadd pass ip from host.example.com to { _NETS_ or not host.example.com }\nadd deny ip from any to any\n"),
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
	machine := build(t, "add pass ip from me to me\nadd pass ip from me6 to any\nadd deny ip from any to any\n", none)
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

// verifies that a table target matches the addresses of its networks of
// either family, negated or not, and that a missing table matches nothing.
func Test_VM_Check_Tables(t *testing.T) {
	rules := "table t create type addr\ntable t add 192.0.2.128/29\ntable t add 198.51.100.0/25\ntable t add 198.51.100.128/25\ntable t add 2001:db8::/32\n" +
		"add pass tcp from table(t) to table(t)\nadd pass ip from not table(t) to 203.0.113.1\nadd pass ip from table(none) to any\nadd deny ip from any to any\n"
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
// VM consults, and that an interface value loses its leading colon.
func Test_VM_Build_Tables(t *testing.T) {
	tables := vm.NewTables[net4, net6]()
	tables.AddNetwork4("pre", must4(t, "203.0.113.0/24"))
	machine := build(t, "table i add vlan1 :LABEL\ntable i add vlan2 plain\ntable i add vlan3\ntable pre add 192.0.2.0/24\nadd pass ip from table(pre) to any\nadd deny ip from any to any\n", vm.Config[net4, net6]{Tables: tables})
	require.Same(t, tables, machine.Tables())
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("203.0.113.7", "192.0.2.1")))
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.7", "192.0.2.1")))
	require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("198.51.100.7", "192.0.2.1")))

	value, ok := machine.Tables().LookupInterface("i", "vlan1")
	require.True(t, ok)
	require.Equal(t, "LABEL", value)
	value, ok = machine.Tables().LookupInterface("i", "vlan2")
	require.True(t, ok)
	require.Equal(t, "plain", value)
	value, ok = machine.Tables().LookupInterface("i", "vlan3")
	require.True(t, ok)
	require.Empty(t, value)

	fresh := build(t, "table t create\n", none)
	require.NotNil(t, fresh.Tables())
	require.False(t, fresh.Tables().LookupNetwork("t", netip.MustParseAddr("192.0.2.1")))
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
			name:  "record",
			rules: "add pass ip from any to any\nfrobnicate now\n",
			cause: vm.ErrUnsupportedRecord,
		},
		{
			name:  "action",
			rules: "add pass ip from any to any\nwarp somewhere\n",
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
			name:    "setup, SYN",
			rules:   "add pass tcp from any to any setup\nadd deny ip from any to any\n",
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name:    "setup, SYN with ACK",
			rules:   "add pass tcp from any to any setup\nadd deny ip from any to any\n",
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPSyn | ipfw.TCPAck),
			verdict: deny,
		},
		{
			name:    "not setup, SYN",
			rules:   "add pass tcp from any to any not setup\nadd deny ip from any to any\n",
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: deny,
		},
		{
			name:    "not setup, ACK",
			rules:   "add pass tcp from any to any not setup\nadd deny ip from any to any\n",
			ctx:     &vm.Context{},
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: pass,
		},
		{
			name:    "setup or in, ACK coming in",
			rules:   "add pass tcp from any to any { setup or in }\nadd deny ip from any to any\n",
			ctx:     &vm.Context{Direction: vm.In},
			packet:  tcp4Flags(ipfw.TCPAck),
			verdict: pass,
		},
		{
			name:    "setup or in, SYN going out",
			rules:   "add pass tcp from any to any { setup or in }\nadd deny ip from any to any\n",
			ctx:     &vm.Context{Direction: vm.Out},
			packet:  tcp4Flags(ipfw.TCPSyn),
			verdict: pass,
		},
		{
			name:    "setup or in, ACK going out",
			rules:   "add pass tcp from any to any { setup or in }\nadd deny ip from any to any\n",
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

	_, err := vm.Build(ipfw.NewParser("add pass ip from any to any\nadd pass tcp from any to any established setup\n", ipfw.WithOptionHook(setupHook)), vm.Config[net4, net6]{Environment: resolving})
	var buildErr *vm.BuildError
	require.ErrorAs(t, err, &buildErr)
	require.Equal(t, 2, buildErr.Line)
	require.Equal(t, "add pass tcp from any to any established setup", buildErr.Text)
	require.ErrorIs(t, err, vm.ErrUnsupportedOption)
	var parseErr *ipfw.ParseError
	require.ErrorAs(t, err, &parseErr)
	require.Equal(t, 41, parseErr.Column)
}

// verifies that a check through the custom matcher allocates nothing.
func Test_VM_CustomOption_NoAllocs(t *testing.T) {
	machine, err := vm.Build(
		ipfw.NewParser("add deny tcp from any to any not setup\nadd pass tcp from any to any { setup or in }\nadd deny ip from any to any\n", ipfw.WithOptionHook(setupHook)),
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
		{option: "note", in: pass, out: pass},
		{option: "not note", in: deny, out: deny},
	}
	note := func(rest string) (ipfw.Opt, int, error) {
		if strings.HasPrefix(rest, "note") {
			return ipfw.Opt{Kind: ipfw.OptComment, Text: "note"}, len("note"), nil
		}
		return ipfw.Opt{}, 0, ipfw.ErrUnknownOption
	}
	for _, tc := range cases {
		t.Run(tc.option, func(t *testing.T) {
			parser := ipfw.NewParser("add pass ip from any to any "+tc.option+"\nadd deny ip from any to any\n", ipfw.WithOptionHook(note))
			machine, err := vm.Build(parser, vm.Config[net4, net6]{Environment: resolving})
			require.NoError(t, err)
			require.Equal(t, tc.in, machine.Check(&vm.Context{Direction: vm.In}, packet))
			require.Equal(t, tc.out, machine.Check(&vm.Context{Direction: vm.Out}, packet))
		})
	}
}

// verifies that via table(NAME) matches an interface the table lists and
// that skipto tablearg then continues at the label the entry's value names.
//
// A value naming no label, or a label before the rule, falls through to the
// next rule, and an entry added after the build counts.
func Test_VM_Check_TableArg(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.2")
	corpus := build(t, "table t create type iface\n\nadd skipto tablearg ip from any to any via table(t) in\ntable t add vlan1234 :INBOUND\nadd deny ip from any to any\n\n:INBOUND\nadd pass ip from any to any\n", none)
	require.Equal(t, pass, corpus.Check(&vm.Context{IfName: "vlan1234"}, packet))
	require.Equal(t, deny, corpus.Check(&vm.Context{IfName: "eth0"}, packet))
	require.Equal(t, deny, corpus.Check(&vm.Context{IfName: "vlan1234", Direction: vm.Out}, packet))

	two := build(t, "table j add vlan1 :ONE\ntable j add vlan2 :TWO\ntable j add vlan3 :NOWHERE\nadd skipto tablearg ip from any to any via table(j)\nadd deny ip from any to any\n:ONE\nadd pass ip from any to any\n:TWO\nadd count ip from any to any\nadd deny ip from any to any\n", none)
	cases := []struct {
		ifname  string
		verdict ipfw.Action
		seen    []traced
	}{
		{
			ifname:  "vlan1",
			verdict: pass,
			seen: []traced{
				{line: 4, action: ipfw.ActionSkipTo, matched: true},
				{line: 7, action: ipfw.ActionPass, matched: true},
			},
		},
		{
			ifname:  "vlan2",
			verdict: deny,
			seen: []traced{
				{line: 4, action: ipfw.ActionSkipTo, matched: true},
				{line: 9, action: ipfw.ActionCount, matched: true},
				{line: 10, action: ipfw.ActionDeny, matched: true},
			},
		},
		{
			ifname:  "vlan3",
			verdict: deny,
			seen: []traced{
				{line: 4, action: ipfw.ActionSkipTo, matched: true},
				{line: 5, action: ipfw.ActionDeny, matched: true},
			},
		},
		{
			ifname:  "vlan4",
			verdict: deny,
			seen: []traced{
				{line: 4, action: ipfw.ActionSkipTo, matched: false},
				{line: 5, action: ipfw.ActionDeny, matched: true},
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

	two.Tables().AddInterface("j", "vlan4", "ONE")
	require.Equal(t, pass, two.Check(&vm.Context{IfName: "vlan4"}, packet))

	backward := build(t, "add count ip from any to any\n:BACK\ntable j add vlan1 :BACK\nadd skipto tablearg ip from any to any via table(j)\nadd pass ip from any to any\n", none)
	tracer := &recordingTracer{}
	action, matched := backward.CheckTrace(&vm.Context{IfName: "vlan1"}, packet, tracer)
	require.True(t, matched)
	require.Equal(t, pass, action)
	require.Equal(t, []traced{
		{line: 1, action: ipfw.ActionCount, matched: true},
		{line: 4, action: ipfw.ActionSkipTo, matched: true},
		{line: 5, action: ipfw.ActionPass, matched: true},
	}, tracer.seen)

	plain := build(t, "table t add eth0 whatever\nadd pass ip from any to any via table(t)\nadd pass ip from any to any not via table(t) in\nadd deny ip from any to any\n", none)
	require.Equal(t, pass, plain.Check(&vm.Context{IfName: "eth0"}, packet))
	require.Equal(t, pass, plain.Check(&vm.Context{IfName: "eth1"}, packet))
	require.Equal(t, deny, plain.Check(&vm.Context{IfName: "eth1", Direction: vm.Out}, packet))
	require.Equal(t, pass, plain.Check(&vm.Context{IfName: "eth0", Direction: vm.Out}, packet))
}

// verifies that a check through a table jump allocates nothing.
func Test_VM_TableArg_NoAllocs(t *testing.T) {
	machine := build(t, "table j add vlan1 :ONE\nadd skipto tablearg ip from any to any via table(j)\nadd deny ip from any to any\n:ONE\nadd pass ip from any to any\n", none)
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
		line        int
		text        string
		cause       error
	}{
		{
			name:        "parse error",
			rules:       "add pass ip from any to any\nadd foobar :any\n",
			environment: resolving,
			line:        2,
			text:        "add foobar :any",
			cause:       ipfw.ErrExpectedAction,
		},
		{
			name:        "rule number going backwards",
			rules:       "add 100 pass ip from any to any\nadd 50 deny ip from any to any\n",
			environment: resolving,
			line:        2,
			text:        "add 50 deny ip from any to any",
			cause:       vm.ErrRuleNumberOrder,
		},
		{
			name:        "rule number repeated",
			rules:       "add 100 pass ip from any to any\nadd 100 deny ip from any to any\n",
			environment: resolving,
			line:        2,
			text:        "add 100 deny ip from any to any",
			cause:       vm.ErrRuleNumberOrder,
		},
		{
			name:        "skipto to a number that never appears",
			rules:       "add deny udp from any to any\nadd skipto 7 ip from any to any\nadd pass ip from any to any\n",
			environment: resolving,
			line:        2,
			text:        "add skipto 7 ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name:        "skipto to its own number",
			rules:       "add 50 skipto 50 ip from any to any\nadd pass ip from any to any\n",
			environment: resolving,
			line:        1,
			text:        "add 50 skipto 50 ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name:        "skipto backwards",
			rules:       "add 50 pass udp from any to any\nadd 100 skipto 50 ip from any to any\n",
			environment: resolving,
			line:        2,
			text:        "add 100 skipto 50 ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name:        "skipto to a label that never appears",
			rules:       "add skipto :NOWHERE ip from any to any\nadd pass ip from any to any\n",
			environment: resolving,
			line:        1,
			text:        "add skipto :NOWHERE ip from any to any",
			cause:       vm.ErrUnresolvedJump,
		},
		{
			name:        "skipto to a label before it",
			rules:       "add count ip from any to any\n:BACK\nadd skipto :BACK ip from any to any\n",
			environment: resolving,
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
			name:        "IPv4 table entry that does not parse",
			rules:       "table t add 192.0.2.0/24\ntable t add 192.0.2.0/33\n",
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
			_, err := vm.Build(ipfw.NewParser(tc.rules), vm.Config[net4, net6]{Environment: tc.environment})
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
	_, err := vm.Build(ipfw.NewParser("add pass ip from any to any\n  add foobar :any\n"), vm.Config[net4, net6]{Environment: resolving})
	var parseErr *ipfw.ParseError
	require.ErrorAs(t, err, &parseErr)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedAction,
		Line:   2,
		Column: 4,
		Text:   "add foobar :any",
	}, *parseErr)
}

// verifies that a numeric protocol needs no resolver.
func Test_VM_Build_NumericProto(t *testing.T) {
	machine, err := vm.Build(
		ipfw.NewParser("add pass 6 from any to any\nadd deny ip from any to any\n"),
		vm.Config[net4, net6]{Environment: networksOnly},
	)
	require.NoError(t, err)
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1")))
}

// anyTargets stands every hostname and macro for one network of each
// family.
type anyTargets struct{}

// ResolveTarget implements ipfw.TargetResolver.
func (anyTargets) ResolveTarget(ipfw.Target) ([]net4, []net6, error) {
	return []net4{parse4("192.0.2.0/28")}, []net6{parse6("2001:db8::/64")}, nil
}

// everyMatcher is a ruleset touching every matcher of the VM, so that a
// check of it reaches all of them whatever the packet is.
const everyMatcher = "table t add 203.0.113.0/24\ntable i add vlan1234 :SECTION\n" +
	"add deny udp from 198.51.100.0/24 to table(t) 53\n" +
	"add count ip from any to any icmptypes 0,8\n" +
	"add count ip from any to any icmp6types 128,129\n" +
	"add deny tcp from any 1-1023 to me6 not established\n" +
	"add deny ip from host.example.com to _NETS_ frag\n" +
	"add count tcp from any to any tcpflags syn,!ack dst-port 8080,8443\n" +
	"add count ip from any to any { proto 17 or out } keep-state :flow\n" +
	"add skipto tablearg ip from any to any via table(i) in\n" +
	":SECTION\n" +
	"add deny ip from not me to { table(t) or 2001:db8::/32 } antispoof\n" +
	"add pass tcp from 192.0.2.0/24 not 25 to any 443 via vlan1??? established\n" +
	"add deny ip from any to any\n"

// everyMatcherVM builds the ruleset above, whose jump goes to its label
// and whose names any resolver serves.
func everyMatcherVM(t *testing.T) *vm.VM[net4, net6] {
	t.Helper()
	machine, err := vm.Build(ipfw.NewParser(everyMatcher), vm.Config[net4, net6]{
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
				if action, matched := machine.CheckTrace(syntheticContext, packet, nopTracer{}); matched && action != expected {
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
func benchmarkCheck(b *testing.B, ruleset string) {
	b.Helper()
	machine, err := vm.Build(ipfw.NewParser(ruleset), vm.Config[net4, net6]{
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

func Benchmark_VM_Check_Jumps(b *testing.B) {
	var ruleset strings.Builder
	for idx := range 1000 {
		fmt.Fprintf(&ruleset, "add skipto :S%d ip from any to any\nadd deny ip from any to any\n:S%d\n", idx, idx)
	}
	ruleset.WriteString("add pass ip from any to any\n")
	benchmarkCheck(b, ruleset.String())
}

func Benchmark_VM_Check_EveryMatcher(b *testing.B) {
	benchmarkCheck(b, strings.Repeat(everyMatcher, 100))
}

func Benchmark_VM_Build_Large(b *testing.B) {
	ruleset := strings.Repeat(everyMatcher, 100)
	cfg := vm.Config[net4, net6]{
		Environment:     ipfw.Environment[net4, net6]{Networks: nets, Protos: fakeProtos{}, Targets: anyTargets{}},
		UnresolvedJumps: vm.UnresolvedJumpsFallThrough,
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(ruleset)))
	for b.Loop() {
		if _, err := vm.Build(ipfw.NewParser(ruleset), cfg); err != nil {
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
				Parse4:    xnetip.ParseNetwork4,
				Parse6:    xnetip.ParseNetwork6,
				FromAddr4: xnetip.Network4FromAddr,
				FromAddr6: xnetip.Network6FromAddr,
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
