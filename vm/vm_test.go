package vm_test

import (
	"net/netip"
	"strconv"
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

// resolving is the configuration with the fake protocol resolver.
var resolving = vm.Config[net4, net6]{Protos: fakeProtos{}}

// build builds a VM from src, failing the test on any error.
func build(t *testing.T, src string, cfg vm.Config[net4, net6]) *vm.VM[net4, net6] {
	t.Helper()
	machine, err := vm.Build(ipfw.NewParser(src), nets, cfg)
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
			machine := build(t, tc.rules, resolving)
			require.Equal(t, tc.verdict, machine.Check(&vm.Context{}, tc.packet))
		})
	}
}

// verifies that nothing matching yields the default verdict, deny unless
// configured, and that CheckTrace reports no termination then.
func Test_VM_Check_DefaultVerdict(t *testing.T) {
	packet := tcp4("192.0.2.1", "192.0.2.1")
	empty := build(t, "", resolving)
	require.Equal(t, deny, empty.Check(&vm.Context{}, packet))
	require.Equal(t, 0, empty.Len())

	permissive := build(t, "add deny udp from any to any\n", vm.Config[net4, net6]{
		Protos:         fakeProtos{},
		DefaultVerdict: pass,
	})
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
	machine := build(t, "add deny udp from any to any\n# c\nadd deny ip from 198.51.100.0/24 to any\nadd pass tcp from any to any\nadd deny ip from any to any\n", resolving)
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
	_, matched = build(t, "add pass tcp from any to any\n", resolving).CheckTrace(&vm.Context{}, icmp, tracer)
	require.False(t, matched)
	require.Equal(t, []traced{{line: 1, action: ipfw.ActionPass, matched: false}}, tracer.seen)
}

// verifies that every build error is located at its line and wraps its
// cause.
//
// A line that does not parse, an action, a target kind, ports and options
// the VM does not take yet, a protocol name with no resolver, a hostname.
func Test_VM_Build_Errors(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		cfg   vm.Config[net4, net6]
		line  int
		text  string
		cause error
	}{
		{
			name:  "parse error",
			rules: "add pass ip from any to any\nadd foobar :any\n",
			cfg:   resolving,
			line:  2,
			text:  "add foobar :any",
			cause: ipfw.ErrExpectedAction,
		},
		{
			name:  "unsupported action",
			rules: "add count ip from any to any\n",
			cfg:   resolving,
			line:  1,
			text:  "add count ip from any to any",
			cause: vm.ErrUnsupportedAction,
		},
		{
			name:  "unsupported target",
			rules: "add pass ip from me to any\n",
			cfg:   resolving,
			line:  1,
			text:  "add pass ip from me to any",
			cause: vm.ErrUnsupportedTarget,
		},
		{
			name:  "unsupported ports",
			rules: "add pass tcp from any 22 to any\n",
			cfg:   resolving,
			line:  1,
			text:  "add pass tcp from any 22 to any",
			cause: vm.ErrUnsupportedPort,
		},
		{
			name:  "unsupported option",
			rules: "add pass tcp from any to any established\n",
			cfg:   resolving,
			line:  1,
			text:  "add pass tcp from any to any established",
			cause: vm.ErrUnsupportedOption,
		},
		{
			name:  "unsupported record",
			rules: ":LABEL\n",
			cfg:   resolving,
			line:  1,
			text:  ":LABEL",
			cause: vm.ErrUnsupportedRecord,
		},
		{
			name:  "unresolved protocol without a resolver",
			rules: "add pass tcp from any to any\n",
			cfg:   vm.Config[net4, net6]{},
			line:  1,
			text:  "add pass tcp from any to any",
			cause: vm.ErrUnresolvedProto,
		},
		{
			name:  "unresolved protocol name",
			rules: "add pass gre from any to any\n",
			cfg:   resolving,
			line:  1,
			text:  "add pass gre from any to any",
			cause: vm.ErrUnresolvedProto,
		},
		{
			name:  "hostname without a resolver",
			rules: "add pass ip from host.example.com to any\n",
			cfg:   resolving,
			line:  1,
			text:  "add pass ip from host.example.com to any",
			cause: vm.ErrUnresolvedHostname,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := vm.Build(ipfw.NewParser(tc.rules), nets, tc.cfg)
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
	_, err := vm.Build(ipfw.NewParser("add pass ip from any to any\n  add foobar :any\n"), nets, resolving)
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
	machine := build(t, "add pass 6 from any to any\nadd deny ip from any to any\n", vm.Config[net4, net6]{})
	require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1")))
}

// verifies that a check allocates nothing.
func Test_VM_Check_NoAllocs(t *testing.T) {
	machine := build(t, "add deny udp from any to any\nadd deny ip from 198.51.100.0/24 to any\nadd pass tcp from 192.0.2.0/24 to { any or 2001:db8::/32 }\nadd deny ip from any to any\n", resolving)
	packet := tcp4("192.0.2.1", "192.0.2.1")
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

// verifies that one VM serves checks from several goroutines at once.
func Test_VM_Check_Concurrent(t *testing.T) {
	machine := build(t, "add pass tcp from 192.0.2.0/24 to any\nadd deny ip from any to any\n", resolving)
	for idx := range 8 {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			t.Parallel()
			for range 1000 {
				require.Equal(t, pass, machine.Check(&vm.Context{}, tcp4("192.0.2.1", "192.0.2.1")))
				require.Equal(t, deny, machine.Check(&vm.Context{}, tcp4("198.51.100.1", "192.0.2.1")))
			}
		})
	}
}
