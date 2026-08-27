package ipfw_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw"
)

type (
	net4 = xnetip.Network4
	net6 = xnetip.Network6
)

// nets plugs xnetip into the typed state.
var nets = ipfw.NetworkParserFuncs[net4, net6]{
	Parse4:    xnetip.ParseNetwork4,
	Parse6:    xnetip.ParseNetwork6,
	FromAddr4: xnetip.Network4FromAddr,
	FromAddr6: xnetip.Network6FromAddr,
}

var (
	_ ipfw.State                     = (*ipfw.Resolver[net4, net6])(nil)
	_ ipfw.VMState[net4, net6]       = (*ipfw.ReduceVMState[net4, net6])(nil)
	_ ipfw.NetworkParser[net4, net6] = ipfw.NetworkParserFuncs[net4, net6]{}
)

// must4 parses IPv4 network text or panics.
func must4(text string) net4 {
	network, err := xnetip.ParseNetwork4(text)
	if err != nil {
		panic(err)
	}
	return network
}

// must6 parses IPv6 network text or panics.
func must6(text string) net6 {
	network, err := xnetip.ParseNetwork6(text)
	if err != nil {
		panic(err)
	}
	return network
}

// fakeProtos resolves the protocol names the tests use.
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
	case "icmp6":
		return 58, true
	}
	return 0, false
}

// fakeServices resolves the service names the tests use.
type fakeServices struct{}

// ResolveService implements ipfw.ServiceResolver.
func (fakeServices) ResolveService(name string) (uint16, bool) {
	switch name {
	case "ssh":
		return 22, true
	case "domain":
		return 53, true
	}
	return 0, false
}

// fakeTargets resolves the names the tests use and hands out the same
// slices every time.
//
// A hostname stands for a host of each family, a `_NAME_` macro for two
// IPv4 networks, `local` for one, `inet` for nothing, anything else is
// rejected.
type fakeTargets struct {
	nets4 []net4
	nets6 []net6
}

// ResolveTarget implements ipfw.TargetResolver.
func (m *fakeTargets) ResolveTarget(target ipfw.Target) ([]net4, []net6, error) {
	m.nets4, m.nets6 = m.nets4[:0], m.nets6[:0]
	switch text := target.Text; {
	case text == "host.example.com":
		m.nets4 = append(m.nets4, must4("192.0.2.1/32"))
		m.nets6 = append(m.nets6, must6("2001:db8::1/128"))
	case len(text) > 2 && text[0] == '_' && text[len(text)-1] == '_':
		m.nets4 = append(m.nets4, must4("192.0.2.0/24"), must4("198.51.100.0/24"))
	case text == "local":
		m.nets4 = append(m.nets4, must4("203.0.113.0/24"))
	case text == "inet":
	default:
		return nil, nil, ipfw.ErrExpectedTarget
	}
	return m.nets4, m.nets6, nil
}

// everything resolves protocols, services and targets.
var everything = ipfw.Environment[net4, net6]{
	Networks: nets,
	Protos:   fakeProtos{},
	Services: fakeServices{},
	Targets:  &fakeTargets{},
}

// networksOnly parses networks and resolves no name.
var networksOnly = ipfw.Environment[net4, net6]{Networks: nets}

// resolved parses one line through a Resolver into a fresh ReduceVMState,
// failing the test on an error.
func resolved(t *testing.T, line string, resolvers ipfw.Environment[net4, net6]) ipfw.ReduceVMState[net4, net6] {
	t.Helper()
	var sink ipfw.ReduceVMState[net4, net6]
	_, err := ipfw.NewParser(line).Next(ipfw.NewResolver(&sink, resolvers))
	require.Nil(t, err)
	return sink
}

// rejected parses one line through a Resolver and returns its error.
func rejected(t *testing.T, line string, resolvers ipfw.Environment[net4, net6]) ipfw.ParseError {
	t.Helper()
	var sink ipfw.ReduceVMState[net4, net6]
	_, err := ipfw.NewParser(line).Next(ipfw.NewResolver(&sink, resolvers))
	require.NotNil(t, err)
	return *err
}

var (
	anyTarget = ipfw.TargetMatch[net4, net6]{Kind: ipfw.TargetAny}
	ipAny     = []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}}
)

// verifies that the resolver hands networks on parsed with the consumer's
// types, keywords and tables by name, version keywords as they are.
func Test_Resolver_Networks(t *testing.T) {
	cases := []struct {
		name  string
		input string
		state ipfw.ReduceVMState[net4, net6]
	}{
		{
			name:  "group of both families",
			input: "add allow ip from { 192.0.2.0/24 or ::1 } to any\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos: ipAny,
				Sources: []ipfw.TargetMatch[net4, net6]{
					{Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.0/24")},
					{Kind: ipfw.TargetNetwork6, Net6: must6("::1")},
				},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
			},
		},
		{
			name:  "negated network",
			input: "add allow ip from not 192.0.2.0/24 to any\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos: ipAny,
				Sources: []ipfw.TargetMatch[net4, net6]{
					{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.0/24")},
				},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
			},
		},
		{
			name:  "keywords and a table keep their name",
			input: "add allow ip from { me or me6 or table(t) } to any\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos: ipAny,
				Sources: []ipfw.TargetMatch[net4, net6]{
					{Kind: ipfw.TargetMe},
					{Kind: ipfw.TargetMe6},
					{Kind: ipfw.TargetTable, Name: "t"},
				},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.state, resolved(t, tc.input, networksOnly))
		})
	}
}

// verifies that protocol and service names become numbers, a number
// passing through, with the negation kept.
func Test_Resolver_Names(t *testing.T) {
	cases := []struct {
		name  string
		input string
		state ipfw.ReduceVMState[net4, net6]
	}{
		{
			name:  "protocol name",
			input: "add allow tcp from any to any\n",
			state: ipfw.ReduceVMState[net4, net6]{
				Protos:       []ipfw.ProtoNumberMatch{{Number: 6}},
				Sources:      []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
			},
		},
		{
			name:  "protocol group with a number and a negation",
			input: "add allow { not udp or 47 } from any to any\n",
			state: ipfw.ReduceVMState[net4, net6]{
				Protos:       []ipfw.ProtoNumberMatch{{Neg: true, Number: 17}, {Number: 47}},
				Sources:      []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
			},
		},
		{
			name:  "service names in ports and ranges",
			input: "add allow tcp from any ssh,1024-65535 to any not domain-ssh\n",
			state: ipfw.ReduceVMState[net4, net6]{
				Protos:           []ipfw.ProtoNumberMatch{{Number: 6}},
				Sources:          []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations:     []ipfw.TargetMatch[net4, net6]{anyTarget},
				SourcePorts:      []ipfw.PortNumberMatch{{Lo: 22, Hi: 22}, {Lo: 1024, Hi: 65535}},
				DestinationPorts: []ipfw.PortNumberMatch{{Neg: true, Lo: 53, Hi: 22}},
			},
		},
		{
			name:  "option arguments",
			input: "add allow ip from any to any proto udp dst-port ssh,domain-70 established\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos:     ipAny,
				Sources:      []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				Options: []ipfw.Opt{
					{Kind: ipfw.OptProto, Proto: ipfw.Proto{Number: 17}},
					{
						Kind:  ipfw.OptDestinationPort,
						Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 22}, Hi: ipfw.Port{Number: 22}},
					},
					{
						Or:    true,
						Kind:  ipfw.OptDestinationPort,
						Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 53}, Hi: ipfw.Port{Number: 70}},
					},
					{Kind: ipfw.OptEstablished},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.state, resolved(t, tc.input, everything))
		})
	}
}

// verifies that a resolver stands hostnames and targets of unknown shape
// for networks of both families, one call per network.
//
// The negation is copied to each, and a name standing for nothing leaves
// the side empty.
func Test_Resolver_Targets(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		sources      []ipfw.TargetMatch[net4, net6]
		destinations []ipfw.TargetMatch[net4, net6]
	}{
		{
			name:  "hostname and macro",
			input: "add allow ip from not host.example.com to _X_\n",
			sources: []ipfw.TargetMatch[net4, net6]{
				{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.1/32")},
				{Neg: true, Or: true, Kind: ipfw.TargetNetwork6, Net6: must6("2001:db8::1/128")},
			},
			destinations: []ipfw.TargetMatch[net4, net6]{
				{Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.0/24")},
				{Or: true, Kind: ipfw.TargetNetwork4, Net4: must4("198.51.100.0/24")},
			},
		},
		{
			name:  "resolved name inside a group keeps the order",
			input: "add allow ip from { 192.0.2.5 or local or ::1 } to any\n",
			sources: []ipfw.TargetMatch[net4, net6]{
				{Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.5")},
				{Kind: ipfw.TargetNetwork4, Net4: must4("203.0.113.0/24")},
				{Kind: ipfw.TargetNetwork6, Net6: must6("::1")},
			},
			destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
		},
		{
			name:         "name standing for nothing leaves the side empty",
			input:        "add allow ip from inet to any\n",
			sources:      nil,
			destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := resolved(t, tc.input, everything)
			require.Equal(t, tc.sources, state.Sources)
			require.Equal(t, tc.destinations, state.Destinations)
		})
	}
}

// verifies that a name the resolvers cannot turn into a value, or network
// text they reject, fails the line at the token with the kind of its family.
func Test_Resolver_Errors(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		resolvers ipfw.Environment[net4, net6]
		expected  ipfw.ParseError
	}{
		{
			name:      "invalid IPv4 network",
			input:     "add allow ip from 300.1.1.1 to any\n",
			resolvers: networksOnly,
			expected:  ipfw.ParseError{Kind: ipfw.ErrExpectedIPv4Network, Line: 1, Column: 18, Text: "add allow ip from 300.1.1.1 to any"},
		},
		{
			name:      "invalid IPv6 network",
			input:     "add allow ip from any to 2001:db8:::1\n",
			resolvers: networksOnly,
			expected:  ipfw.ParseError{Kind: ipfw.ErrExpectedIPv6Network, Line: 1, Column: 25, Text: "add allow ip from any to 2001:db8:::1"},
		},
		{
			name:      "protocol name without a resolver",
			input:     "add allow tcp from any to any\n",
			resolvers: networksOnly,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 10, Text: "add allow tcp from any to any"},
		},
		{
			name:      "unknown protocol name",
			input:     "add allow gre from any to any\n",
			resolvers: everything,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 10, Text: "add allow gre from any to any"},
		},
		{
			name:      "service name without a resolver",
			input:     "add allow ip from any ssh to any\n",
			resolvers: networksOnly,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedService, Line: 1, Column: 22, Text: "add allow ip from any ssh to any"},
		},
		{
			name:      "unknown service at the end of a range",
			input:     "add allow ip from any to any 1-bogus\n",
			resolvers: everything,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedService, Line: 1, Column: 29, Text: "add allow ip from any to any 1-bogus"},
		},
		{
			name:      "service name in an option",
			input:     "add allow ip from any to any dst-port bogus\n",
			resolvers: everything,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedService, Line: 1, Column: 38, Text: "add allow ip from any to any dst-port bogus"},
		},
		{
			name:      "protocol name in an option",
			input:     "add allow ip from any to any proto gre\n",
			resolvers: everything,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 35, Text: "add allow ip from any to any proto gre"},
		},
		{
			name:      "hostname without a resolver",
			input:     "add allow ip from any to host.example.com\n",
			resolvers: networksOnly,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedTarget, Line: 1, Column: 25, Text: "add allow ip from any to host.example.com"},
		},
		{
			name:      "custom target without a resolver",
			input:     "add allow ip from 2a02::g to any\n",
			resolvers: networksOnly,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedTarget, Line: 1, Column: 18, Text: "add allow ip from 2a02::g to any"},
		},
		{
			name:      "target the resolver rejects",
			input:     "add allow ip from bogus to any\n",
			resolvers: everything,
			expected:  ipfw.ParseError{Kind: ipfw.ErrExpectedTarget, Line: 1, Column: 18, Text: "add allow ip from bogus to any"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, rejected(t, tc.input, tc.resolvers))
		})
	}
}

// verifies that Reset empties the slices and keeps their capacity.
func Test_ReduceVMState_Reset(t *testing.T) {
	state := resolved(t, "add allow tcp from { 192.0.2.0/24 or ::1 } ssh to any domain established\n", everything)
	capacity := cap(state.Sources)
	require.Positive(t, capacity)
	state.Reset()
	require.Empty(t, state.IPProtos)
	require.Empty(t, state.Protos)
	require.Empty(t, state.Sources)
	require.Empty(t, state.Destinations)
	require.Empty(t, state.SourcePorts)
	require.Empty(t, state.DestinationPorts)
	require.Empty(t, state.Options)
	require.Equal(t, capacity, cap(state.Sources))
}

// verifies that a line exercising every resolver parses into a warmed-up
// typed state without allocating.
func Test_Resolver_NoAllocs(t *testing.T) {
	src := "add allow tcp from { _X_ or host.example.com } ssh to 198.51.100.0/24 domain-70 proto udp dst-port ssh\n"
	parser := ipfw.NewParser(src)
	var sink ipfw.ReduceVMState[net4, net6]
	state := ipfw.NewResolver(&sink, everything)
	_, _ = parser.Next(state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		sink.Reset()
		if _, err := parser.Next(state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

func ExampleNewResolver() {
	env := ipfw.Environment[xnetip.Network4, xnetip.Network6]{
		Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
			Parse4:    xnetip.ParseNetwork4,
			Parse6:    xnetip.ParseNetwork6,
			FromAddr4: xnetip.Network4FromAddr,
			FromAddr6: xnetip.Network6FromAddr,
		},
	}
	var typed ipfw.ReduceVMState[xnetip.Network4, xnetip.Network6]
	rec, err := ipfw.NewParser("add pass ip from 192.0.2.0/24 to 2001:db8::/32 22,80\n").Next(ipfw.NewResolver(&typed, env))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(rec.Instruction.Action, typed.Sources[0].Net4.ContainsAddr(netip.MustParseAddr("192.0.2.7")))
	fmt.Println(typed.Destinations[0].Kind == ipfw.TargetNetwork6, typed.DestinationPorts[0].Lo, typed.DestinationPorts[1].Lo)
	// Output:
	//
	// pass true
	// true 22 80
}
