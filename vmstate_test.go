package ipfw_test

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yanet-platform/xnetip"

	"github.com/yanet-platform/ipfw-go"
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

// nets plugs xnetip into the typed state.
var nets = ipfw.NetworkParserFuncs[net4, net6]{
	Parse4: xnetip.ParseNetwork4,
	Parse6: xnetip.ParseNetwork6,
}

var (
	_ ipfw.State                     = (*ipfw.Resolver[net4, net6])(nil)
	_ ipfw.VMState[net4, net6]       = (*ipfw.ReduceVMState[net4, net6])(nil)
	_ ipfw.NetworkParser[net4, net6] = ipfw.NetworkParserFuncs[net4, net6]{}
)

// verifies that raw custom tokens resolve without losing negation, patterns or address families.
func Test_Resolver_CompatibilityTargets(t *testing.T) {
	const input = "add pass ip from { not custom:first or custom:second } to table(_EX_TABLE_)"
	parser := ipfw.NewParser(input)
	var raw ipfw.ReduceState
	record, err := parser.Next(&raw)
	require.Nil(t, err)
	wantRecord := passAnyToAny(1, input)
	require.Equal(t, wantRecord, *record)
	require.Equal(t, ipfw.ReduceState{
		IPProtos: ipAny,
		Sources: []ipfw.Target{
			{Neg: true, Kind: ipfw.TargetCustom, Text: "custom:first"},
			{Pattern: 1, Kind: ipfw.TargetCustom, Text: "custom:second"},
		},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetTable, Text: "_EX_TABLE_"}},
	}, raw)
	next(t, parser, eof)

	networks4 := []net4{must4("192.0.2.0/24"), must4("198.51.100.0/24")}
	networks6 := []net6{must6("2001:db8::/32")}
	var seen []ipfw.Target
	targets := exampleTargetResolver(func(target ipfw.Target) ([]net4, []net6, error) {
		seen = append(seen, target)
		switch target.Text {
		case "custom:first":
			return networks4, networks6, nil
		case "custom:second":
			return nil, networks6, nil
		default:
			return nil, nil, ipfw.ErrUnresolvedTarget
		}
	})
	var typed ipfw.ReduceVMState[net4, net6]
	resolver := ipfw.NewResolver(&typed, ipfw.Environment[net4, net6]{Targets: targets})
	parser.Reset(input)
	record, err = parser.Next(resolver)
	require.Nil(t, err)
	require.Equal(t, wantRecord, *record)
	require.Equal(t, raw.Sources, seen)
	require.Equal(t, ipfw.ReduceVMState[net4, net6]{
		IPProtos: ipAny,
		Sources: []ipfw.TargetMatch[net4, net6]{
			{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.0/24")},
			{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("198.51.100.0/24")},
			{Neg: true, Kind: ipfw.TargetNetwork6, Net6: must6("2001:db8::/32")},
			{Pattern: 1, Kind: ipfw.TargetNetwork6, Net6: must6("2001:db8::/32")},
		},
		Destinations: []ipfw.TargetMatch[net4, net6]{
			{Kind: ipfw.TargetTable, Name: "_EX_TABLE_"},
		},
	}, typed)
	next(t, parser, eof)
	ok := true
	allocations := testing.AllocsPerRun(100, func() {
		seen = seen[:0]
		typed.Reset()
		parser.Reset(input)
		if _, err := parser.Next(resolver); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocations)
}

type exampleTargetResolver func(ipfw.Target) ([]net4, []net6, error)

// ResolveTarget delegates the consumer's token policy to a test callback.
func (m exampleTargetResolver) ResolveTarget(target ipfw.Target) ([]net4, []net6, error) {
	return m(target)
}

// verifies that custom tokens stay whole and resolver failures retain their position and cause.
func Test_Resolver_CompatibilityTargetPolicies(t *testing.T) {
	cause := errors.New("example resolution failed")
	cases := []struct {
		name          string
		input         string
		text          string
		kind          ipfw.TargetKind
		cause         error
		expectedKind  ipfw.ErrorKind
		expectedCause error
	}{
		{
			name: "whole custom token", input: "add pass ip from custom:whole to any",
			text: "custom:whole", kind: ipfw.TargetCustom,
		},
		{
			name: "known empty custom token", input: "add pass ip from custom:empty to any",
			text: "custom:empty", kind: ipfw.TargetCustom,
		},
		{
			name: "known empty hostname", input: "add pass ip from empty.example.com to any",
			text: "empty.example.com", kind: ipfw.TargetHostname,
		},
		{
			name: "missing custom token", input: "add pass ip from custom:missing to any",
			text: "custom:missing", kind: ipfw.TargetCustom, cause: ipfw.ErrUnresolvedTarget,
			expectedKind: ipfw.ErrUnresolvedTarget,
		},
		{
			name: "rejected custom token", input: "add pass ip from custom:rejected to any",
			text: "custom:rejected", kind: ipfw.TargetCustom, cause: ipfw.ErrExpectedTarget,
			expectedKind: ipfw.ErrExpectedTarget,
		},
		{
			name: "ordinary resolver error", input: "add pass ip from custom:failed to any",
			text: "custom:failed", kind: ipfw.TargetCustom, cause: cause,
			expectedKind: ipfw.ErrState, expectedCause: cause,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var seen []ipfw.Target
			targets := exampleTargetResolver(func(target ipfw.Target) ([]net4, []net6, error) {
				seen = append(seen, target)
				return nil, nil, testCase.cause
			})
			var state ipfw.ReduceVMState[net4, net6]
			resolver := ipfw.NewResolver(&state, ipfw.Environment[net4, net6]{Targets: targets})
			parser := ipfw.NewParser(testCase.input)
			record, err := parser.Next(resolver)
			wantState := ipfw.ReduceVMState[net4, net6]{IPProtos: ipAny}
			if testCase.cause != nil {
				require.Nil(t, record)
				require.NotNil(t, err)
				require.Equal(t, ipfw.ParseError{
					Kind: testCase.expectedKind, Err: testCase.expectedCause,
					Line: 1, Column: 17, Text: testCase.input,
				}, *err)
				require.ErrorIs(t, err, testCase.cause)
			} else {
				require.Nil(t, err)
				require.Equal(t, passAnyToAny(1, testCase.input), *record)
				wantState.Destinations = []ipfw.TargetMatch[net4, net6]{{Kind: ipfw.TargetAny}}
			}
			require.Equal(t, wantState, state)
			require.Equal(t, []ipfw.Target{{Kind: testCase.kind, Text: testCase.text}}, seen)
			next(t, parser, eof)
		})
	}
}

// verifies that inet and service names retain consumer-owned resolution and option grouping.
func Test_Resolver_CompatibilityNames(t *testing.T) {
	const input = "add pass inet from any ssh to any domain not dst-port ssh { proto tcp or in }"
	parser := ipfw.NewParser(input)
	var raw ipfw.ReduceState
	record, err := parser.Next(&raw)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, input), *record)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "inet"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		SourcePorts:  []ipfw.PortMatch{{Lo: ipfw.Port{Name: "ssh"}, Hi: ipfw.Port{Name: "ssh"}}},
		DestinationPorts: []ipfw.PortMatch{
			{Lo: ipfw.Port{Name: "domain"}, Hi: ipfw.Port{Name: "domain"}},
		},
		Options: []ipfw.Opt{
			{
				Neg: true, Kind: ipfw.OptDestinationPort,
				Ports: ipfw.PortRange{Lo: ipfw.Port{Name: "ssh"}, Hi: ipfw.Port{Name: "ssh"}},
			},
			{Block: 1, Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "tcp"}},
			{Block: 1, Pattern: 1, Kind: ipfw.OptIn},
		},
	}, raw)
	next(t, parser, eof)

	var state ipfw.ReduceVMState[net4, net6]
	resolver := ipfw.NewResolver(&state, ipfw.Environment[net4, net6]{
		Protos: exampleProtoResolver{"inet": 253, "tcp": 6}, Services: fakeServices{},
	})
	parser.Reset(input)
	record, err = parser.Next(resolver)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, input), *record)
	require.Equal(t, ipfw.ReduceVMState[net4, net6]{
		Protos:           []ipfw.ProtoNumberMatch{{Number: 253}},
		Sources:          []ipfw.TargetMatch[net4, net6]{{Kind: ipfw.TargetAny}},
		Destinations:     []ipfw.TargetMatch[net4, net6]{{Kind: ipfw.TargetAny}},
		SourcePorts:      []ipfw.PortNumberMatch{{Lo: 22, Hi: 22}},
		DestinationPorts: []ipfw.PortNumberMatch{{Lo: 53, Hi: 53}},
		Options: []ipfw.Opt{
			{
				Neg: true, Kind: ipfw.OptDestinationPort,
				Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 22}, Hi: ipfw.Port{Number: 22}},
			},
			{Block: 1, Kind: ipfw.OptProto, Proto: ipfw.Proto{Number: 6}},
			{Block: 1, Pattern: 1, Kind: ipfw.OptIn},
		},
	}, state)
	next(t, parser, eof)

	parser.Reset(input)
	state = ipfw.ReduceVMState[net4, net6]{}
	record, err = parser.Next(ipfw.NewResolver(&state, networksOnly))
	require.Nil(t, record)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 9, Text: input,
	}, *err)
	require.Equal(t, ipfw.ReduceVMState[net4, net6]{}, state)
	next(t, parser, eof)
}

type exampleProtoResolver map[string]uint8

// ResolveProto returns only explicitly configured protocol names.
func (m exampleProtoResolver) ResolveProto(name string) (uint8, bool) {
	number, ok := m[name]
	return number, ok
}

// protoChecker knows the protocols the resolver resolves.
func protoChecker(resolver ipfw.ProtoResolver) ipfw.ProtoCheckerFunc {
	return func(name string) bool {
		_, ok := resolver.ResolveProto(name)
		return ok
	}
}

// verifies that one proto checker chooses the same grammar for a raw state, a
// resolver and a wrapper forwarding only the State callbacks.
func Test_Resolver_ProtoCheckerGrammar(t *testing.T) {
	protos := exampleProtoResolver{"in": 6, "tcp": 6}
	cases := []struct {
		name     string
		input    string
		expected *ipfw.ParseError
	}{
		{name: "known option-shaped protocol", input: "add pass in from any to any"},
		{
			name:  "known option-shaped protocol needs from",
			input: "add pass in proto tcp",
			expected: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedFrom,
				Line:   1,
				Column: 12,
				Text:   "add pass in proto tcp",
			},
		},
		{
			name:  "unknown protocol name selects options",
			input: "add pass udp from any to any",
			expected: &ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 9,
				Text:   "add pass udp from any to any",
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var raw ipfw.ReduceState
			var sink ipfw.ReduceVMState[net4, net6]
			resolver := ipfw.NewResolver(&sink, ipfw.Environment[net4, net6]{
				Networks: nets,
				Protos:   protos,
			})
			states := map[string]ipfw.State{
				"raw":      &raw,
				"resolver": resolver,
				"wrapper":  &grammarOpaqueState{State: resolver},
			}
			for name, state := range states {
				parser := ipfw.NewParser(test.input, ipfw.WithProtoChecker(protoChecker(protos)))
				record, err := parser.Next(state)
				require.Equal(t, test.expected, err, name)
				if test.expected == nil {
					require.Equal(t, passAnyToAny(1, test.input), *record, name)
				} else {
					require.Nil(t, record, name)
				}
			}
		})
	}
}

// verifies that a consuming sink's error cannot be mistaken for an unknown protocol.
func Test_Resolver_GrammarSelection_SinkError(t *testing.T) {
	const input = "add allow in"
	var sink grammarRejectingSink
	protos := exampleProtoResolver{"in": 6}
	state := ipfw.NewResolver(&sink, ipfw.Environment[net4, net6]{
		Protos: protos,
	})
	parser := ipfw.NewParser(input, ipfw.WithProtoChecker(protoChecker(protos)))
	record, err := parser.Next(state)
	require.Nil(t, record)
	require.Equal(t, &ipfw.ParseError{
		Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 10, Text: input,
	}, err)
	require.Equal(t, ipfw.ReduceVMState[net4, net6]{
		Protos: []ipfw.ProtoNumberMatch{{Number: 6}},
	}, sink.ReduceVMState)
	next(t, parser, eof)
}

// grammarRejectingSink records a protocol before rejecting it.
type grammarRejectingSink struct {
	ipfw.ReduceVMState[net4, net6]
}

// OnProto preserves its side effect when returning an unresolved-protocol error.
func (m *grammarRejectingSink) OnProto(match ipfw.ProtoNumberMatch) error {
	if err := m.ReduceVMState.OnProto(match); err != nil {
		return err
	}
	return ipfw.ErrUnresolvedProto
}

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
// A hostname stands for a host of each family, `custom:first` for two IPv4
// networks, `local` for one, and the empty names for nothing. Anything else is
// rejected.
type fakeTargets struct {
	nets4 []net4
	nets6 []net6
}

// ResolveTarget implements ipfw.TargetResolver.
func (m *fakeTargets) ResolveTarget(target ipfw.Target) ([]net4, []net6, error) {
	m.nets4, m.nets6 = m.nets4[:0], m.nets6[:0]
	switch target.Text {
	case "host.example.com":
		m.nets4 = append(m.nets4, must4("192.0.2.1/32"))
		m.nets6 = append(m.nets6, must6("2001:db8::1/128"))
	case "custom:first":
		m.nets4 = append(m.nets4, must4("192.0.2.0/24"), must4("198.51.100.0/24"))
	case "local":
		m.nets4 = append(m.nets4, must4("203.0.113.0/24"))
	case "inet", "empty.example.com":
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
					{Pattern: 1, Kind: ipfw.TargetNetwork6, Net6: must6("::1")},
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
			name: "negated address lists",
			input: "add allow ip from not 192.0.2.1,198.51.100.1 " +
				"to not 2001:db8::1,2001:db8::2\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos: ipAny,
				Sources: []ipfw.TargetMatch[net4, net6]{
					{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.1")},
					{
						Neg:  true,
						Kind: ipfw.TargetNetwork4,
						Net4: must4("198.51.100.1"),
					},
				},
				Destinations: []ipfw.TargetMatch[net4, net6]{
					{Neg: true, Kind: ipfw.TargetNetwork6, Net6: must6("2001:db8::1")},
					{
						Neg:  true,
						Kind: ipfw.TargetNetwork6,
						Net6: must6("2001:db8::2"),
					},
				},
			},
		},
		{
			name:  "keywords and a table keep their name and value",
			input: "add allow ip from { me or me6 or table(t) } to not table(u,:V)\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos: ipAny,
				Sources: []ipfw.TargetMatch[net4, net6]{
					{Kind: ipfw.TargetMe},
					{Pattern: 1, Kind: ipfw.TargetMe6},
					{Pattern: 2, Kind: ipfw.TargetTable, Name: "t"},
				},
				Destinations: []ipfw.TargetMatch[net4, net6]{
					{Neg: true, Kind: ipfw.TargetTable, Name: "u,:V"},
				},
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
			name:  "protocol option name becomes a number",
			input: "add allow ip from any to any proto udp\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos:     ipAny,
				Sources:      []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				Options: []ipfw.Opt{
					{Kind: ipfw.OptProto, Proto: ipfw.Proto{Number: 17}},
				},
			},
		},
		{
			name:  "service port list keeps list membership",
			input: "add allow ip from any to any dst-port ssh,domain-70\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos:     ipAny,
				Sources:      []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				Options: []ipfw.Opt{
					{
						Kind:  ipfw.OptDestinationPort,
						Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 22}, Hi: ipfw.Port{Number: 22}},
					},
					{
						Kind:  ipfw.OptDestinationPort,
						Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 53}, Hi: ipfw.Port{Number: 70}},
					},
				},
			},
		},
		{
			name:  "argument-free option passes through",
			input: "add allow ip from any to any established\n",
			state: ipfw.ReduceVMState[net4, net6]{
				IPProtos:     ipAny,
				Sources:      []ipfw.TargetMatch[net4, net6]{anyTarget},
				Destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				Options: []ipfw.Opt{
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
			name:  "hostname and custom token",
			input: "add allow ip from not host.example.com to custom:first\n",
			sources: []ipfw.TargetMatch[net4, net6]{
				{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.1/32")},
				{Neg: true, Kind: ipfw.TargetNetwork6, Net6: must6("2001:db8::1/128")},
			},
			destinations: []ipfw.TargetMatch[net4, net6]{
				{Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.0/24")},
				{Kind: ipfw.TargetNetwork4, Net4: must4("198.51.100.0/24")},
			},
		},
		{
			name:  "resolved name inside a group keeps the order",
			input: "add allow ip from { 192.0.2.5 or local or ::1 } to any\n",
			sources: []ipfw.TargetMatch[net4, net6]{
				{Kind: ipfw.TargetNetwork4, Net4: must4("192.0.2.5")},
				{Pattern: 1, Kind: ipfw.TargetNetwork4, Net4: must4("203.0.113.0/24")},
				{Pattern: 2, Kind: ipfw.TargetNetwork6, Net6: must6("::1")},
			},
			destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
		},
		{
			name: "empty first address list member keeps its pattern",
			input: "add allow ip from { 203.0.113.1 or " +
				"not empty.example.com,host.example.com } to any\n",
			sources: []ipfw.TargetMatch[net4, net6]{
				{Kind: ipfw.TargetNetwork4, Net4: must4("203.0.113.1")},
				{
					Neg:     true,
					Pattern: 1,
					Kind:    ipfw.TargetNetwork4,
					Net4:    must4("192.0.2.1/32"),
				},
				{
					Neg:     true,
					Pattern: 1,
					Kind:    ipfw.TargetNetwork6,
					Net6:    must6("2001:db8::1/128"),
				},
			},
			destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
		},
		{
			name:  "custom address list",
			input: "add allow ip from not local,custom:first to any\n",
			sources: []ipfw.TargetMatch[net4, net6]{
				{Neg: true, Kind: ipfw.TargetNetwork4, Net4: must4("203.0.113.0/24")},
				{
					Neg:  true,
					Kind: ipfw.TargetNetwork4,
					Net4: must4("192.0.2.0/24"),
				},
				{
					Neg:  true,
					Kind: ipfw.TargetNetwork4,
					Net4: must4("198.51.100.0/24"),
				},
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

// verifies that resolver failures retain their kind and source position.
func Test_Resolver_Errors(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		resolvers ipfw.Environment[net4, net6]
		expected  ipfw.ParseError
	}{
		{
			name:      "protocol name without a resolver",
			input:     "add allow tcp from any to any\n",
			resolvers: networksOnly,
			expected: ipfw.ParseError{
				Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 10, Text: "add allow tcp from any to any",
			},
		},
		{
			name:      "unknown protocol name",
			input:     "add allow gre from any to any\n",
			resolvers: everything,
			expected: ipfw.ParseError{
				Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 10, Text: "add allow gre from any to any",
			},
		},
		{
			name:      "protocol zero in body",
			input:     "add allow 0 from any to any\n",
			resolvers: everything,
			expected: ipfw.ParseError{
				Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 10, Text: "add allow 0 from any to any",
			},
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
			name:      "protocol zero in an option",
			input:     "add allow ip from any to any proto 0\n",
			resolvers: everything,
			expected:  ipfw.ParseError{Kind: ipfw.ErrUnresolvedProto, Line: 1, Column: 35, Text: "add allow ip from any to any proto 0"},
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

// verifies that a rejected network retains its family and parser cause.
func Test_Resolver_NetworkErrorCause(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		kind   ipfw.ErrorKind
		column int
	}{
		{
			name:   "IPv4",
			input:  "add allow ip from 300.1.1.1 to any\n",
			kind:   ipfw.ErrExpectedIPv4Network,
			column: 18,
		},
		{
			name:   "IPv6",
			input:  "add allow ip from any to 2001:db8:::1\n",
			kind:   ipfw.ErrExpectedIPv6Network,
			column: 25,
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
			var sink ipfw.ReduceVMState[net4, net6]
			_, err := ipfw.NewParser(tc.input).Next(ipfw.NewResolver(&sink, environment))
			require.Error(t, err)
			require.Equal(t, tc.kind, err.Kind)
			require.Equal(t, tc.column, err.Column)
			require.ErrorIs(t, err, tc.kind)
			require.ErrorIs(t, err, cause)
			var parserErr *networkParserError
			require.ErrorAs(t, err, &parserErr)
			require.Same(t, cause, parserErr)
		})
	}
}

// verifies that the target family overrides conflicting kinds from the parser cause.
func Test_Resolver_NetworkErrorCause_ConflictingKinds(t *testing.T) {
	cause := &networkParserError{text: "network parser failed"}
	environment := ipfw.Environment[net4, net6]{
		Networks: ipfw.NetworkParserFuncs[net4, net6]{
			Parse4: func(string) (net4, error) {
				return net4{}, errors.Join(
					ipfw.ErrExpectedIPv6Network,
					ipfw.ErrExpectedIPv4Network.Wrap(cause),
				)
			},
			Parse6: xnetip.ParseNetwork6,
		},
	}
	var sink ipfw.ReduceVMState[net4, net6]
	_, err := ipfw.NewParser("add allow ip from 300.1.1.1 to any\n").Next(
		ipfw.NewResolver(&sink, environment),
	)
	require.Error(t, err)
	require.Equal(t, ipfw.ErrExpectedIPv4Network, err.Kind)
	require.ErrorIs(t, err, cause)
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

// verifies that both grammar paths parse into a warmed-up typed state without allocating.
func Test_Resolver_NoAllocs(t *testing.T) {
	for _, input := range []string{
		"add allow tcp from { custom:first or host.example.com,192.0.2.1 } ssh to" +
			" 198.51.100.0/24,203.0.113.0/24 domain-70 proto udp dst-port ssh\n",
		"add allow { not in or out } proto tcp dst-port ssh\n",
	} {
		parser := ipfw.NewParser(input, ipfw.WithProtoChecker(protoChecker(fakeProtos{})))
		var sink ipfw.ReduceVMState[net4, net6]
		state := ipfw.NewResolver(&sink, everything)
		_, err := parser.Next(state)
		require.Nil(t, err)
		ok := true
		allocs := testing.AllocsPerRun(100, func() {
			parser.Reset(input)
			sink.Reset()
			if _, err := parser.Next(state); err != nil {
				ok = false
			}
		})
		require.True(t, ok)
		require.Zero(t, allocs)
	}
}

func ExampleNewResolver() {
	env := ipfw.Environment[xnetip.Network4, xnetip.Network6]{
		Networks: ipfw.NetworkParserFuncs[xnetip.Network4, xnetip.Network6]{
			Parse4: xnetip.ParseNetwork4,
			Parse6: xnetip.ParseNetwork6,
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
