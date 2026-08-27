package ipfw_test

import (
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
	_ ipfw.State                     = (*ipfw.RuleState[net4, net6])(nil)
	_ ipfw.NetworkParser[net4, net6] = ipfw.NetworkParserFuncs[net4, net6]{}
)

// ruleTokens is the exported part of a RuleState, comparable as a whole.
type ruleTokens struct {
	ipProtos         []ipfw.ProtoIPMatch
	protos           []ipfw.ProtoMatch
	sources          []ipfw.TargetMatch[net4, net6]
	destinations     []ipfw.TargetMatch[net4, net6]
	sourcePorts      []ipfw.PortMatch
	destinationPorts []ipfw.PortMatch
	options          []ipfw.Opt
}

// tokensOf copies the slices of the state for comparison.
func tokensOf(state *ipfw.RuleState[net4, net6]) ruleTokens {
	return ruleTokens{
		ipProtos:         state.IPProtos,
		protos:           state.Protos,
		sources:          state.Sources,
		destinations:     state.Destinations,
		sourcePorts:      state.SourcePorts,
		destinationPorts: state.DestinationPorts,
		options:          state.Options,
	}
}

// newRuleState is a typed state over xnetip with the given custom target
// handler.
func newRuleState(custom ipfw.CustomTargetFunc[net4, net6]) *ipfw.RuleState[net4, net6] {
	return ipfw.NewRuleState[net4, net6](nets, custom)
}

// network4 is a parsed IPv4 network target.
func network4(t *testing.T, text string) ipfw.TargetMatch[net4, net6] {
	t.Helper()
	network, err := xnetip.ParseNetwork4(text)
	require.NoError(t, err)
	return ipfw.TargetMatch[net4, net6]{Kind: ipfw.TargetNetwork4, Net4: network}
}

// network6 is a parsed IPv6 network target.
func network6(t *testing.T, text string) ipfw.TargetMatch[net4, net6] {
	t.Helper()
	network, err := xnetip.ParseNetwork6(text)
	require.NoError(t, err)
	return ipfw.TargetMatch[net4, net6]{Kind: ipfw.TargetNetwork6, Net6: network}
}

// anyTarget is the typed `any`.
var anyTarget = ipfw.TargetMatch[net4, net6]{Kind: ipfw.TargetAny}

// verifies that the typed state parses network text with the consumer's
// types and passes every other token through as it is.
func Test_RuleState_Networks(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		tokens func(t *testing.T) ruleTokens
	}{
		{
			name:  "IPv6 source with ports",
			input: "add allow tcp from 2001:db8::/32 1024-65535 to any domain\n",
			tokens: func(t *testing.T) ruleTokens {
				return ruleTokens{
					protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
					sources:          []ipfw.TargetMatch[net4, net6]{network6(t, "2001:db8::/32")},
					destinations:     []ipfw.TargetMatch[net4, net6]{anyTarget},
					sourcePorts:      []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1024}, ipfw.Port{Number: 65535})},
					destinationPorts: []ipfw.PortMatch{portService("domain")},
				}
			},
		},
		{
			name:  "group of both families",
			input: "add allow ip from { 192.0.2.0/24 or ::1 } to any\n",
			tokens: func(t *testing.T) ruleTokens {
				return ruleTokens{
					ipProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
					sources:      []ipfw.TargetMatch[net4, net6]{network4(t, "192.0.2.0/24"), network6(t, "::1")},
					destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				}
			},
		},
		{
			name:  "negated network",
			input: "add allow ip from not 192.0.2.0/24 to any\n",
			tokens: func(t *testing.T) ruleTokens {
				negated := network4(t, "192.0.2.0/24")
				negated.Neg = true
				return ruleTokens{
					ipProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
					sources:      []ipfw.TargetMatch[net4, net6]{negated},
					destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				}
			},
		},
		{
			name:  "keywords and a table keep their name",
			input: "add allow ip from { me or me6 or table(t) } to any established\n",
			tokens: func(*testing.T) ruleTokens {
				return ruleTokens{
					ipProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
					sources: []ipfw.TargetMatch[net4, net6]{
						{Kind: ipfw.TargetMe},
						{Kind: ipfw.TargetMe6},
						{Kind: ipfw.TargetTable, Name: "t"},
					},
					destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
					options:      []ipfw.Opt{{Kind: ipfw.OptEstablished}},
				}
			},
		},
		{
			name:  "hostname is kept without a resolver",
			input: "add allow ip from host.example.com to any\n",
			tokens: func(*testing.T) ruleTokens {
				return ruleTokens{
					ipProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
					sources:      []ipfw.TargetMatch[net4, net6]{{Kind: ipfw.TargetHostname, Name: "host.example.com"}},
					destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := newRuleState(nil)
			rec, err := ipfw.NewParser(tc.input).Next(state)
			require.Nil(t, err)
			require.Equal(t, ipfw.RecordInstruction, rec.Kind)
			require.Equal(t, tc.tokens(t), tokensOf(state))
		})
	}
}

// verifies that network text the consumer's parser rejects and targets of
// no known shape fail the line at the token.
func Test_RuleState_Errors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "invalid IPv4 network",
			input: "add allow ip from 300.1.1.1 to any\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedIPv4Network,
				Line:   1,
				Column: 18,
				Text:   "add allow ip from 300.1.1.1 to any",
			},
		},
		{
			name:  "invalid IPv6 network",
			input: "add allow ip from any to 2001:db8:::1\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedIPv6Network,
				Line:   1,
				Column: 25,
				Text:   "add allow ip from any to 2001:db8:::1",
			},
		},
		{
			name:  "custom target without a handler",
			input: "add allow ip from 2a02::g to any\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 18,
				Text:   "add allow ip from 2a02::g to any",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := newRuleState(nil)
			_, err := ipfw.NewParser(tc.input).Next(state)
			require.NotNil(t, err)
			require.Equal(t, tc.expected, *err)
		})
	}
}

// verifies that Reset empties the slices and keeps their capacity.
func Test_RuleState_Reset(t *testing.T) {
	state := newRuleState(nil)
	_, err := ipfw.NewParser("add allow tcp from { 192.0.2.0/24 or ::1 } 22 to any 80 established\n").Next(state)
	require.Nil(t, err)
	capacity := cap(state.Sources)
	require.Positive(t, capacity)
	state.Reset()
	tokens := tokensOf(state)
	require.Empty(t, tokens.ipProtos)
	require.Empty(t, tokens.protos)
	require.Empty(t, tokens.sources)
	require.Empty(t, tokens.destinations)
	require.Empty(t, tokens.sourcePorts)
	require.Empty(t, tokens.destinationPorts)
	require.Empty(t, tokens.options)
	require.Equal(t, capacity, cap(state.Sources))
}

// verifies that a line with networks of both families parses into a
// warmed-up typed state without allocating.
func Test_RuleState_NoAllocs(t *testing.T) {
	src := "add allow tcp from { 192.0.2.0/24 or 2001:db8::/32 } to 198.51.100.0/24 22\n"
	parser := ipfw.NewParser(src)
	state := newRuleState(nil)
	_, _ = parser.Next(state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		if _, err := parser.Next(state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

// customTargets is a custom target handler for the extra syntax.
//
// It maps `_NAME_` to the table `NAME`, `inet` to the table `inet` and
// `local` to a parsed network.
func customTargets(target ipfw.Target) (ipfw.TargetMatch[net4, net6], error) {
	match := ipfw.TargetMatch[net4, net6]{Neg: target.Neg}
	switch text := target.Text; {
	case text == "inet":
		match.Kind, match.Name = ipfw.TargetTable, "inet"
	case len(text) > 2 && text[0] == '_' && text[len(text)-1] == '_':
		match.Kind, match.Name = ipfw.TargetTable, text[1:len(text)-1]
	case text == "local":
		network, err := xnetip.ParseNetwork4("192.0.2.0/24")
		if err != nil {
			return ipfw.TargetMatch[net4, net6]{}, err
		}
		match.Kind, match.Net4 = ipfw.TargetNetwork4, network
	default:
		return ipfw.TargetMatch[net4, net6]{}, ipfw.ErrExpectedTarget
	}
	return match, nil
}

// verifies that a custom target handler turns targets of no known shape
// into typed ones and that what it rejects fails the line at the token.
//
// The negation is the handler's to copy.
func Test_RuleState_CustomTarget(t *testing.T) {
	state := newRuleState(customTargets)
	_, err := ipfw.NewParser("add allow ip from not _X_ to inet\n").Next(state)
	require.Nil(t, err)
	require.Equal(t, ruleTokens{
		ipProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		sources:  []ipfw.TargetMatch[net4, net6]{{Neg: true, Kind: ipfw.TargetTable, Name: "X"}},
		destinations: []ipfw.TargetMatch[net4, net6]{
			{Kind: ipfw.TargetTable, Name: "inet"},
		},
	}, tokensOf(state))

	state = newRuleState(customTargets)
	_, err = ipfw.NewParser("add allow ip from local to any\n").Next(state)
	require.Nil(t, err)
	require.Equal(t, ruleTokens{
		ipProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		sources:      []ipfw.TargetMatch[net4, net6]{network4(t, "192.0.2.0/24")},
		destinations: []ipfw.TargetMatch[net4, net6]{anyTarget},
	}, tokensOf(state))

	state = newRuleState(customTargets)
	_, err = ipfw.NewParser("add allow ip from bogus to any\n").Next(state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedTarget,
		Line:   1,
		Column: 18,
		Text:   "add allow ip from bogus to any",
	}, *err)
}

// verifies that a line with custom targets parses into a warmed-up typed
// state without allocating.
func Test_RuleState_Custom_NoAllocs(t *testing.T) {
	src := "add allow ip from { _X_ or inet } to local\n"
	parser := ipfw.NewParser(src)
	state := newRuleState(customTargets)
	_, _ = parser.Next(state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		if _, err := parser.Next(state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
