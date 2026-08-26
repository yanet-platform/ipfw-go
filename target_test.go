package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// verifies that the target parsers feed the right side of the state,
// report the consumed length, and position a failure at the token.
//
// A token runs up to whitespace, a closing brace or a comma. The keywords
// `any`, `me` and `me6`, IPv4 and IPv6 network text, hostnames and
// `table(NAME)` are the shapes known so far.
func Test_ParseTargets_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		n     int
		err   error
		state ipfw.CollectState
	}{
		{name: "any", input: "any to", n: 3, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "any at end of input", input: "any", n: 3, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "any before a newline", input: "any\n", n: 3, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "any before a closing brace", input: "any}", n: 3, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "any before a comma", input: "any,x", n: 3, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "negated any", input: "not any x", n: 7, state: ipfw.CollectState{Sources: []ipfw.Target{{Neg: true, Kind: ipfw.TargetAny}}}},
		{
			name:  "me",
			input: "me to any",
			n:     2,
			state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetMe}}},
		},
		{
			name:  "me6",
			input: "me6 to any",
			n:     3,
			state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetMe6}}},
		},
		{
			name:  "negated me6",
			input: "not me6 x",
			n:     7,
			state: ipfw.CollectState{Sources: []ipfw.Target{{Neg: true, Kind: ipfw.TargetMe6}}},
		},
		{name: "me with a suffix", input: "mex to any", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "me6 with a suffix", input: "me6x to any", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "me is case-sensitive", input: "ME to any", n: 0, err: ipfw.ErrExpectedTarget},
		{
			name:  "IPv4 address",
			input: "192.0.2.1 to any",
			n:     9,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"}},
			},
		},
		{
			name:  "IPv4 network in CIDR notation",
			input: "192.0.2.0/24 to any",
			n:     12,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"}},
			},
		},
		{
			name:  "IPv4 network with an explicit mask",
			input: "192.0.2.0/255.255.255.0 to any",
			n:     23,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/255.255.255.0"}},
			},
		},
		{
			name:  "IPv4 text is not validated",
			input: "300.1.1.1 to any",
			n:     9,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "300.1.1.1"}},
			},
		},
		{
			name:  "digits alone are IPv4 text",
			input: "42 to any",
			n:     2,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "42"}},
			},
		},
		{
			name:  "negated IPv4 network",
			input: "not 192.0.2.0/24 x",
			n:     16,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Neg: true, Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"}},
			},
		},
		{
			name:  "IPv4 address stops at a comma",
			input: "192.0.2.1,203.0.113.1 to any",
			n:     9,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"}},
			},
		},
		{
			name:  "IPv4 network with a suffix",
			input: "192.0.2.0/24abc to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{
			name:  "IPv6 address",
			input: "2001:db8:c00::1 to any",
			n:     15,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:db8:c00::1"}},
			},
		},
		{
			name:  "IPv6 network in CIDR notation",
			input: "2001:db8:c00::/40 to any",
			n:     17,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:db8:c00::/40"}},
			},
		},
		{
			name:  "IPv6 network with an explicit mask",
			input: "2001:db8:c00::f800:0:0/ffff:ffff:ff00:0:ffff:f800:: to any",
			n:     51,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{
					Kind: ipfw.TargetNetwork6,
					Text: "2001:db8:c00::f800:0:0/ffff:ffff:ff00:0:ffff:f800::",
				}},
			},
		},
		{
			name:  "IPv6 loopback",
			input: "::1 to any",
			n:     3,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "::1"}},
			},
		},
		{
			name:  "IPv4-mapped IPv6 address",
			input: "::ffff:192.0.2.1 to any",
			n:     16,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "::ffff:192.0.2.1"}},
			},
		},
		{
			name:  "uppercase hex digits",
			input: "2001:DB8::1 to any",
			n:     11,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:DB8::1"}},
			},
		},
		{
			name:  "IPv6 text is not validated",
			input: "2001:db8:::1 to any",
			n:     12,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:db8:::1"}},
			},
		},
		{
			name:  "negated IPv6 network",
			input: "not 2001:db8::/32 x",
			n:     17,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Neg: true, Kind: ipfw.TargetNetwork6, Text: "2001:db8::/32"}},
			},
		},
		{
			name:  "IPv6 address with a suffix",
			input: "::1zz to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{
			name:  "at sign is not IPv6 text",
			input: "2001:db8::1@2 to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{
			name:  "hostname",
			input: "host.example.com to any",
			n:     16,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "host.example.com"}},
			},
		},
		{
			name:  "hostname starting with a keyword",
			input: "any.example.com to any",
			n:     15,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "any.example.com"}},
			},
		},
		{
			name:  "hostname with a dash and an underscore",
			input: "foo-bar_1.example.com to any",
			n:     21,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "foo-bar_1.example.com"}},
			},
		},
		{
			name:  "digits with a letter suffix are a hostname",
			input: "192.0.2.1abc to any",
			n:     12,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "192.0.2.1abc"}},
			},
		},
		{
			name:  "negated hostname",
			input: "not host.example.com x",
			n:     20,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Neg: true, Kind: ipfw.TargetHostname, Text: "host.example.com"}},
			},
		},
		{
			name:  "quoted hostname",
			input: "`node-1.example.net' to any",
			n:     20,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "node-1.example.net"}},
			},
		},
		{
			name:  "quoted hostname without the closing quote",
			input: "`x.y to any",
			n:     0,
			err:   ipfw.ErrExpectedHostnameEscapeClose,
		},
		{
			name:  "quoted hostname of the wrong shape",
			input: "`123' to any",
			n:     0,
			err:   ipfw.ErrExpectedHostname,
		},
		{
			name:  "empty quoted hostname",
			input: "`' to any",
			n:     0,
			err:   ipfw.ErrExpectedHostname,
		},
		{
			name:  "name without a dot",
			input: "localhost to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{
			name:  "table",
			input: "table(_X_) to any",
			n:     10,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetTable, Text: "_X_"}},
			},
		},
		{
			name:  "table with an empty name",
			input: "table() to any",
			n:     7,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetTable, Text: ""}},
			},
		},
		{
			name:  "negated table",
			input: "not table(t) x",
			n:     12,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Neg: true, Kind: ipfw.TargetTable, Text: "t"}},
			},
		},
		{
			name:  "table before a closing brace",
			input: "table(t)}",
			n:     8,
			state: ipfw.CollectState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetTable, Text: "t"}},
			},
		},
		{
			name:  "table name stops at whitespace",
			input: "table(a b) to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{
			name:  "table name stops at a comma",
			input: "table(a,b) to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{
			name:  "table without the closing parenthesis",
			input: "table(t to any",
			n:     0,
			err:   ipfw.ErrExpectedTarget,
		},
		{name: "braced single", input: "{ any } x", n: 7, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "empty input", input: "", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "unknown target", input: "anything to", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "keyword is case-sensitive", input: "ANY to", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "unknown negated target", input: "not foo", n: 4, err: ipfw.ErrExpectedTarget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.CollectState
			n, err := ipfw.ParseSourceTargets(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, tc.state, state)

			state = ipfw.CollectState{}
			n, err = ipfw.ParseDestinationTargets(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, ipfw.CollectState{Destinations: tc.state.Sources}, state)
		})
	}
}

// verifies that an error from the state comes back as is, positioned at
// the rejected token.
func Test_ParseTargets_StateError(t *testing.T) {
	state := rejectingState{err: ipfw.ErrUnknownOption}
	n, err := ipfw.ParseSourceTargets("not any x", state)
	require.Equal(t, 4, n)
	require.Equal(t, ipfw.ErrUnknownOption, err)
	n, err = ipfw.ParseDestinationTargets("any x", state)
	require.Equal(t, 0, n)
	require.Equal(t, ipfw.ErrUnknownOption, err)
}

// verifies that classifying network text allocates nothing.
func Test_ParseTargets_NoAllocs(t *testing.T) {
	input := "{ 192.0.2.0/24 or not 2001:db8::/32 or `host.example.com' or table(t) } to any"
	var state ipfw.CollectState
	_, _ = ipfw.ParseSourceTargets(input, &state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		state.Reset()
		n, err := ipfw.ParseSourceTargets(input, &state)
		if err != nil || n != 71 {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
