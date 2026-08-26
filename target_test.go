package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// verifies that the target parsers feed the right side of the state,
// report the consumed length, and position a failure at the token.
//
// A token runs up to whitespace, a closing brace or a comma, and `any`, `me`
// and `me6` are the shapes known so far.
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
		{name: "braced single", input: "{ any } x", n: 7, state: ipfw.CollectState{Sources: []ipfw.Target{{Kind: ipfw.TargetAny}}}},
		{name: "empty input", input: "", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "unknown target", input: "anything to", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "keyword is case-sensitive", input: "ANY to", n: 0, err: ipfw.ErrExpectedTarget},
		{name: "network is not known yet", input: "10.0.0.0/8 to", n: 0, err: ipfw.ErrExpectedTarget},
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
