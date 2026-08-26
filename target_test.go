package ipfw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// verifies that a target token runs up to whitespace, a closing brace or a
// comma.
func Test_ScanTargetToken_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		token string
		rest  string
	}{
		{name: "stops at space", input: "any to any", token: "any", rest: " to any"},
		{name: "stops at closing brace", input: "any}", token: "any", rest: "}"},
		{name: "stops at comma", input: "a,b", token: "a", rest: ",b"},
		{name: "stops at newline", input: "any\n", token: "any", rest: "\n"},
		{name: "whole input", input: "10.0.0.0/8", token: "10.0.0.0/8", rest: ""},
		{name: "empty input", input: "", token: "", rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, rest := scanTargetToken(tc.input)
			require.Equal(t, tc.token, token)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that only the exact `any` keyword is a target for now.
func Test_ClassifyTarget_Any(t *testing.T) {
	target, kind := classifyTarget("any")
	require.Equal(t, ErrorKind(0), kind)
	require.Equal(t, Target{Kind: TargetAny}, target)

	for _, token := range []string{"", "anything", "ANY"} {
		_, kind := classifyTarget(token)
		require.Equal(t, ErrExpectedTarget, kind, token)
	}
}

// verifies that the exported target parsers feed the right side of the
// state, report the consumed length, and position a failure at the token.
func Test_ParseTargets_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		n     int
		err   error
		state CollectState
	}{
		{name: "any", input: "any to", n: 3, state: CollectState{Sources: []Target{{Kind: TargetAny}}}},
		{name: "negated any", input: "not any x", n: 7, state: CollectState{Sources: []Target{{Neg: true, Kind: TargetAny}}}},
		{name: "braced single", input: "{ any } x", n: 7, state: CollectState{Sources: []Target{{Kind: TargetAny}}}},
		{name: "empty input", input: "", n: 0, err: ErrExpectedTarget},
		{name: "unknown target", input: "anything to", n: 0, err: ErrExpectedTarget},
		{name: "unknown negated target", input: "not foo", n: 4, err: ErrExpectedTarget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state CollectState
			n, err := ParseSourceTargets(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, tc.state, state)

			state = CollectState{}
			n, err = ParseDestinationTargets(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, CollectState{Destinations: tc.state.Sources}, state)
		})
	}
}

// verifies that an error from the state comes back as is, positioned at
// the rejected token.
func Test_ParseTargets_StateError(t *testing.T) {
	state := rejectingState{err: ErrUnknownOption}
	n, err := ParseSourceTargets("not any x", state)
	require.Equal(t, 4, n)
	require.Equal(t, ErrUnknownOption, err)
	n, err = ParseDestinationTargets("any x", state)
	require.Equal(t, 0, n)
	require.Equal(t, ErrUnknownOption, err)
}
