package ipfw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// verifies that every alias of the pass action is recognized by prefix and
// that anything else is rejected with the input untouched.
func Test_ParseAction_Pass(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		action Action
		kind   ErrorKind
		rest   string
	}{
		{name: "allow", input: "allow ip from any to any", action: Action{Kind: ActionPass}, rest: " ip from any to any"},
		{name: "pass", input: "pass ip from any to any", action: Action{Kind: ActionPass}, rest: " ip from any to any"},
		{name: "accept", input: "accept ip", action: Action{Kind: ActionPass}, rest: " ip"},
		{name: "permit", input: "permit ip", action: Action{Kind: ActionPass}, rest: " ip"},
		{name: "prefix match leaves the tail", input: "passthru x", action: Action{Kind: ActionPass}, rest: "thru x"},
		{name: "truncated keyword", input: "pas ip", kind: ErrExpectedAction, rest: "pas ip"},
		{name: "unknown keyword", input: "x", kind: ErrExpectedAction, rest: "x"},
		{name: "empty input", input: "", kind: ErrExpectedAction, rest: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, rest, err := parseAction(tc.input)
			require.Equal(t, tc.kind, err.Kind)
			if tc.kind != 0 {
				require.Equal(t, tc.input, err.At)
			}
			require.Equal(t, tc.action, action)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that the pass action prints its canonical keyword.
func Test_Action_String_Pass(t *testing.T) {
	require.Equal(t, "pass", Action{Kind: ActionPass}.String())
}
