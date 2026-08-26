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

// verifies that both spellings of the deny action are recognized by prefix
// and print as deny.
func Test_ParseAction_Deny(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		action Action
		kind   ErrorKind
		rest   string
	}{
		{name: "deny", input: "deny ip from any to any", action: Action{Kind: ActionDeny}, rest: " ip from any to any"},
		{name: "drop", input: "drop ip", action: Action{Kind: ActionDeny}, rest: " ip"},
		{name: "prefix match leaves the tail", input: "denyall ip", action: Action{Kind: ActionDeny}, rest: "all ip"},
		{name: "denied is not deny", input: "denied ip", kind: ErrExpectedAction, rest: "denied ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, rest, err := parseAction(tc.input)
			require.Equal(t, tc.kind, err.Kind)
			require.Equal(t, tc.action, action)
			require.Equal(t, tc.rest, rest)
		})
	}
	require.Equal(t, "deny", Action{Kind: ActionDeny}.String())
}

// verifies that the count action is recognized and prints as count.
func Test_ParseAction_Count(t *testing.T) {
	action, rest, err := parseAction("count ip from any to any")
	require.Equal(t, ErrorKind(0), err.Kind)
	require.Equal(t, Action{Kind: ActionCount}, action)
	require.Equal(t, " ip from any to any", rest)
	require.Equal(t, "count", Action{Kind: ActionCount}.String())
}
