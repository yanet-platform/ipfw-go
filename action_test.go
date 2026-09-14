package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw-go"
)

// verifies that an action prints the way it is written in a ruleset.
func Test_Action_String(t *testing.T) {
	cases := []struct {
		name   string
		action ipfw.Action
		text   string
	}{
		{name: "pass", action: ipfw.Action{Kind: ipfw.ActionPass}, text: "pass"},
		{name: "deny", action: ipfw.Action{Kind: ipfw.ActionDeny}, text: "deny"},
		{name: "count", action: ipfw.Action{Kind: ipfw.ActionCount}, text: "count"},
		{
			name: "skipto label",
			action: ipfw.Action{
				Kind:   ipfw.ActionSkipTo,
				SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "ADMIN_RULES"},
			},
			text: "skipto :ADMIN_RULES",
		},
		{
			name: "skipto number",
			action: ipfw.Action{
				Kind:   ipfw.ActionSkipTo,
				SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 100},
			},
			text: "skipto 100",
		},
		{
			name: "skipto tablearg",
			action: ipfw.Action{
				Kind:   ipfw.ActionSkipTo,
				SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToTableArg},
			},
			text: "skipto tablearg",
		},
		{
			name:   "check-state",
			action: ipfw.Action{Kind: ipfw.ActionCheckState},
			text:   "check-state",
		},
		{
			name:   "check-state with flow",
			action: ipfw.Action{Kind: ipfw.ActionCheckState, Flow: "any"},
			text:   "check-state :any",
		},
		{name: "zero value", action: ipfw.Action{}, text: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.text, tc.action.String())
		})
	}
}

// verifies that a skipto target prints the way it is written after skipto.
func Test_SkipTo_String(t *testing.T) {
	require.Equal(
		t,
		":ADMIN_RULES",
		ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "ADMIN_RULES"}.String(),
	)
	require.Equal(t, "100", ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 100}.String())
	require.Equal(t, "tablearg", ipfw.SkipTo{Kind: ipfw.SkipToTableArg}.String())
	require.Empty(t, ipfw.SkipTo{}.String())
}
