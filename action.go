package ipfw

import "strconv"

// ActionKind is what a rule does with a matching packet.
type ActionKind uint8

// The actions.
//
// Pass and deny terminate the search, count only bumps the rule counters and
// continues with the next rule, skipto jumps, check-state consults the
// dynamic state.
const (
	_ ActionKind = iota
	ActionPass
	ActionDeny
	ActionCount
	ActionSkipTo
	ActionCheckState
)

// Action is the rule action with its argument.
type Action struct {
	// Kind is the action.
	Kind ActionKind
	// SkipTo is the target of a skipto action.
	SkipTo SkipTo
	// Flow is the `check-state :flow` name, empty when absent.
	Flow string
}

// String returns the canonical keyword of the action, empty for a kind
// without one.
func (m Action) String() string {
	switch m.Kind {
	case ActionPass:
		return "pass"
	case ActionDeny:
		return "deny"
	case ActionCount:
		return "count"
	case ActionSkipTo:
		return "skipto " + m.SkipTo.String()
	case ActionCheckState:
		if m.Flow == "" {
			return "check-state"
		}
		return "check-state :" + m.Flow
	default:
		return ""
	}
}

// SkipToKind is how a skipto names its target.
type SkipToKind uint8

// The skipto target kinds.
const (
	_ SkipToKind = iota
	SkipToLabel
	SkipToNumber
	SkipToTableArg
)

// SkipTo is the target of a skipto action.
type SkipTo struct {
	// Kind is how the target is named.
	Kind SkipToKind
	// Label is the target label without the colon.
	Label string
	// Number is the target rule number, a jump landing on the rule numbered
	// exactly so.
	Number uint32
}

// String returns the target the way it is written after skipto, empty for
// a kind without one.
func (m SkipTo) String() string {
	switch m.Kind {
	case SkipToLabel:
		return ":" + m.Label
	case SkipToNumber:
		return strconv.FormatUint(uint64(m.Number), 10)
	case SkipToTableArg:
		return "tablearg"
	default:
		return ""
	}
}

// parseFlowName reads the optional ` :flow` of check-state, reporting
// whether it was there.
func parseFlowName(s string) (string, string, bool) {
	rest, ok := ws1(s)
	if !ok {
		return "", s, false
	}
	rest, ok = prefix(rest, ":")
	if !ok {
		return "", s, false
	}
	flow, rest := token(rest)
	if flow == "" {
		return "", s, false
	}
	return flow, rest, true
}
