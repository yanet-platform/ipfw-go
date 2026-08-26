package ipfw

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
	// Number is the target rule number.
	Number uint32
}

// The keyword-only actions in the order they are tried, the most frequent
// spellings first.
var actionKeywords = [...]struct {
	keyword string
	kind    ActionKind
}{
	{"allow", ActionPass},
	{"pass", ActionPass},
	{"accept", ActionPass},
	{"permit", ActionPass},
	{"deny", ActionDeny},
	{"drop", ActionDeny},
	{"count", ActionCount},
}

// parseAction recognizes the action keyword by prefix.
func parseAction(s string) (Action, string, fail) {
	for _, entry := range actionKeywords {
		if rest, ok := prefix(s, entry.keyword); ok {
			return Action{Kind: entry.kind}, rest, fail{}
		}
	}
	return Action{}, s, fail{Kind: ErrExpectedAction, At: s}
}
