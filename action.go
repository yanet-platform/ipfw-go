package ipfw

// ActionKind is what a rule does with a matching packet.
type ActionKind uint8

// The actions. Pass and deny terminate the search, count continues it,
// skipto jumps, check-state consults the dynamic state.
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
