package ipfw

// TargetKind classifies a source or destination token by its shape.
type TargetKind uint8

// The target kinds. The parser classifies by shape and never validates a
// network, and anything of an unknown shape is TargetCustom.
const (
	_ TargetKind = iota
	TargetAny
	TargetMe
	TargetMe6
	TargetHostname
	TargetTable
	TargetNetwork4
	TargetNetwork6
	TargetCustom
)

// Target is a source or destination of the rule body, negated by `not`.
type Target struct {
	// Neg is the `not` prefix.
	Neg bool
	// Kind is the shape the token was classified as.
	Kind TargetKind
	// Text is the network text, the hostname, the table name or the raw
	// custom token, and empty for any, me and me6.
	Text string
}

// ParseSourceTargets parses the source part of a rule body into state.
//
// It returns the number of bytes consumed, or on failure its offset together
// with the error, an ErrorKind unless the state returned something else.
func ParseSourceTargets(s string, state State) (int, error) {
	rest, err := parseTargets(s, state, false)
	return consumed(s, rest, err)
}

// ParseDestinationTargets is ParseSourceTargets for the destination part.
func ParseDestinationTargets(s string, state State) (int, error) {
	rest, err := parseTargets(s, state, true)
	return consumed(s, rest, err)
}

// parseTargets parses one target or a `{ a or b … }` group of them into the
// source or the destination side of the state.
func parseTargets(s string, state State, destination bool) (string, fail) {
	g, rest := openGroup(s)
	for {
		afterElement, err := parseTargetElement(rest, state, destination)
		if err.Failed() {
			return s, err
		}
		var more bool
		rest, more, err = g.next(afterElement)
		if err.Failed() {
			return s, err
		}
		if !more {
			return rest, fail{}
		}
	}
}

// parseTargetElement parses one optionally negated target, a failure
// pointing at the token after the negation.
func parseTargetElement(s string, state State, destination bool) (string, fail) {
	rest, neg := notWS1(s)
	token, afterToken := scanTargetToken(rest)
	target, kind := classifyTarget(token)
	if kind != 0 {
		return s, fail{Kind: kind, At: rest}
	}
	target.Neg = neg
	var err error
	if destination {
		err = state.DestinationTarget(target)
	} else {
		err = state.SourceTarget(target)
	}
	if failure := failFrom(err, rest); failure.Failed() {
		return s, failure
	}
	return afterToken, fail{}
}

func scanTargetToken(s string) (string, string) {
	return takeWhile(s, isTargetByte)
}

func isTargetByte(c byte) bool {
	return !isASCIISpace(c) && c != '}' && c != ','
}

// classifyTarget tells the kind of a target from its shape without parsing
// it, a kind per step until every shape is known.
func classifyTarget(token string) (Target, ErrorKind) {
	switch token {
	case "any":
		return Target{Kind: TargetAny}, 0
	default:
		return Target{}, ErrExpectedTarget
	}
}
