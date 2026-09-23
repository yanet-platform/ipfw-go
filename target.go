package ipfw

import "strings"

// TargetKind classifies a source or destination token by its shape.
type TargetKind uint8

// The target kinds. The parser classifies by shape and never validates a
// network.
//
// A token of no known shape is TargetCustom, its raw text left for the
// state to interpret or reject.
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

// Target is one member of a source or destination of the rule body.
type Target struct {
	// Neg is the `not` prefix, shared by the members of an address list.
	Neg bool
	// Pattern is the index, from zero, of the match pattern the target
	// belongs to: the alternatives of a `{ a or b }` group count up, the
	// members of an address list share one.
	Pattern uint16
	// Kind is the shape the token was classified as.
	Kind TargetKind
	// Text is the network text, the hostname, what the parentheses of a table
	// lookup hold or the raw custom token, and empty for any, me and me6.
	//
	// A table lookup is its name, followed by a comma and the value when it
	// asks for one, as in `table(NAME,VALUE)`. The value shares the text as it
	// shares the token: a fifth field would keep the target out of the
	// registers of every function it passes through.
	Text string
}

// ParseSourceTargets parses the source part of a rule body into state.
//
// It returns the number of bytes consumed, or on failure its offset together
// with the error, an ErrorKind unless the state returned something else.
// Callback effects are provisional until it succeeds. A failure does not roll
// them back, so callers must discard or reset them after an error.
func ParseSourceTargets(s string, state State) (int, error) {
	rest, err := parseTargets(s, state, sourceSide)
	return consumed(s, rest, err)
}

// ParseDestinationTargets is ParseSourceTargets for the destination part with
// the same callback lifecycle.
func ParseDestinationTargets(s string, state State) (int, error) {
	rest, err := parseTargets(s, state, destinationSide)
	return consumed(s, rest, err)
}

// parseTargets parses one target, an address list or a `{ a or b … }` group
// into the source or the destination side of the state, the alternatives of
// the group numbered from zero.
func parseTargets(s string, state State, side bodySide) (string, fail) {
	g, rest := openGroup(s, headerPosition)
	for pattern := uint16(0); ; pattern++ {
		afterElement, err := parseTargetElement(rest, state, side, pattern)
		if err.Failed() {
			return s, err
		}
		var more bool
		rest, more, err = g.Next(afterElement)
		if err.Failed() {
			return s, err
		}
		if !more {
			return rest, fail{}
		}
	}
}

// parseTargetElement parses one optionally negated target or address list as
// the pattern, a failure pointing at the member after the negation or comma.
func parseTargetElement(
	s string,
	state State,
	side bodySide,
	pattern uint16,
) (string, fail) {
	rest, neg := targetNot(s)
	token, afterTarget := scanTargetToken(rest)
	if hasPrefix(afterTarget, ",") && hasPrefix(token, "table(") {
		token, afterTarget = scanTableToken(rest, token, afterTarget)
	}
	target, kind, errorOffset := classifyTarget(token)
	if kind != 0 {
		return s, fail{Kind: kind, At: rest[errorOffset:]}
	}
	family := target.Kind
	target.Neg, target.Pattern = neg, pattern
	if err := failFrom(emitTarget(state, side, target), rest); err.Failed() {
		return s, err
	}
	if !isAddressListTarget(target) {
		return afterTarget, fail{}
	}
	for {
		afterComma, ok := prefix(afterTarget, ",")
		if !ok {
			return afterTarget, fail{}
		}
		rest = skipCommaSpace(afterComma)
		if listEnded(rest) {
			return rest, fail{}
		}
		token, afterTarget = scanTargetToken(rest)
		target, kind, errorOffset = classifyTarget(token)
		if kind != 0 || !isAddressListTarget(target) {
			return s, fail{Kind: ErrExpectedTarget, At: rest[errorOffset:]}
		}
		if family == TargetNetwork4 && target.Kind == TargetNetwork6 ||
			family == TargetNetwork6 && target.Kind == TargetNetwork4 {
			return s, fail{Kind: ErrExpectedTarget, At: rest}
		}
		target.Neg, target.Pattern = neg, pattern
		if err := failFrom(emitTarget(state, side, target), rest); err.Failed() {
			return s, err
		}
	}
}

// A `not` ending a target alternative starts negation even without an operand,
// so a dangling operator fails instead of becoming a custom target.
func targetNot(s string) (string, bool) {
	rest, ok := notPrefix(s)
	if !ok || rest != "" && rest[0] != '}' && !isASCIISpace(rest[0]) {
		return s, false
	}
	if afterSpace, ok := ws1(rest); ok {
		return afterSpace, true
	}
	return rest, true
}

// isAddressListTarget reports whether the target can be an address-list member.
//
// An unclosed `table(` token cut at its comma stays one custom token, so it
// fails at the comma instead of turning into a list.
func isAddressListTarget(target Target) bool {
	switch target.Kind {
	case TargetHostname, TargetNetwork4, TargetNetwork6:
		return true
	case TargetCustom:
		return !hasPrefix(target.Text, "table(")
	default:
		return false
	}
}

// emitTarget hands the target to the callback of its side.
func emitTarget(state State, side bodySide, target Target) error {
	switch side {
	case sourceSide:
		return state.OnSourceTarget(target)
	case destinationSide:
		return state.OnDestinationTarget(target)
	}
	return nil
}

func scanTargetToken(s string) (string, string) {
	return takeWhile(s, isTargetByte)
}

// scanTableToken rescans a `table(` token cut at a comma as the whole table
// lookup, the comma being the one before its value, and leaves the token and
// the rest as cut when no closing parenthesis follows the value.
func scanTableToken(s, token, rest string) (string, string) {
	_, afterValue := takeWhile(rest, isTableValueByte)
	if !hasPrefix(afterValue, ")") {
		return token, rest
	}
	_, afterValue = takeWhile(afterValue, isTargetByte)
	return s[:len(s)-len(afterValue)], afterValue
}

func isTargetByte(c byte) bool {
	return !isASCIISpace(c) && c != '}' && c != ','
}

// classifyTarget tells the kind of a target from its shape without parsing it.
// Failures include their byte offset within the token.
func classifyTarget(token string) (Target, ErrorKind, int) {
	if token == "" {
		return Target{}, ErrExpectedTarget, 0
	}
	if token[0] == '{' {
		return Target{}, ErrExpectedTarget, 0
	}
	switch token {
	case "not":
		return Target{}, ErrExpectedTarget, 0
	case "any":
		return Target{Kind: TargetAny}, 0, 0
	case "me6":
		return Target{Kind: TargetMe6}, 0, 0
	case "me":
		return Target{Kind: TargetMe}, 0, 0
	}
	if hasPrefix(token, "table(") {
		if target, kind, errorOffset, ok := classifyTable(token); ok {
			return target, kind, errorOffset
		}
	}
	if isNetwork6Text(token) {
		return Target{Kind: TargetNetwork6, Text: token}, 0, 0
	}
	if isNetwork4Text(token) {
		return Target{Kind: TargetNetwork4, Text: token}, 0, 0
	}
	if token[0] == '`' {
		target, kind := classifyQuotedHostname(token)
		return target, kind, 0
	}
	if isHostnameText(token) {
		return Target{Kind: TargetHostname, Text: token}, 0, 0
	}
	return Target{Kind: TargetCustom, Text: token}, 0, 0
}

// classifyTable tells a closed table lookup, false for a token that is not
// one.
//
// It is a function of its own to keep the classification of every other
// target as small as it was.
func classifyTable(token string) (Target, ErrorKind, int, bool) {
	inside, end, ok := tableName(token)
	if !ok {
		return Target{}, 0, 0, false
	}
	name, value, hasValue := strings.Cut(inside, ",")
	if name == "" {
		return Target{}, ErrExpectedTableName, 0, true
	}
	if hasValue && value == "" {
		return Target{}, ErrExpectedTableValue, end - 1, true
	}
	if end != len(token) {
		return Target{}, ErrExpectedTarget, end, true
	}
	return Target{Kind: TargetTable, Text: inside}, 0, 0, true
}

// tableName returns what the parentheses of a table lookup hold, the name
// with the value after a comma, and the end of the lookup.
//
// An empty name is included, while an unclosed token is not a table reference.
func tableName(token string) (string, int, bool) {
	inside, ok := prefix(token, "table(")
	if !ok {
		return "", 0, false
	}
	closing := strings.IndexByte(inside, ')')
	if closing < 0 {
		return "", 0, false
	}
	return inside[:closing], len("table(") + closing + 1, true
}

// classifyQuotedHostname strips the backtick and the closing quote of a
// “ `name' “ token, the name inside having to be a hostname.
//
// Unlike a plain token of the wrong shape, a quoted one cannot be anything
// else, so it is an error rather than a fallthrough.
func classifyQuotedHostname(token string) (Target, ErrorKind) {
	if len(token) < 2 || token[len(token)-1] != '\'' {
		return Target{}, ErrExpectedHostnameEscapeClose
	}
	name := token[1 : len(token)-1]
	if !isHostnameText(name) {
		return Target{}, ErrExpectedHostname
	}
	return Target{Kind: TargetHostname, Text: name}, 0
}

// isNetwork6Text reports whether the token is made of hex digits, colons,
// dots and slashes with at least one colon, the shape of IPv6 network text.
//
// The colon tells it from IPv4 text, so it is checked first: an IPv4-mapped
// address such as `::ffff:192.0.2.1` has both shapes.
func isNetwork6Text(token string) bool {
	if strings.IndexByte(token, ':') < 0 {
		return false
	}
	_, rest := takeWhile(token, isNetwork6Byte)
	return rest == ""
}

func isNetwork6Byte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' ||
		c == ':' || c == '.' || c == '/'
}

// isNetwork4Text reports whether the token is made of digits, dots and
// slashes only, the shape of an IPv4 address or network whatever the values.
func isNetwork4Text(token string) bool {
	_, rest := takeWhile(token, isNetwork4Byte)
	return token != "" && rest == ""
}

func isNetwork4Byte(c byte) bool {
	return c >= '0' && c <= '9' || c == '.' || c == '/'
}

// isHostnameText reports whether the token is letters, digits, dots, dashes
// and underscores with at least one dot and one letter.
//
// The letter tells a hostname from IPv4 text and the dot from a keyword,
// both checked before.
func isHostnameText(token string) bool {
	hasDot, hasLetter := false, false
	for idx := range len(token) {
		switch c := token[idx]; {
		case c == '.':
			hasDot = true
		case isASCIILetter(c):
			hasLetter = true
		case c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return hasDot && hasLetter
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
