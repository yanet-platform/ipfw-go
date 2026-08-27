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
	rest, err := parseTargets(s, state, sourceSide)
	return consumed(s, rest, err)
}

// ParseDestinationTargets is ParseSourceTargets for the destination part.
func ParseDestinationTargets(s string, state State) (int, error) {
	rest, err := parseTargets(s, state, destinationSide)
	return consumed(s, rest, err)
}

// parseTargets parses one target or a `{ a or b … }` group of them into the
// source or the destination side of the state.
func parseTargets(s string, state State, side bodySide) (string, fail) {
	g, rest := openGroup(s)
	for {
		afterElement, err := parseTargetElement(rest, state, side)
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

// parseTargetElement parses one optionally negated target, a failure
// pointing at the token after the negation.
func parseTargetElement(s string, state State, side bodySide) (string, fail) {
	rest, neg := notWS1(s)
	token, afterToken := scanTargetToken(rest)
	target, kind := classifyTarget(token)
	if kind != 0 {
		return s, fail{Kind: kind, At: rest}
	}
	target.Neg = neg
	if err := failFrom(emitTarget(state, side, target), rest); err.Failed() {
		return s, err
	}
	return afterToken, fail{}
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

func isTargetByte(c byte) bool {
	return !isASCIISpace(c) && c != '}' && c != ','
}

// classifyTarget tells the kind of a target from its shape without parsing
// it, an empty token being the only error.
func classifyTarget(token string) (Target, ErrorKind) {
	if token == "" {
		return Target{}, ErrExpectedTarget
	}
	switch token {
	case "any":
		return Target{Kind: TargetAny}, 0
	case "me6":
		return Target{Kind: TargetMe6}, 0
	case "me":
		return Target{Kind: TargetMe}, 0
	}
	if name, ok := tableName(token); ok {
		return Target{Kind: TargetTable, Text: name}, 0
	}
	if isNetwork6Text(token) {
		return Target{Kind: TargetNetwork6, Text: token}, 0
	}
	if isNetwork4Text(token) {
		return Target{Kind: TargetNetwork4, Text: token}, 0
	}
	if token[0] == '`' {
		return classifyQuotedHostname(token)
	}
	if isHostnameText(token) {
		return Target{Kind: TargetHostname, Text: token}, 0
	}
	return Target{Kind: TargetCustom, Text: token}, 0
}

// tableName returns the name inside a `table(NAME)` token, an empty name
// included, and false for any other token.
func tableName(token string) (string, bool) {
	inside, ok := prefix(token, "table(")
	if !ok || !strings.HasSuffix(inside, ")") {
		return "", false
	}
	return inside[:len(inside)-1], true
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
	_, rest := takeWhile(token, isNetwork6Byte)
	return rest == "" && strings.IndexByte(token, ':') >= 0
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
