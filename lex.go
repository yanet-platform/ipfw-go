package ipfw

import "strings"

// fail is a parse failure inside a line, the zero value being success.
type fail struct {
	// Kind is what went wrong.
	Kind ErrorKind
	// At is the input left at the point of detection, from which the line
	// parser derives the column.
	At string
	// Err is the error a State or a hook returned, set with ErrState.
	Err error
}

// Failed reports whether the value describes a failure.
func (m fail) Failed() bool {
	return m.Kind != 0
}

// ToError returns the failure as the error a public function reports: the
// attached error when a State or a hook produced one, the kind otherwise.
func (m fail) ToError() error {
	if m.Err != nil {
		return m.Err
	}
	return m.Kind
}

// consumed reports a sub-parser outcome the public way: the number of bytes
// consumed, or the offset of the failure together with its error.
func consumed(s, rest string, err fail) (int, error) {
	if err.Failed() {
		return len(s) - len(err.At), err.ToError()
	}
	return len(s) - len(rest), nil
}

// failFrom turns the error a State or a hook returned into a failure at the
// rejected token.
//
// An ErrorKind keeps its kind, anything else is an ErrState carrying the
// error.
func failFrom(err error, at string) fail {
	if err == nil {
		return fail{}
	}
	if kind, ok := err.(ErrorKind); ok {
		return fail{Kind: kind, At: at}
	}
	return fail{Kind: ErrState, At: at, Err: err}
}

func isWS(c byte) bool {
	return c == ' ' || c == '\t'
}

// isASCIISpace deliberately excludes vertical tab, like the reference grammar.
func isASCIISpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	}
	return false
}

func prefix(s, p string) (string, bool) {
	if !strings.HasPrefix(s, p) {
		return s, false
	}
	return s[len(p):], true
}

func takeWhile(s string, f func(byte) bool) (string, string) {
	idx := 0
	for idx < len(s) && f(s[idx]) {
		idx++
	}
	return s[:idx], s[idx:]
}

func ws0(s string) string {
	_, rest := takeWhile(s, isWS)
	return rest
}

func ws1(s string) (string, bool) {
	taken, rest := takeWhile(s, isWS)
	return rest, taken != ""
}

func skipSpace(s string) string {
	_, rest := takeWhile(s, isASCIISpace)
	return rest
}

func token(s string) (string, string) {
	return takeWhile(s, isTokenByte)
}

func isTokenByte(c byte) bool {
	return !isASCIISpace(c)
}

// keywordWS1 consumes the keyword only when whitespace follows, so a token
// that merely starts with it is left alone.
//
// That is what tells a port named `topx` from the keyword `to` and a
// protocol named `nottcp` from the negation.
func keywordWS1(s, keyword string) (string, bool) {
	rest, ok := prefix(s, keyword)
	if !ok {
		return s, false
	}
	rest, ok = ws1(rest)
	if !ok {
		return s, false
	}
	return rest, true
}

func notWS1(s string) (string, bool) {
	return keywordWS1(s, "not")
}

// ws1Keyword consumes whitespace followed by the keyword and leaves the
// input alone when either is missing.
//
// That is the shape of an optional trailing keyword such as ` log`. The
// keyword matches by prefix.
func ws1Keyword(s, keyword string) (string, bool) {
	rest, ok := ws1(s)
	if !ok {
		return s, false
	}
	rest, ok = prefix(rest, keyword)
	if !ok {
		return s, false
	}
	return rest, true
}

// parseU8 stops at the first non-digit. A missing or overflowing number is an
// error, and the input is returned unchanged.
func parseU8(s string) (uint8, string, ErrorKind) {
	value, rest, ok := parseUint(s, 0xff)
	if !ok {
		return 0, s, ErrExpectedU8
	}
	return uint8(value), rest, 0
}

// parseU16 is parseU8 for sixteen bits.
func parseU16(s string) (uint16, string, ErrorKind) {
	value, rest, ok := parseUint(s, 0xffff)
	if !ok {
		return 0, s, ErrExpectedU16
	}
	return uint16(value), rest, 0
}

// parseU32 is parseU8 for thirty-two bits.
func parseU32(s string) (uint32, string, ErrorKind) {
	value, rest, ok := parseUint(s, 0xffffffff)
	if !ok {
		return 0, s, ErrExpectedU32
	}
	return uint32(value), rest, 0
}

// parseUint checks for overflow before folding in a digit, so the value never
// wraps. Leading zeros are accepted.
func parseUint(s string, max uint64) (uint64, string, bool) {
	var value uint64
	idx := 0
	for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
		digit := uint64(s[idx] - '0')
		if value > (max-digit)/10 {
			return 0, s, false
		}
		value = value*10 + digit
		idx++
	}
	if idx == 0 {
		return 0, s, false
	}
	return value, s[idx:], true
}

// group is the state of one `{ a or b … }` list, or of a lone element.
//
// The callers drive it with direct calls: an element parser passed as a
// function value is an indirect call the compiler cannot inline.
type group struct {
	// Braced is whether the list is in braces, `or` separating the
	// elements and `}` ending it.
	Braced bool
}

// openGroup consumes the opening brace and the spaces after it when there is
// one, and leaves a lone element untouched.
func openGroup(s string) (group, string) {
	rest, ok := prefix(s, "{")
	if !ok {
		return group{}, s
	}
	return group{Braced: true}, skipSpace(rest)
}

// Next reads what follows an element and reports whether another one comes.
//
// Inside braces `or` goes on with the next element, the spaces after it
// skipped, and `}` ends the list. Anything else is ErrExpectedOr at the
// first non-space byte, the input being returned unchanged. A lone element
// ends the list with the input untouched.
func (m group) Next(s string) (string, bool, fail) {
	if !m.Braced {
		return s, false, fail{}
	}
	rest := skipSpace(s)
	if closed, ok := prefix(rest, "}"); ok {
		return closed, false, fail{}
	}
	rest, ok := prefix(rest, "or")
	if !ok {
		return s, false, fail{Kind: ErrExpectedOr, At: rest}
	}
	return skipSpace(rest), true, fail{}
}
