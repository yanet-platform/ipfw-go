package ipfw

import "strconv"

// ErrorKind names a syntax or semantic error found while parsing a ruleset.
//
// Parsing functions report failures as an ErrorKind, the zero value meaning
// success; the public API wraps the kind into a positioned ParseError. Every
// kind is an error value on its own, so errors.Is works against a kind.
type ErrorKind uint8

// The error kinds a parser can report.
const (
	_ ErrorKind = iota

	// ErrExpectedLine is reported when a line starts with neither a command,
	// a table command, a label nor a comment.
	ErrExpectedLine
	// ErrExpectedCommand is reported when a command keyword is missing.
	ErrExpectedCommand
	// ErrExpectedFrom is reported when the protocol is not followed by the
	// `from` keyword.
	ErrExpectedFrom
	// ErrExpectedPrefix is reported when a required keyword or punctuation
	// is missing.
	ErrExpectedPrefix
	// ErrExpectedAction is reported when the rule action is missing or
	// unknown.
	ErrExpectedAction
	// ErrExpectedOr is reported when the elements of a `{ … }` group are
	// not separated by `or`.
	ErrExpectedOr
	// ErrExpectedProto is reported when a transport protocol is missing or
	// cannot be resolved.
	ErrExpectedProto
	// ErrExpectedWhitespace is reported when two tokens are not separated
	// by whitespace.
	ErrExpectedWhitespace
	// ErrExpectedIPProto is reported when an IP protocol keyword is expected.
	ErrExpectedIPProto
	// ErrExpectedEitherIPOrProto is reported when the rule body does not
	// start with a protocol.
	ErrExpectedEitherIPOrProto
	// ErrExpectedIPv4Network is reported when an IPv4 network does not parse.
	ErrExpectedIPv4Network
	// ErrExpectedIPv6Network is reported when an IPv6 network does not parse.
	ErrExpectedIPv6Network
	// ErrExpectedHostname is reported when a quoted hostname is malformed.
	ErrExpectedHostname
	// ErrExpectedPort is reported when a port is missing or a service name
	// cannot be resolved.
	ErrExpectedPort
	// ErrUnexpectedEscape is reported when a backslash in a port name
	// escapes anything but `-`.
	ErrUnexpectedEscape
	// ErrExpectedToken is reported when a non-empty token is expected.
	ErrExpectedToken
	// ErrExpectedFlowName is reported when a flow name is expected after a
	// colon.
	ErrExpectedFlowName
	// ErrUnknownOption is reported when a rule option keyword is unknown.
	ErrUnknownOption
	// ErrExpectedTarget is reported when a source or destination target is
	// missing or unsupported.
	ErrExpectedTarget
	// ErrExpectedHostnameEscapeClose is reported when a backtick-quoted
	// hostname lacks its closing quote.
	ErrExpectedHostnameEscapeClose
	// ErrExpectedTableCommand is reported when a table command is neither
	// `create` nor `add`.
	ErrExpectedTableCommand
	// ErrExpectedTableKey is reported when a table entry key is missing.
	ErrExpectedTableKey
	// ErrExpectedSkipTo is reported when a skipto target is missing or
	// malformed.
	ErrExpectedSkipTo
	// ErrExpectedU8 is reported when an 8-bit number is missing or too large.
	ErrExpectedU8
	// ErrExpectedU16 is reported when a 16-bit number is missing or too
	// large.
	ErrExpectedU16
	// ErrExpectedU32 is reported when a 32-bit number is missing or too
	// large.
	ErrExpectedU32
	// ErrUnknownICMPType is reported when an ICMP type is not a known one.
	ErrUnknownICMPType
	// ErrUnknownICMP6Type is reported when an ICMPv6 type is not a known one.
	ErrUnknownICMP6Type
	// ErrUnknownTCPFlag is reported when a TCP flag name is unknown.
	ErrUnknownTCPFlag
	// ErrExpectedIfName is reported when an interface name is expected.
	ErrExpectedIfName
	// ErrExpectedIfMask is reported when an interface mask pattern is
	// invalid.
	ErrExpectedIfMask
	// ErrExpectedTableType is reported when a table type is unknown.
	ErrExpectedTableType
	// ErrExpectedTableName is reported when a table name is expected.
	ErrExpectedTableName
	// ErrExpectedTableValue is reported when a table value is expected.
	ErrExpectedTableValue
	// ErrExpectedOpt is reported when an option lacks its argument.
	ErrExpectedOpt
	// ErrExpectedNewlineOrEOF is reported when a line has trailing content
	// after a complete command.
	ErrExpectedNewlineOrEOF
	// ErrState is reported when a State or a hook returned an error that is
	// not an ErrorKind; the error is attached to the ParseError.
	ErrState
)

// The messages in kind order; index 0 is the unused zero value.
var errorKindMessages = [...]string{
	"",
	"expected `add`, `table`, a `:label` or a `#` comment",
	"expected command",
	"expected `from`",
	"unexpected token",
	"expected action",
	"expected `or` separator",
	"expected protocol",
	"expected whitespace",
	"expected IP protocol",
	"expected IP or transport protocol",
	"expected IPv4 network",
	"expected IPv6 network",
	"expected hostname",
	"expected port",
	"unexpected escape character in port name",
	"expected token",
	"expected flow name",
	"unknown option",
	"expected target",
	"expected closing `'` of a quoted hostname",
	"expected table command (`create` or `add`)",
	"expected table key (network or interface name)",
	"expected skipto target (label, rule number or `tablearg`)",
	"expected 8-bit unsigned integer",
	"expected 16-bit unsigned integer",
	"expected 32-bit unsigned integer",
	"unknown ICMP type",
	"unknown ICMPv6 type",
	"unknown TCP flag",
	"expected interface name",
	"invalid interface mask pattern",
	"expected table type",
	"expected table name",
	"expected table value",
	"expected option argument",
	"expected `\\n` or EOF",
	"state error",
}

// Error returns the human-readable message of the kind.
func (k ErrorKind) Error() string {
	if k == 0 || int(k) >= len(errorKindMessages) {
		return "unknown error kind " + strconv.Itoa(int(k))
	}
	return errorKindMessages[k]
}

// ParseError is a parse failure located in the input.
//
// Column is a byte offset into Text, the offending line with its leading
// whitespace skipped and trailing whitespace trimmed; a column equal to the
// text length means the error is at the end of the line. Err carries the
// error a State or a hook returned when Kind is ErrState.
type ParseError struct {
	// Kind is what went wrong.
	Kind ErrorKind
	// Err is the error a State or a hook returned; nil unless Kind is ErrState.
	Err error
	// Line is the 1-based line number of the offending line.
	Line int
	// Column is the 0-based byte offset into Text of the first unparsed byte.
	Column int
	// Text is the offending line without leading and trailing whitespace.
	Text string
}

// Error renders the position followed by the message and, when present, the
// attached error.
func (e *ParseError) Error() string {
	message := strconv.Itoa(e.Line) + ":" + strconv.Itoa(e.Column) + ": " + e.Kind.Error()
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	return message
}

// Is reports whether target is the kind of this error, so errors.Is can test
// a parse error against a kind.
func (e *ParseError) Is(target error) bool {
	kind, ok := target.(ErrorKind)
	return ok && kind == e.Kind
}

// Unwrap returns the attached state error, if any.
func (e *ParseError) Unwrap() error {
	return e.Err
}
