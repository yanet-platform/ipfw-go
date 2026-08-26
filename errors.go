package ipfw

import "strconv"

// ErrorKind names a syntax or semantic error found while parsing a ruleset.
//
// Parsing functions report failures as an ErrorKind, the zero value meaning
// success. The public API wraps the kind into a positioned ParseError. Every
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
	// not an ErrorKind. The error is attached to the ParseError.
	ErrState
)

// Error returns the human-readable message of the kind.
func (k ErrorKind) Error() string {
	switch k {
	case ErrExpectedLine:
		return "expected `add`, `table`, a `:label` or a `#` comment"
	case ErrExpectedCommand:
		return "expected command"
	case ErrExpectedFrom:
		return "expected `from`"
	case ErrExpectedPrefix:
		return "unexpected token"
	case ErrExpectedAction:
		return "expected action"
	case ErrExpectedOr:
		return "expected `or` separator"
	case ErrExpectedProto:
		return "expected protocol"
	case ErrExpectedWhitespace:
		return "expected whitespace"
	case ErrExpectedIPProto:
		return "expected IP protocol"
	case ErrExpectedEitherIPOrProto:
		return "expected IP or transport protocol"
	case ErrExpectedIPv4Network:
		return "expected IPv4 network"
	case ErrExpectedIPv6Network:
		return "expected IPv6 network"
	case ErrExpectedHostname:
		return "expected hostname"
	case ErrExpectedPort:
		return "expected port"
	case ErrUnexpectedEscape:
		return "unexpected escape character in port name"
	case ErrExpectedToken:
		return "expected token"
	case ErrExpectedFlowName:
		return "expected flow name"
	case ErrUnknownOption:
		return "unknown option"
	case ErrExpectedTarget:
		return "expected target"
	case ErrExpectedHostnameEscapeClose:
		return "expected closing `'` of a quoted hostname"
	case ErrExpectedTableCommand:
		return "expected table command (`create` or `add`)"
	case ErrExpectedTableKey:
		return "expected table key (network or interface name)"
	case ErrExpectedSkipTo:
		return "expected skipto target (label, rule number or `tablearg`)"
	case ErrExpectedU8:
		return "expected 8-bit unsigned integer"
	case ErrExpectedU16:
		return "expected 16-bit unsigned integer"
	case ErrExpectedU32:
		return "expected 32-bit unsigned integer"
	case ErrUnknownICMPType:
		return "unknown ICMP type"
	case ErrUnknownICMP6Type:
		return "unknown ICMPv6 type"
	case ErrUnknownTCPFlag:
		return "unknown TCP flag"
	case ErrExpectedIfName:
		return "expected interface name"
	case ErrExpectedIfMask:
		return "invalid interface mask pattern"
	case ErrExpectedTableType:
		return "expected table type"
	case ErrExpectedTableName:
		return "expected table name"
	case ErrExpectedTableValue:
		return "expected table value"
	case ErrExpectedOpt:
		return "expected option argument"
	case ErrExpectedNewlineOrEOF:
		return "expected `\\n` or EOF"
	case ErrState:
		return "state error"
	default:
		return "unknown error kind " + strconv.Itoa(int(k))
	}
}

// ParseError is a parse failure located in the input.
//
// Column is a byte offset into Text, the offending line with its leading
// whitespace skipped and trailing whitespace trimmed. A column equal to the
// text length means the error is at the end of the line. Err carries the
// error a State or a hook returned when Kind is ErrState.
type ParseError struct {
	// Kind is what went wrong.
	Kind ErrorKind
	// Err is the error a State or a hook returned, nil unless Kind is ErrState.
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
