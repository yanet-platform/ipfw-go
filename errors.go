package ipfw

import "strconv"

// ErrorKind names an error found while parsing or canonically formatting a ruleset.
type ErrorKind uint8

// The parser and formatter error kinds. The zero value means no error.
const (
	_ ErrorKind = iota
	ErrExpectedLine
	ErrExpectedFrom
	// ErrExpectedPrefix is a missing keyword or punctuation.
	ErrExpectedPrefix
	ErrExpectedAction
	ErrExpectedOr
	ErrExpectedProto
	ErrExpectedWhitespace
	ErrExpectedEitherIPOrProto
	ErrExpectedIPv4Network
	ErrExpectedIPv6Network
	ErrExpectedHostname
	ErrExpectedPort
	// ErrUnexpectedEscape is a backslash in a port name escaping anything but `-`.
	ErrUnexpectedEscape
	ErrExpectedToken
	ErrUnknownOption
	ErrExpectedTarget
	// ErrUnresolvedTarget is a hostname or a target of unknown shape that no
	// resolver turns into networks.
	ErrUnresolvedTarget
	// ErrUnresolvedProto is a protocol name that no resolver turns into a number.
	ErrUnresolvedProto
	// ErrUnresolvedService is a service name that no resolver turns into a port.
	ErrUnresolvedService
	ErrExpectedHostnameEscapeClose
	ErrExpectedTableCommand
	ErrExpectedTableKey
	ErrExpectedSkipTo
	ErrExpectedU8
	ErrExpectedU16
	ErrExpectedU32
	ErrUnknownICMPType
	ErrUnknownICMP6Type
	ErrUnknownTCPFlag
	ErrExpectedTableType
	ErrExpectedTableName
	ErrExpectedTableValue
	// ErrExpectedOpt is an option without its argument.
	ErrExpectedOpt
	ErrExpectedNewlineOrEOF
	// ErrState wraps an error a State or a hook returned, see ParseError.Err.
	ErrState
	ErrExpectedTag
	ErrStateOptionInGroup
	ErrDuplicateStateOption
	// The formatter-specific kinds.
	ErrUnknownRecordKind
	ErrUnexpectedBody
	ErrInvalidName
	ErrUnknownActionKind
	ErrUnknownSkipToKind
	ErrUnknownProtoKind
	ErrUnknownTargetKind
	ErrUnknownTableKind
	ErrUnknownTableKeyKind
	ErrUnknownTableType
	ErrUnknownOptionKind
	ErrUnknownViaKind
	ErrMissingProtocol
	ErrMissingSource
	ErrMissingDestination
	ErrInvalidLog
	ErrBrokenOrChain
	ErrInconsistentNegation
	ErrInvalidTCPFlags
	ErrEmptyTypeSet
	ErrMissingCustomOptAppender
)

// Error returns the message of the kind.
func (m ErrorKind) Error() string {
	switch m {
	case ErrExpectedLine:
		return "expected `add`, `table`, a `:label` or a `#` comment"
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
	case ErrUnknownOption:
		return "unknown option"
	case ErrExpectedTarget:
		return "expected target"
	case ErrUnresolvedTarget:
		return "unresolved target name"
	case ErrUnresolvedProto:
		return "unresolved protocol name"
	case ErrUnresolvedService:
		return "unresolved service name"
	case ErrExpectedHostnameEscapeClose:
		return "expected closing `'` of a quoted hostname"
	case ErrExpectedTableCommand:
		return "expected table command (`create` or `add`)"
	case ErrExpectedTableKey:
		return "expected table key"
	case ErrExpectedSkipTo:
		return "expected skipto target (label, rule number or `tablearg`)"
	case ErrExpectedTag:
		return "expected positive tag number"
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
	case ErrStateOptionInGroup:
		return "state-producing option in OR block"
	case ErrDuplicateStateOption:
		return "more than one state-producing option"
	case ErrUnknownRecordKind:
		return "record kind without a canonical form"
	case ErrUnexpectedBody:
		return "fields or body the record kind cannot hold"
	case ErrInvalidName:
		return "invalid name or text"
	case ErrUnknownActionKind:
		return "action kind without a canonical form"
	case ErrUnknownSkipToKind:
		return "skipto target kind without a canonical form"
	case ErrUnknownProtoKind:
		return "IP version set without a canonical keyword"
	case ErrUnknownTargetKind:
		return "target kind without a canonical form"
	case ErrUnknownTableKind:
		return "table command without a canonical form"
	case ErrUnknownTableKeyKind:
		return "table key kind without a canonical form"
	case ErrUnknownTableType:
		return "table type without a canonical form"
	case ErrUnknownOptionKind:
		return "option kind without a canonical form"
	case ErrUnknownViaKind:
		return "via kind without a canonical form"
	case ErrMissingProtocol:
		return "missing protocol"
	case ErrMissingSource:
		return "missing source"
	case ErrMissingDestination:
		return "missing destination"
	case ErrInvalidLog:
		return "invalid log and logamount combination"
	case ErrBrokenOrChain:
		return "invalid grouping or list continuation"
	case ErrInconsistentNegation:
		return "inconsistent negation within a list"
	case ErrInvalidTCPFlags:
		return "invalid tcpflags requirements"
	case ErrEmptyTypeSet:
		return "empty icmptypes or icmp6types set"
	case ErrMissingCustomOptAppender:
		return "custom option without an appender"
	default:
		return "unknown error kind " + strconv.Itoa(int(m))
	}
}

// ParseError is a parse failure located in the input.
type ParseError struct {
	Kind ErrorKind
	// Err is the error a State or a hook returned, nil unless Kind is ErrState.
	Err error
	// Line is 1-based.
	Line int
	// Column is the byte offset into Text of the first unparsed byte.
	Column int
	// Text is the offending line without leading and trailing whitespace.
	Text string
}

// Error renders the position, the message and the attached error, if any.
func (m *ParseError) Error() string {
	message := strconv.Itoa(m.Line) + ":" + strconv.Itoa(m.Column) + ": " + m.Kind.Error()
	if m.Err != nil {
		message += ": " + m.Err.Error()
	}
	return message
}

// Is matches target against the kind.
func (m *ParseError) Is(target error) bool {
	kind, ok := target.(ErrorKind)
	return ok && kind == m.Kind
}

// Unwrap returns the attached error, if any.
func (m *ParseError) Unwrap() error {
	return m.Err
}
