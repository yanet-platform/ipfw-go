package ipfw_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// verifies that every error kind renders its documented message and an
// unknown value renders its number.
func Test_ErrorKind_Error(t *testing.T) {
	cases := []struct {
		name    string
		kind    ipfw.ErrorKind
		message string
	}{
		{
			name:    "expected line",
			kind:    ipfw.ErrExpectedLine,
			message: "expected `add`, `table`, a `:label` or a `#` comment",
		},
		{name: "expected command", kind: ipfw.ErrExpectedCommand, message: "expected command"},
		{name: "expected from", kind: ipfw.ErrExpectedFrom, message: "expected `from`"},
		{name: "expected prefix", kind: ipfw.ErrExpectedPrefix, message: "unexpected token"},
		{name: "expected action", kind: ipfw.ErrExpectedAction, message: "expected action"},
		{name: "expected or", kind: ipfw.ErrExpectedOr, message: "expected `or` separator"},
		{name: "expected proto", kind: ipfw.ErrExpectedProto, message: "expected protocol"},
		{
			name:    "expected whitespace",
			kind:    ipfw.ErrExpectedWhitespace,
			message: "expected whitespace",
		},
		{name: "expected IP proto", kind: ipfw.ErrExpectedIPProto, message: "expected IP protocol"},
		{
			name:    "expected either IP or proto",
			kind:    ipfw.ErrExpectedEitherIPOrProto,
			message: "expected IP or transport protocol",
		},
		{
			name:    "expected IPv4 network",
			kind:    ipfw.ErrExpectedIPv4Network,
			message: "expected IPv4 network",
		},
		{
			name:    "expected IPv6 network",
			kind:    ipfw.ErrExpectedIPv6Network,
			message: "expected IPv6 network",
		},
		{name: "expected hostname", kind: ipfw.ErrExpectedHostname, message: "expected hostname"},
		{name: "expected port", kind: ipfw.ErrExpectedPort, message: "expected port"},
		{
			name:    "unexpected escape",
			kind:    ipfw.ErrUnexpectedEscape,
			message: "unexpected escape character in port name",
		},
		{name: "expected token", kind: ipfw.ErrExpectedToken, message: "expected token"},
		{name: "expected flow name", kind: ipfw.ErrExpectedFlowName, message: "expected flow name"},
		{name: "unknown option", kind: ipfw.ErrUnknownOption, message: "unknown option"},
		{name: "expected target", kind: ipfw.ErrExpectedTarget, message: "expected target"},
		{
			name:    "unresolved target",
			kind:    ipfw.ErrUnresolvedTarget,
			message: "unresolved target name",
		},
		{
			name:    "expected hostname escape close",
			kind:    ipfw.ErrExpectedHostnameEscapeClose,
			message: "expected closing `'` of a quoted hostname",
		},
		{
			name:    "expected table command",
			kind:    ipfw.ErrExpectedTableCommand,
			message: "expected table command (`create` or `add`)",
		},
		{
			name:    "expected table key",
			kind:    ipfw.ErrExpectedTableKey,
			message: "expected table key (network or interface name)",
		},
		{
			name:    "expected skipto",
			kind:    ipfw.ErrExpectedSkipTo,
			message: "expected skipto target (label, rule number or `tablearg`)",
		},
		{name: "expected u8", kind: ipfw.ErrExpectedU8, message: "expected 8-bit unsigned integer"},
		{
			name:    "expected u16",
			kind:    ipfw.ErrExpectedU16,
			message: "expected 16-bit unsigned integer",
		},
		{
			name:    "expected u32",
			kind:    ipfw.ErrExpectedU32,
			message: "expected 32-bit unsigned integer",
		},
		{name: "unknown ICMP type", kind: ipfw.ErrUnknownICMPType, message: "unknown ICMP type"},
		{
			name:    "unknown ICMPv6 type",
			kind:    ipfw.ErrUnknownICMP6Type,
			message: "unknown ICMPv6 type",
		},
		{name: "unknown TCP flag", kind: ipfw.ErrUnknownTCPFlag, message: "unknown TCP flag"},
		{
			name:    "expected interface name",
			kind:    ipfw.ErrExpectedIfName,
			message: "expected interface name",
		},
		{
			name:    "invalid interface mask",
			kind:    ipfw.ErrExpectedIfMask,
			message: "invalid interface mask pattern",
		},
		{
			name:    "expected table type",
			kind:    ipfw.ErrExpectedTableType,
			message: "expected table type",
		},
		{
			name:    "expected table name",
			kind:    ipfw.ErrExpectedTableName,
			message: "expected table name",
		},
		{
			name:    "expected table value",
			kind:    ipfw.ErrExpectedTableValue,
			message: "expected table value",
		},
		{
			name:    "expected option argument",
			kind:    ipfw.ErrExpectedOpt,
			message: "expected option argument",
		},
		{
			name:    "expected newline or EOF",
			kind:    ipfw.ErrExpectedNewlineOrEOF,
			message: "expected `\\n` or EOF",
		},
		{name: "state error", kind: ipfw.ErrState, message: "state error"},
		{
			name:    "unknown value renders its number",
			kind:    ipfw.ErrorKind(200),
			message: "unknown error kind 200",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.message, tc.kind.Error())
		})
	}
}

// verifies that the defined kinds all have a non-empty message and no two
// kinds share one, so a message identifies its kind.
func Test_ErrorKind_MessagesAreDistinct(t *testing.T) {
	seen := map[string]ipfw.ErrorKind{}
	for kind := ipfw.ErrorKind(1); kind <= ipfw.ErrState; kind++ {
		message := kind.Error()
		require.NotEmpty(t, message, "kind %d", kind)
		require.NotContains(t, message, "unknown error kind", "kind %d", kind)
		previous, duplicate := seen[message]
		require.False(t, duplicate, "kinds %d and %d share %q", previous, kind, message)
		seen[message] = kind
	}
}

// verifies that a parse error prints its position and message, and appends
// the underlying error when one is attached.
func Test_ParseError_Error(t *testing.T) {
	cases := []struct {
		name     string
		err      *ipfw.ParseError
		expected string
	}{
		{
			name: "kind only",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   3,
				Column: 12,
				Text:   "add foobar",
			},
			expected: "3:12: expected action",
		},
		{
			name: "state error with cause",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrState,
				Err:    errors.New("boom"),
				Line:   3,
				Column: 12,
			},
			expected: "3:12: state error: boom",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

// verifies that errors.Is matches a parse error against its own kind only.
func Test_ParseError_Is(t *testing.T) {
	err := &ipfw.ParseError{Kind: ipfw.ErrExpectedAction, Line: 1}
	require.ErrorIs(t, err, ipfw.ErrExpectedAction)
	require.NotErrorIs(t, err, ipfw.ErrExpectedPort)
	require.NotErrorIs(t, err, ipfw.ErrState)
}

// verifies that the attached state error is reachable through the error
// chain and that a plain parse error unwraps to nothing.
func Test_ParseError_Unwrap(t *testing.T) {
	cause := errors.New("boom")
	withCause := &ipfw.ParseError{Kind: ipfw.ErrState, Err: cause, Line: 1}
	require.ErrorIs(t, withCause, cause)
	require.ErrorIs(t, withCause, ipfw.ErrState)
	require.Equal(t, cause, errors.Unwrap(withCause))

	plain := &ipfw.ParseError{Kind: ipfw.ErrExpectedAction, Line: 1}
	require.NoError(t, errors.Unwrap(plain))
}
