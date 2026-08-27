package ipfw_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/ipfw-go"
)

// portNumber is a single numeric port match.
func portNumber(number uint16) ipfw.PortMatch {
	port := ipfw.Port{Number: number}
	return ipfw.PortMatch{Lo: port, Hi: port}
}

// portService is a single named port match.
func portService(name string) ipfw.PortMatch {
	port := ipfw.Port{Name: name}
	return ipfw.PortMatch{Lo: port, Hi: port}
}

// portSpan is a port range match.
func portSpan(lo, hi ipfw.Port) ipfw.PortMatch {
	return ipfw.PortMatch{Lo: lo, Hi: hi}
}

// negated is the match with its negation set.
func negated(match ipfw.PortMatch) ipfw.PortMatch {
	match.Neg = true
	return match
}

// OnSourcePort implements State.
func (m rejectingState) OnSourcePort(ipfw.PortMatch) error {
	return m.err
}

// OnDestinationPort implements State.
func (m rejectingState) OnDestinationPort(ipfw.PortMatch) error {
	return m.err
}

// verifies that the port parsers feed the right side of the state, report
// the consumed length, and position a failure at the port.
//
// A port is a run of letters and digits up to a dash, a number when every
// byte is a digit and the value fits sixteen bits, a name otherwise. A dash
// makes a range of two ports and commas a list of ranges, each one emitted
// as it is read. A `not` before the list negates every element. A backslash
// escapes a dash so it does not end the port, the name keeping the escape.
func Test_ParsePorts_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		n     int
		err   error
		ports []ipfw.PortMatch
	}{
		{
			name:  "number",
			input: "22 to any",
			n:     2,
			ports: []ipfw.PortMatch{portNumber(22)},
		},
		{
			name:  "service name",
			input: "http to any",
			n:     4,
			ports: []ipfw.PortMatch{portService("http")},
		},
		{
			name:  "overflowing number is a name",
			input: "70000 to any",
			n:     5,
			ports: []ipfw.PortMatch{portService("70000")},
		},
		{
			name:  "maximum number",
			input: "65535",
			n:     5,
			ports: []ipfw.PortMatch{portNumber(65535)},
		},
		{
			name:  "leading zeros",
			input: "007 x",
			n:     3,
			ports: []ipfw.PortMatch{portNumber(7)},
		},
		{
			name:  "digits then letters are a name",
			input: "8http x",
			n:     5,
			ports: []ipfw.PortMatch{portService("8http")},
		},
		{
			name:  "keyword is a name",
			input: "to x",
			n:     2,
			ports: []ipfw.PortMatch{portService("to")},
		},
		{
			name:  "range",
			input: "22-53 to any",
			n:     5,
			ports: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 22}, ipfw.Port{Number: 53})},
		},
		{
			name:  "range of names",
			input: "http-https x",
			n:     10,
			ports: []ipfw.PortMatch{portSpan(ipfw.Port{Name: "http"}, ipfw.Port{Name: "https"})},
		},
		{
			name:  "range of a number and a name",
			input: "22-ssh x",
			n:     6,
			ports: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 22}, ipfw.Port{Name: "ssh"})},
		},
		{
			name:  "whole range",
			input: "1-65535",
			n:     7,
			ports: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1}, ipfw.Port{Number: 65535})},
		},
		{
			name:  "range without its second port",
			input: "22-",
			n:     3,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "range without its second port before a space",
			input: "22- 53",
			n:     3,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "list",
			input: "22,80,443 x",
			n:     9,
			ports: []ipfw.PortMatch{portNumber(22), portNumber(80), portNumber(443)},
		},
		{
			name:  "list with a range",
			input: "22,80-90,443",
			n:     12,
			ports: []ipfw.PortMatch{
				portNumber(22),
				portSpan(ipfw.Port{Number: 80}, ipfw.Port{Number: 90}),
				portNumber(443),
			},
		},
		{
			name:  "list of names",
			input: "http,https x",
			n:     10,
			ports: []ipfw.PortMatch{portService("http"), portService("https")},
		},
		{
			name:  "trailing comma keeps the elements before it",
			input: "22,80,",
			n:     6,
			err:   ipfw.ErrExpectedPort,
			ports: []ipfw.PortMatch{portNumber(22), portNumber(80)},
		},
		{
			name:  "comma first",
			input: ",22",
			n:     0,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "space after the comma",
			input: "22, 80",
			n:     3,
			err:   ipfw.ErrExpectedPort,
			ports: []ipfw.PortMatch{portNumber(22)},
		},
		{
			name:  "negated port",
			input: "not 22 x",
			n:     6,
			ports: []ipfw.PortMatch{negated(portNumber(22))},
		},
		{
			name:  "negated list",
			input: "not 22-23,80",
			n:     12,
			ports: []ipfw.PortMatch{
				negated(portSpan(ipfw.Port{Number: 22}, ipfw.Port{Number: 23})),
				negated(portNumber(80)),
			},
		},
		{
			name:  "not glued to a name is a name",
			input: "notify x",
			n:     6,
			ports: []ipfw.PortMatch{portService("notify")},
		},
		{
			name:  "bare not is a name",
			input: "not",
			n:     3,
			ports: []ipfw.PortMatch{portService("not")},
		},
		{
			name:  "nothing after not",
			input: "not ",
			n:     4,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "escaped dash in a name",
			input: "ftp\\-data to any",
			n:     9,
			ports: []ipfw.PortMatch{portService("ftp\\-data")},
		},
		{
			name:  "range of escaped names",
			input: "ftp\\-data-ftp to any",
			n:     13,
			ports: []ipfw.PortMatch{portSpan(ipfw.Port{Name: "ftp\\-data"}, ipfw.Port{Name: "ftp"})},
		},
		{
			name:  "escape at the second port",
			input: "20-ftp\\-data",
			n:     12,
			ports: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 20}, ipfw.Port{Name: "ftp\\-data"})},
		},
		{
			name:  "escaped dash makes digits a name",
			input: "2\\-2 x",
			n:     4,
			ports: []ipfw.PortMatch{portService("2\\-2")},
		},
		{
			name:  "escape of anything but a dash",
			input: "ftp\\x",
			n:     3,
			err:   ipfw.ErrUnexpectedEscape,
		},
		{
			name:  "trailing backslash is part of the name",
			input: "ftp\\ x",
			n:     4,
			ports: []ipfw.PortMatch{portService("ftp\\")},
		},
		{
			name:  "backslash alone is a name",
			input: "\\",
			n:     1,
			ports: []ipfw.PortMatch{portService("\\")},
		},
		{
			name:  "empty input",
			input: "",
			n:     0,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "dash first",
			input: "-22",
			n:     0,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "underscore is not a port byte",
			input: "_x",
			n:     0,
			err:   ipfw.ErrExpectedPort,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			n, err := ipfw.ParseSourcePorts(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, ipfw.ReduceState{SourcePorts: tc.ports}, state)

			state = ipfw.ReduceState{}
			n, err = ipfw.ParseDestinationPorts(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, ipfw.ReduceState{DestinationPorts: tc.ports}, state)
		})
	}
}

// verifies that an error from the state comes back as is, positioned at
// the port.
func Test_ParsePorts_StateError(t *testing.T) {
	state := rejectingState{err: ipfw.ErrUnknownOption}
	n, err := ipfw.ParseSourcePorts("22 x", state)
	require.Equal(t, 0, n)
	require.Equal(t, ipfw.ErrUnknownOption, err)
	n, err = ipfw.ParseDestinationPorts("80", state)
	require.Equal(t, 0, n)
	require.Equal(t, ipfw.ErrUnknownOption, err)
	n, err = ipfw.ParseDestinationPorts("not 80", state)
	require.Equal(t, 4, n)
	require.Equal(t, ipfw.ErrUnknownOption, err)
}

// verifies that any 16-bit number formatted in decimal parses back to
// itself and is consumed entirely.
func Test_ParsePorts_NumberRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		port := rapid.Uint16().Draw(t, "port")
		input := strconv.FormatUint(uint64(port), 10)
		var state ipfw.ReduceState
		n, err := ipfw.ParseSourcePorts(input, &state)
		require.NoError(t, err)
		require.Equal(t, len(input), n)
		require.Equal(t, ipfw.ReduceState{SourcePorts: []ipfw.PortMatch{portNumber(port)}}, state)
	})
}

// verifies that a decimal above the 16-bit range is a service name rather
// than an error, since custom services may be named by digits.
func Test_ParsePorts_OverflowIsName(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := rapid.Uint64Range(math.MaxUint16+1, math.MaxUint64).Draw(t, "value")
		input := strconv.FormatUint(value, 10)
		var state ipfw.ReduceState
		n, err := ipfw.ParseSourcePorts(input, &state)
		require.NoError(t, err)
		require.Equal(t, len(input), n)
		require.Equal(t, ipfw.ReduceState{SourcePorts: []ipfw.PortMatch{portService(input)}}, state)
	})
}

// isPortLetterOrDigit is the port alphabet the tests pin, the dash and the
// backslash being separators handled on top of it.
func isPortLetterOrDigit(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// verifies the port alphabet byte by byte, non-ASCII bytes included.
//
// Every byte that is not a letter, a digit, the range dash, the escape
// backslash or the list comma ends the port.
func Test_ParsePorts_Alphabet(t *testing.T) {
	for c := range 256 {
		b := byte(c)
		if isPortLetterOrDigit(b) || b == '-' || b == '\\' || b == ',' {
			continue
		}
		var state ipfw.ReduceState
		n, err := ipfw.ParseSourcePorts("ab"+string([]byte{b}), &state)
		require.NoError(t, err, "byte %#x", b)
		require.Equal(t, 2, n, "byte %#x", b)
		require.Equal(t, ipfw.ReduceState{SourcePorts: []ipfw.PortMatch{portService("ab")}}, state)
	}
}

// verifies that any run of letters and digits holding a letter is a whole
// service name, consumed entirely.
func Test_ParsePorts_NameRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*`).Draw(t, "name")
		var state ipfw.ReduceState
		n, err := ipfw.ParseSourcePorts(name, &state)
		require.NoError(t, err)
		require.Equal(t, len(name), n)
		require.Equal(t, ipfw.ReduceState{SourcePorts: []ipfw.PortMatch{portService(name)}}, state)
	})
}

// verifies that parsing a port into a warmed-up state allocates nothing.
func Test_ParsePorts_NoAllocs(t *testing.T) {
	input := "not 22,1024-65535,ftp\\-data to any"
	var state ipfw.ReduceState
	_, _ = ipfw.ParseSourcePorts(input, &state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		state.Reset()
		n, err := ipfw.ParseSourcePorts(input, &state)
		if err != nil || n != 27 {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
