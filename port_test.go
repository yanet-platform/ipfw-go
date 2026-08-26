package ipfw_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/ipfw"
)

// portNumber is a single numeric port match.
func portNumber(number uint16) ipfw.PortMatch {
	port := ipfw.Port{Number: number}
	return ipfw.PortMatch{Range: ipfw.PortRange{Lo: port, Hi: port}}
}

// portService is a single named port match.
func portService(name string) ipfw.PortMatch {
	port := ipfw.Port{Name: name}
	return ipfw.PortMatch{Range: ipfw.PortRange{Lo: port, Hi: port}}
}

// portSpan is a port range match.
func portSpan(lo, hi ipfw.Port) ipfw.PortMatch {
	return ipfw.PortMatch{Range: ipfw.PortRange{Lo: lo, Hi: hi}}
}

// SourcePort implements State.
func (m rejectingState) SourcePort(ipfw.PortMatch) error {
	return m.err
}

// DestinationPort implements State.
func (m rejectingState) DestinationPort(ipfw.PortMatch) error {
	return m.err
}

// verifies that the port parsers feed the right side of the state, report
// the consumed length, and position a failure at the port.
//
// A port is a run of letters and digits up to a dash, a number when every
// byte is a digit and the value fits sixteen bits, a name otherwise. A dash
// makes a range of two ports.
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
			var state ipfw.CollectState
			n, err := ipfw.ParseSourcePorts(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, ipfw.CollectState{SourcePorts: tc.ports}, state)

			state = ipfw.CollectState{}
			n, err = ipfw.ParseDestinationPorts(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, ipfw.CollectState{DestinationPorts: tc.ports}, state)
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
}

// verifies that any 16-bit number formatted in decimal parses back to
// itself and is consumed entirely.
func Test_ParsePorts_NumberRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		port := rapid.Uint16().Draw(t, "port")
		input := strconv.FormatUint(uint64(port), 10)
		var state ipfw.CollectState
		n, err := ipfw.ParseSourcePorts(input, &state)
		require.NoError(t, err)
		require.Equal(t, len(input), n)
		require.Equal(t, ipfw.CollectState{SourcePorts: []ipfw.PortMatch{portNumber(port)}}, state)
	})
}

// verifies that a decimal above the 16-bit range is a service name rather
// than an error, since custom services may be named by digits.
func Test_ParsePorts_OverflowIsName(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		value := rapid.Uint64Range(math.MaxUint16+1, math.MaxUint64).Draw(t, "value")
		input := strconv.FormatUint(value, 10)
		var state ipfw.CollectState
		n, err := ipfw.ParseSourcePorts(input, &state)
		require.NoError(t, err)
		require.Equal(t, len(input), n)
		require.Equal(t, ipfw.CollectState{SourcePorts: []ipfw.PortMatch{portService(input)}}, state)
	})
}

// verifies that parsing a port into a warmed-up state allocates nothing.
func Test_ParsePorts_NoAllocs(t *testing.T) {
	input := "1024-65535 to any"
	var state ipfw.CollectState
	_, _ = ipfw.ParseSourcePorts(input, &state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		state.Reset()
		n, err := ipfw.ParseSourcePorts(input, &state)
		if err != nil || n != 10 {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
