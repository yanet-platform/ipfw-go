package ipfw

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// verifies that a protocol token is a number when it is all digits and fits
// a byte, and a name otherwise, an overflowing number included.
func Test_ParseProto_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		proto Proto
		kind  ErrorKind
		rest  string
	}{
		{name: "number", input: "8", proto: Proto{Number: 8}, rest: ""},
		{name: "name", input: "tcp", proto: Proto{Name: "tcp"}, rest: ""},
		{name: "name starting with a digit", input: "3pc", proto: Proto{Name: "3pc"}, rest: ""},
		{name: "number with rest", input: "42 from any to any", proto: Proto{Number: 42}, rest: " from any to any"},
		{name: "overflow is a name", input: "424242424 from any to any", proto: Proto{Name: "424242424"}, rest: " from any to any"},
		{name: "largest number", input: "255", proto: Proto{Number: 255}, rest: ""},
		{name: "one past the largest is a name", input: "256", proto: Proto{Name: "256"}, rest: ""},
		{name: "dash is part of a name", input: "ipv6-icmp x", proto: Proto{Name: "ipv6-icmp"}, rest: " x"},
		{name: "empty input", input: "", kind: ErrExpectedProto, rest: ""},
		{name: "no protocol byte", input: "_ x", kind: ErrExpectedProto, rest: "_ x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proto, rest, kind := parseProto(tc.input)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, tc.proto, proto)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that `not` negates a protocol only when whitespace follows it.
func Test_ParseProtoMatch_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		match ProtoMatch
		kind  ErrorKind
		rest  string
	}{
		{name: "negated", input: "not tcp from any to any", match: ProtoMatch{Neg: true, Proto: Proto{Name: "tcp"}}, rest: " from any to any"},
		{name: "glued not is a name", input: "nottcp from any to any", match: ProtoMatch{Proto: Proto{Name: "nottcp"}}, rest: " from any to any"},
		{name: "negation without a protocol", input: "not ", kind: ErrExpectedProto, rest: "not "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match, rest, kind := parseProtoMatch(tc.input)
			require.Equal(t, tc.kind, kind)
			require.Equal(t, tc.match, match)
			require.Equal(t, tc.rest, rest)
		})
	}
}

// verifies that the exported protocol parser feeds the state, reports the
// consumed length, and positions a failure at the element start.
func Test_ParseProtocols_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		n     int
		err   error
		state CollectState
	}{
		{name: "name", input: "tcp from any to any", n: 3, state: CollectState{Protos: []ProtoMatch{{Proto: Proto{Name: "tcp"}}}}},
		{name: "negated number", input: "not 17 x", n: 6, state: CollectState{Protos: []ProtoMatch{{Neg: true, Proto: Proto{Number: 17}}}}},
		{name: "invalid", input: "_ from any to any", n: 0, err: ErrExpectedEitherIPOrProto},
		{name: "negation without a protocol", input: "not _", n: 0, err: ErrExpectedEitherIPOrProto},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state CollectState
			n, err := ParseProtocols(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, tc.state, state)
		})
	}
}

// rejectingState turns every token into the configured error.
type rejectingState struct {
	DiscardState
	err error
}

// Proto implements State.
func (m rejectingState) Proto(ProtoMatch) error {
	return m.err
}

// verifies that an error from the state comes back as is, positioned at
// the rejected token.
func Test_ParseProtocols_StateError(t *testing.T) {
	n, err := ParseProtocols("tcp from", rejectingState{err: ErrUnknownOption})
	require.Equal(t, 0, n)
	require.Equal(t, ErrUnknownOption, err)

	boom := errors.New("boom")
	n, err = ParseProtocols("tcp from", rejectingState{err: boom})
	require.Equal(t, 0, n)
	require.Equal(t, boom, err)
}

// verifies that every byte value formatted in decimal parses as a number.
func Test_ParseProto_NumberRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint8().Draw(t, "number")
		proto, rest, kind := parseProto(strconv.FormatUint(uint64(number), 10) + " x")
		require.Equal(t, ErrorKind(0), kind)
		require.Equal(t, Proto{Number: number}, proto)
		require.Equal(t, " x", rest)
	})
}

// verifies that a lowercase word parses as a name.
func Test_ParseProto_NameRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "name")
		proto, rest, kind := parseProto(name + " x")
		require.Equal(t, ErrorKind(0), kind)
		require.Equal(t, Proto{Name: name}, proto)
		require.Equal(t, " x", rest)
	})
}

// verifies that protocol parsing into a warmed-up state allocates nothing.
func Test_ParseProtocols_NoAllocs(t *testing.T) {
	var state CollectState
	_, _ = ParseProtocols("not tcp from", &state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		state.Reset()
		if n, err := ParseProtocols("not tcp from", &state); err != nil || n != 7 {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
