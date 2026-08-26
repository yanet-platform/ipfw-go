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
		{
			name:  "name",
			input: "tcp from any to any",
			n:     3,
			state: CollectState{Protos: []ProtoMatch{{Proto: Proto{Name: "tcp"}}}},
		},
		{
			name:  "negated name",
			input: "not tcp from any to any",
			n:     7,
			state: CollectState{Protos: []ProtoMatch{{Neg: true, Proto: Proto{Name: "tcp"}}}},
		},
		{
			name:  "glued not is a name",
			input: "nottcp from any to any",
			n:     6,
			state: CollectState{Protos: []ProtoMatch{{Proto: Proto{Name: "nottcp"}}}},
		},
		{
			name:  "negated number",
			input: "not 17 x",
			n:     6,
			state: CollectState{Protos: []ProtoMatch{{Neg: true, Proto: Proto{Number: 17}}}},
		},
		{
			name:  "ip keyword",
			input: "ip from any to any",
			n:     2,
			state: CollectState{IPProtos: []ProtoIPMatch{{Proto: ProtoIPAny}}},
		},
		{
			name:  "all keyword",
			input: "all from",
			n:     3,
			state: CollectState{IPProtos: []ProtoIPMatch{{Proto: ProtoIPAny}}},
		},
		{
			name:  "negated ip4 keyword",
			input: "not ip4 from",
			n:     7,
			state: CollectState{IPProtos: []ProtoIPMatch{{Neg: true, Proto: ProtoIPv4}}},
		},
		{
			name:  "ipv6 keyword",
			input: "ipv6 from",
			n:     4,
			state: CollectState{IPProtos: []ProtoIPMatch{{Proto: ProtoIPv6}}},
		},
		{
			name:  "keyword prefix is a transport name",
			input: "ipencap from any to any",
			n:     7,
			state: CollectState{Protos: []ProtoMatch{{Proto: Proto{Name: "ipencap"}}}},
		},
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

// IPProto implements State.
func (m rejectingState) IPProto(ProtoIPMatch) error {
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

	n, err = ParseProtocols("not ip from", rejectingState{err: boom})
	require.Equal(t, 0, n)
	require.Equal(t, boom, err)
}

// verifies that only the exact IP version keywords are recognized.
func Test_ParseProtoIP_Table(t *testing.T) {
	cases := []struct {
		token string
		proto ProtoIP
		ok    bool
	}{
		{token: "ip", proto: ProtoIPAny, ok: true},
		{token: "all", proto: ProtoIPAny, ok: true},
		{token: "ip4", proto: ProtoIPv4, ok: true},
		{token: "ipv4", proto: ProtoIPv4, ok: true},
		{token: "ip6", proto: ProtoIPv6, ok: true},
		{token: "ipv6", proto: ProtoIPv6, ok: true},
		{token: "ipencap"},
		{token: "IP"},
		{token: "ip4x"},
		{token: ""},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			proto, ok := ParseProtoIP(tc.token)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.proto, proto)
		})
	}
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
