package ipfw_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/ipfw"
)

// protos is the state of a body with the given transport protocols.
func protos(matches ...ipfw.ProtoMatch) ipfw.CollectState {
	return ipfw.CollectState{Protos: matches}
}

// verifies that the protocol parser feeds the state, reports the consumed
// length, and positions a failure at the element start.
//
// A protocol is a number only when it is all digits and fits a byte, a
// name otherwise, an overflowing number included.
func Test_ParseProtocols_Table(t *testing.T) {
	cases := []struct {
		name  string
		input string
		n     int
		err   error
		state ipfw.CollectState
	}{
		{
			name:  "number",
			input: "8 x",
			n:     1,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Number: 8}}),
		},
		{
			name:  "name",
			input: "tcp from any to any",
			n:     3,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}}),
		},
		{
			name:  "name starting with a digit",
			input: "3pc x",
			n:     3,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "3pc"}}),
		},
		{
			name:  "number with rest",
			input: "42 from any to any",
			n:     2,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Number: 42}}),
		},
		{
			name:  "overflow is a name",
			input: "424242424 x",
			n:     9,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "424242424"}}),
		},
		{
			name:  "largest number",
			input: "255 x",
			n:     3,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Number: 255}}),
		},
		{
			name:  "one past the largest is a name",
			input: "256 x",
			n:     3,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "256"}}),
		},
		{
			name:  "dash is part of a name",
			input: "ipv6-icmp x",
			n:     9,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "ipv6-icmp"}}),
		},
		{
			name:  "negated name",
			input: "not tcp x",
			n:     7,
			state: protos(ipfw.ProtoMatch{Neg: true, Proto: ipfw.Proto{Name: "tcp"}}),
		},
		{
			name:  "glued not is a name",
			input: "nottcp x",
			n:     6,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "nottcp"}}),
		},
		{
			name:  "negated number",
			input: "not 17 x",
			n:     6,
			state: protos(ipfw.ProtoMatch{Neg: true, Proto: ipfw.Proto{Number: 17}}),
		},
		{
			name:  "ip keyword",
			input: "ip from any to any",
			n:     2,
			state: ipfw.CollectState{IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}}},
		},
		{
			name:  "all keyword",
			input: "all from",
			n:     3,
			state: ipfw.CollectState{IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}}},
		},
		{
			name:  "negated ip4 keyword",
			input: "not ip4 from",
			n:     7,
			state: ipfw.CollectState{
				IPProtos: []ipfw.ProtoIPMatch{{Neg: true, Proto: ipfw.ProtoIPv4}},
			},
		},
		{
			name:  "ipv6 keyword",
			input: "ipv6 from",
			n:     4,
			state: ipfw.CollectState{IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv6}}},
		},
		{
			name:  "keyword prefix is a transport name",
			input: "ipencap x",
			n:     7,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "ipencap"}}),
		},
		{name: "empty input", input: "", n: 0, err: ipfw.ErrExpectedEitherIPOrProto},
		{name: "invalid", input: "_ from any to any", n: 0, err: ipfw.ErrExpectedEitherIPOrProto},
		{
			name:  "negation without a protocol",
			input: "not _",
			n:     0,
			err:   ipfw.ErrExpectedEitherIPOrProto,
		},
		{
			name:  "group",
			input: "{ tcp or udp } from any to any",
			n:     14,
			state: protos(
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}},
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "udp"}},
			),
		},
		{
			name:  "group without inner spaces",
			input: "{tcp or udp} x",
			n:     12,
			state: protos(
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}},
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "udp"}},
			),
		},
		{
			name:  "group across a newline",
			input: "{ tcp or\nudp } x",
			n:     14,
			state: protos(
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}},
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "udp"}},
			),
		},
		{
			name:  "group mixing an IP keyword and a transport name",
			input: "{ ip or tcp } x",
			n:     13,
			state: ipfw.CollectState{
				IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Protos:   []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
			},
		},
		{
			name:  "negation inside a group",
			input: "{ not tcp or udp }",
			n:     18,
			state: protos(
				ipfw.ProtoMatch{Neg: true, Proto: ipfw.Proto{Name: "tcp"}},
				ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "udp"}},
			),
		},
		{
			name:  "missing separator",
			input: "{ tcp udp } from any to any",
			n:     6,
			err:   ipfw.ErrExpectedOr,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}}),
		},
		{
			name:  "unclosed group",
			input: "{ tcp",
			n:     5,
			err:   ipfw.ErrExpectedOr,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}}),
		},
		{
			name:  "invalid element inside a group",
			input: "{ tcp or _ }",
			n:     9,
			err:   ipfw.ErrExpectedEitherIPOrProto,
			state: protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.CollectState
			n, err := ipfw.ParseProtocols(tc.input, &state)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, tc.state, state)
		})
	}
}

// rejectingState turns every token into the configured error.
type rejectingState struct {
	ipfw.DiscardState
	err error
}

// OnIPProto implements State.
func (m rejectingState) OnIPProto(ipfw.ProtoIPMatch) error {
	return m.err
}

// OnProto implements State.
func (m rejectingState) OnProto(ipfw.ProtoMatch) error {
	return m.err
}

// OnSourceTarget implements State.
func (m rejectingState) OnSourceTarget(ipfw.Target) error {
	return m.err
}

// OnDestinationTarget implements State.
func (m rejectingState) OnDestinationTarget(ipfw.Target) error {
	return m.err
}

// verifies that an error from the state comes back as is, positioned at
// the rejected token.
func Test_ParseProtocols_StateError(t *testing.T) {
	n, err := ipfw.ParseProtocols("tcp from", rejectingState{err: ipfw.ErrUnknownOption})
	require.Equal(t, 0, n)
	require.Equal(t, ipfw.ErrUnknownOption, err)

	boom := errors.New("boom")
	n, err = ipfw.ParseProtocols("tcp from", rejectingState{err: boom})
	require.Equal(t, 0, n)
	require.Equal(t, boom, err)

	n, err = ipfw.ParseProtocols("not ip from", rejectingState{err: boom})
	require.Equal(t, 0, n)
	require.Equal(t, boom, err)
}

// verifies that only the exact IP version keywords are recognized.
func Test_ParseProtoIP_Table(t *testing.T) {
	cases := []struct {
		token string
		proto ipfw.ProtoIP
		ok    bool
	}{
		{token: "ip", proto: ipfw.ProtoIPAny, ok: true},
		{token: "all", proto: ipfw.ProtoIPAny, ok: true},
		{token: "ip4", proto: ipfw.ProtoIPv4, ok: true},
		{token: "ipv4", proto: ipfw.ProtoIPv4, ok: true},
		{token: "ip6", proto: ipfw.ProtoIPv6, ok: true},
		{token: "ipv6", proto: ipfw.ProtoIPv6, ok: true},
		{token: "ipencap"},
		{token: "IP"},
		{token: "ip4x"},
		{token: ""},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			proto, ok := ipfw.ParseProtoIP(tc.token)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.proto, proto)
		})
	}
}

// verifies that every byte value formatted in decimal parses as a number.
func Test_ParseProtocols_NumberRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		number := rapid.Uint8().Draw(t, "number")
		text := strconv.FormatUint(uint64(number), 10)
		var state ipfw.CollectState
		n, err := ipfw.ParseProtocols(text+" x", &state)
		require.NoError(t, err)
		require.Equal(t, len(text), n)
		require.Equal(t, protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Number: number}}), state)
	})
}

// verifies that a lowercase word parses as a name unless it is an IP
// version keyword.
func Test_ParseProtocols_NameRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[a-z]{1,6}`).Draw(t, "name")
		if _, keyword := ipfw.ParseProtoIP(name); keyword {
			t.Skip("an IP version keyword")
		}
		var state ipfw.CollectState
		n, err := ipfw.ParseProtocols(name+" x", &state)
		require.NoError(t, err)
		require.Equal(t, len(name), n)
		require.Equal(t, protos(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: name}}), state)
	})
}

// verifies that protocol parsing into a warmed-up state allocates nothing,
// groups included.
func Test_ParseProtocols_NoAllocs(t *testing.T) {
	for _, input := range []string{"not tcp from", "{ not ip or tcp or 17 } from"} {
		var state ipfw.CollectState
		_, _ = ipfw.ParseProtocols(input, &state)
		ok := true
		allocs := testing.AllocsPerRun(100, func() {
			state.Reset()
			if _, err := ipfw.ParseProtocols(input, &state); err != nil {
				ok = false
			}
		})
		require.True(t, ok, input)
		require.Zero(t, allocs, input)
	}
}
