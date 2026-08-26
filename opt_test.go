package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// dstPort is a dst-port option for one numeric port.
func dstPort(number uint16) ipfw.Opt {
	port := ipfw.Port{Number: number}
	return ipfw.Opt{Kind: ipfw.OptDestinationPort, Ports: ipfw.PortRange{Lo: port, Hi: port}}
}

// srcPort is a src-port option for one numeric port.
func srcPort(number uint16) ipfw.Opt {
	port := ipfw.Port{Number: number}
	return ipfw.Opt{Kind: ipfw.OptSourcePort, Ports: ipfw.PortRange{Lo: port, Hi: port}}
}

// typeSet is the set of the given ICMP or ICMPv6 type numbers.
func typeSet(types ...uint8) ipfw.TypeSet {
	var set ipfw.TypeSet
	for _, ty := range types {
		set.Add(ty)
	}
	return set
}

// icmpTypes is an icmptypes option for the given type numbers.
func icmpTypes(types ...uint8) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptICMPTypes, Types: typeSet(types...)}
}

// icmp6Types is an icmp6types option for the given type numbers.
func icmp6Types(types ...uint8) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptICMP6Types, Types: typeSet(types...)}
}

// notOpt is the option with its negation set.
func notOpt(opt ipfw.Opt) ipfw.Opt {
	opt.Neg = true
	return opt
}

// orOpt is the option joined to the previous one.
func orOpt(opt ipfw.Opt) ipfw.Opt {
	opt.Or = true
	return opt
}

// OnOption implements State.
func (m rejectingState) OnOption(ipfw.Opt) error {
	return m.err
}

// verifies that every option kind renders its ipfw keyword and the zero
// value renders nothing.
func Test_OptKind_String(t *testing.T) {
	cases := []struct {
		name    string
		kind    ipfw.OptKind
		keyword string
	}{
		{name: "comment", kind: ipfw.OptComment, keyword: "//"},
		{name: "diverted", kind: ipfw.OptDiverted, keyword: "diverted"},
		{name: "source port", kind: ipfw.OptSourcePort, keyword: "src-port"},
		{name: "destination port", kind: ipfw.OptDestinationPort, keyword: "dst-port"},
		{name: "established", kind: ipfw.OptEstablished, keyword: "established"},
		{name: "frag", kind: ipfw.OptFrag, keyword: "frag"},
		{name: "icmp types", kind: ipfw.OptICMPTypes, keyword: "icmptypes"},
		{name: "icmp6 types", kind: ipfw.OptICMP6Types, keyword: "icmp6types"},
		{name: "in", kind: ipfw.OptIn, keyword: "in"},
		{name: "out", kind: ipfw.OptOut, keyword: "out"},
		{name: "keep-state", kind: ipfw.OptKeepState, keyword: "keep-state"},
		{name: "proto", kind: ipfw.OptProto, keyword: "proto"},
		{name: "tcpflags", kind: ipfw.OptTCPFlags, keyword: "tcpflags"},
		{name: "via", kind: ipfw.OptVia, keyword: "via"},
		{name: "antispoof", kind: ipfw.OptAntiSpoof, keyword: "antispoof"},
		{name: "custom", kind: ipfw.OptCustom, keyword: "custom"},
		{name: "zero value", kind: 0, keyword: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.keyword, tc.kind.String())
		})
	}
}

// verifies that the option list runs up to the end of the line or an inline
// comment and that anything else in it is an unknown option at its token.
//
// Each option is handed to the state as it is read.
func Test_ParseOptions_Table(t *testing.T) {
	established := ipfw.Opt{Kind: ipfw.OptEstablished}
	cases := []struct {
		name    string
		input   string
		n       int
		err     error
		options []ipfw.Opt
	}{
		{name: "established", input: "established", n: 11, options: []ipfw.Opt{established}},
		{
			name:    "established before a newline",
			input:   "established\n",
			n:       11,
			options: []ipfw.Opt{established},
		},
		{
			name:    "whitespace before a comment is consumed",
			input:   "established // c",
			n:       12,
			options: []ipfw.Opt{established},
		},
		{
			name:    "trailing whitespace is consumed",
			input:   "established  ",
			n:       13,
			options: []ipfw.Opt{established},
		},
		{
			name:    "two options",
			input:   "established established\n",
			n:       23,
			options: []ipfw.Opt{established, established},
		},
		{
			name:    "keyword matches by prefix",
			input:   "establishedx",
			n:       11,
			options: []ipfw.Opt{established},
		},
		{name: "empty input", input: "", n: 0},
		{name: "newline alone", input: "\n", n: 0},
		{name: "comment alone", input: "// c", n: 0},
		{name: "unknown option", input: "foo", n: 0, err: ipfw.ErrUnknownOption},
		{name: "port is not an option", input: "22", n: 0, err: ipfw.ErrUnknownOption},
		{
			name:    "unknown option after a known one",
			input:   "established x",
			n:       12,
			err:     ipfw.ErrUnknownOption,
			options: []ipfw.Opt{established},
		},
		{
			name:    "negated option",
			input:   "not established",
			n:       15,
			options: []ipfw.Opt{{Neg: true, Kind: ipfw.OptEstablished}},
		},
		{
			name:    "negation applies to its option only",
			input:   "not established established",
			n:       27,
			options: []ipfw.Opt{{Neg: true, Kind: ipfw.OptEstablished}, established},
		},
		{name: "negated unknown option", input: "not foo", n: 4, err: ipfw.ErrUnknownOption},
		{name: "not glued to a keyword", input: "notestablished", n: 0, err: ipfw.ErrUnknownOption},
		{name: "not alone", input: "not", n: 0, err: ipfw.ErrUnknownOption},
		{name: "nothing after not", input: "not ", n: 4, err: ipfw.ErrUnknownOption},
		{
			name:    "group of two",
			input:   "{ established or established }",
			n:       30,
			options: []ipfw.Opt{established, {Or: true, Kind: ipfw.OptEstablished}},
		},
		{
			name:    "tight group",
			input:   "{established or established}",
			n:       28,
			options: []ipfw.Opt{established, {Or: true, Kind: ipfw.OptEstablished}},
		},
		{
			name:  "group then a plain option",
			input: "{ not established or established } established",
			n:     46,
			options: []ipfw.Opt{
				{Neg: true, Kind: ipfw.OptEstablished},
				{Or: true, Kind: ipfw.OptEstablished},
				established,
			},
		},
		{
			name:    "group without or keeps the first member",
			input:   "{ established established }",
			n:       14,
			err:     ipfw.ErrExpectedOr,
			options: []ipfw.Opt{established},
		},
		{
			name:    "unclosed group keeps the first member",
			input:   "{ established",
			n:       13,
			err:     ipfw.ErrExpectedOr,
			options: []ipfw.Opt{established},
		},
		{name: "empty group", input: "{ }", n: 2, err: ipfw.ErrUnknownOption},
		{
			name:    "in",
			input:   "in",
			n:       2,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "out",
			input:   "out",
			n:       3,
			options: []ipfw.Opt{{Kind: ipfw.OptOut}},
		},
		{
			name:    "in then out",
			input:   "in out",
			n:       6,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Kind: ipfw.OptOut}},
		},
		{
			name:    "group of in and out",
			input:   "{ in or out }",
			n:       13,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Or: true, Kind: ipfw.OptOut}},
		},
		{
			name:    "frag",
			input:   "frag",
			n:       4,
			options: []ipfw.Opt{{Kind: ipfw.OptFrag}},
		},
		{
			name:    "diverted",
			input:   "diverted",
			n:       8,
			options: []ipfw.Opt{{Kind: ipfw.OptDiverted}},
		},
		{
			name:    "negated diverted",
			input:   "not diverted",
			n:       12,
			options: []ipfw.Opt{{Neg: true, Kind: ipfw.OptDiverted}},
		},
		{
			name:    "antispoof",
			input:   "antispoof",
			n:       9,
			options: []ipfw.Opt{{Kind: ipfw.OptAntiSpoof}},
		},
		{
			name:    "antispoof then in",
			input:   "antispoof in",
			n:       12,
			options: []ipfw.Opt{{Kind: ipfw.OptAntiSpoof}, {Kind: ipfw.OptIn}},
		},
		{
			name:    "destination port option",
			input:   "dst-port 11995",
			n:       14,
			options: []ipfw.Opt{dstPort(11995)},
		},
		{
			name:    "source port option",
			input:   "src-port 179",
			n:       12,
			options: []ipfw.Opt{srcPort(179)},
		},
		{
			name:    "port list",
			input:   "dst-port 22,80",
			n:       14,
			options: []ipfw.Opt{dstPort(22), orOpt(dstPort(80))},
		},
		{
			name:  "port range in the list",
			input: "dst-port 22,1024-65535",
			n:     22,
			options: []ipfw.Opt{
				dstPort(22),
				{
					Or:    true,
					Kind:  ipfw.OptDestinationPort,
					Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 1024}, Hi: ipfw.Port{Number: 65535}},
				},
			},
		},
		{
			name:    "negated port list at top level is two and terms",
			input:   "not dst-port 22,80",
			n:       18,
			options: []ipfw.Opt{notOpt(dstPort(22)), notOpt(dstPort(80))},
		},
		{
			name:    "port list opening a group",
			input:   "{ dst-port 22,80 or in }",
			n:       24,
			options: []ipfw.Opt{dstPort(22), orOpt(dstPort(80)), {Or: true, Kind: ipfw.OptIn}},
		},
		{
			name:    "negated port list opening a group keeps the or",
			input:   "{ not dst-port 22,80 or in }",
			n:       28,
			options: []ipfw.Opt{notOpt(dstPort(22)), notOpt(orOpt(dstPort(80))), {Or: true, Kind: ipfw.OptIn}},
		},
		{
			name:    "port list inside a group",
			input:   "{ in or dst-port 22,80 }",
			n:       24,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, orOpt(dstPort(22)), orOpt(dstPort(80))},
		},
		{
			name:  "port option without whitespace",
			input: "dst-port",
			n:     8,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:  "port option without a port",
			input: "dst-port ",
			n:     9,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:  "port option range without its second port",
			input: "dst-port x-",
			n:     11,
			err:   ipfw.ErrExpectedPort,
		},
		{
			name:    "port option with a trailing comma",
			input:   "src-port 22,",
			n:       12,
			err:     ipfw.ErrExpectedPort,
			options: []ipfw.Opt{srcPort(22)},
		},
		{
			name:    "proto by name",
			input:   "proto tcp",
			n:       9,
			options: []ipfw.Opt{{Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "tcp"}}},
		},
		{
			name:    "proto by number",
			input:   "proto 6",
			n:       7,
			options: []ipfw.Opt{{Kind: ipfw.OptProto, Proto: ipfw.Proto{Number: 6}}},
		},
		{
			name:  "proto without whitespace",
			input: "proto",
			n:     5,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:  "proto without a protocol",
			input: "proto _",
			n:     6,
			err:   ipfw.ErrExpectedProto,
		},
		{
			name:    "keep-state",
			input:   "keep-state",
			n:       10,
			options: []ipfw.Opt{{Kind: ipfw.OptKeepState}},
		},
		{
			name:    "keep-state with a flow",
			input:   "keep-state :flow",
			n:       16,
			options: []ipfw.Opt{{Kind: ipfw.OptKeepState, Text: "flow"}},
		},
		{
			name:    "keep-state then in",
			input:   "keep-state in",
			n:       13,
			options: []ipfw.Opt{{Kind: ipfw.OptKeepState}, {Kind: ipfw.OptIn}},
		},
		{
			name:    "keep-state with an empty flow",
			input:   "keep-state :",
			n:       11,
			err:     ipfw.ErrUnknownOption,
			options: []ipfw.Opt{{Kind: ipfw.OptKeepState}},
		},
		{
			name:    "icmptypes list",
			input:   "icmptypes 3,8,11,12",
			n:       19,
			options: []ipfw.Opt{icmpTypes(3, 8, 11, 12)},
		},
		{
			name:    "icmptype single",
			input:   "icmptype 8",
			n:       10,
			options: []ipfw.Opt{icmpTypes(8)},
		},
		{
			name:    "icmptypes with the zero type",
			input:   "icmptypes 0,8",
			n:       13,
			options: []ipfw.Opt{icmpTypes(0, 8)},
		},
		{
			name:  "unknown icmp type",
			input: "icmptypes 7",
			n:     10,
			err:   ipfw.ErrUnknownICMPType,
		},
		{
			name:  "icmptypes with a trailing comma",
			input: "icmptypes 8,",
			n:     12,
			err:   ipfw.ErrExpectedU8,
		},
		{
			name:  "icmptypes overflow",
			input: "icmptypes 256",
			n:     10,
			err:   ipfw.ErrExpectedU8,
		},
		{
			name:  "icmptypes without whitespace",
			input: "icmptypes",
			n:     9,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:    "icmp6types list",
			input:   "icmp6types 128,135",
			n:       18,
			options: []ipfw.Opt{icmp6Types(128, 135)},
		},
		{
			name:    "icmp6types at the bounds",
			input:   "icmp6types 1,4,149,151,161",
			n:       26,
			options: []ipfw.Opt{icmp6Types(1, 4, 149, 151, 161)},
		},
		{
			name:  "unknown icmp6 type in the gap",
			input: "icmp6types 150",
			n:     11,
			err:   ipfw.ErrUnknownICMP6Type,
		},
		{
			name:  "unknown icmp6 type below the range",
			input: "icmp6types 5",
			n:     11,
			err:   ipfw.ErrUnknownICMP6Type,
		},
		{
			name:    "in with a suffix is in",
			input:   "inet",
			n:       2,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			n, err := ipfw.ParseOptions(tc.input, &state, nil)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.n, n)
			require.Equal(t, ipfw.ReduceState{Options: tc.options}, state)
		})
	}
}

// verifies that the type set holds any of the 256 type numbers on its
// own: adding one sets exactly that one and empties the empty flag.
func Test_TypeSet_AllValues(t *testing.T) {
	for ty := range 256 {
		var set ipfw.TypeSet
		require.True(t, set.IsEmpty())
		require.False(t, set.Has(uint8(ty)))
		set.Add(uint8(ty))
		require.False(t, set.IsEmpty())
		members := 0
		for other := range 256 {
			if set.Has(uint8(other)) {
				members++
				require.Equal(t, ty, other)
			}
		}
		require.Equal(t, 1, members)
	}
}

// verifies that an error from the state comes back as is, positioned at
// the option.
func Test_ParseOptions_StateError(t *testing.T) {
	state := rejectingState{err: ipfw.ErrExpectedOpt}
	n, err := ipfw.ParseOptions("established", state, nil)
	require.Equal(t, 0, n)
	require.Equal(t, ipfw.ErrExpectedOpt, err)
}

// verifies that parsing an option list with an or-group into a warmed-up
// state allocates nothing.
func Test_ParseOptions_Group_NoAllocs(t *testing.T) {
	input := "{ not established or established } established\n"
	var state ipfw.ReduceState
	_, _ = ipfw.ParseOptions(input, &state, nil)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		state.Reset()
		n, err := ipfw.ParseOptions(input, &state, nil)
		if err != nil || n != 46 {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
