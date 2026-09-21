package ipfw_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw-go"
)

// comment is a `//` option with the text after the slashes.
func comment(text string) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptComment, Text: text}
}

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

// tcpFlags is a tcpflags option with independent set and clear requirements.
func tcpFlags(set, clear ipfw.TCPFlag) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptTCPFlags, TCPFlags: ipfw.TCPFlags{Set: set, Clear: clear}}
}

// viaExact is a via option naming one interface.
func viaExact(name string) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptVia, Via: ipfw.Via{Kind: ipfw.ViaExact, Name: name}}
}

// viaMask is a via option with an interface mask.
func viaMask(pattern string) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptVia, Via: ipfw.Via{Kind: ipfw.ViaMask, Name: pattern}}
}

// viaTable is a via option looking the interface up in a table.
func viaTable(name, value string) ipfw.Opt {
	return ipfw.Opt{Kind: ipfw.OptVia, Via: ipfw.Via{Kind: ipfw.ViaTable, Name: name, Value: value}}
}

// notOpt is the option with its negation set.
func notOpt(opt ipfw.Opt) ipfw.Opt {
	opt.Neg = true
	return opt
}

// at is the option placed in the or-block and the match pattern.
func at(block, pattern uint16, opt ipfw.Opt) ipfw.Opt {
	opt.Block, opt.Pattern = block, pattern
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

// verifies that the option list runs up to the end of the line, a comment
// taking the rest of it, and that anything else in it is an unknown option at
// its token.
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
		{name: "estab alias", input: "estab", n: 5, options: []ipfw.Opt{established}},
		{
			name:    "fragment alias",
			input:   "fragment",
			n:       8,
			options: []ipfw.Opt{{Kind: ipfw.OptFrag}},
		},
		{
			name:    "tcpflgs alias",
			input:   "tcpflgs syn,!ack",
			n:       16,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPAck)},
		},
		{
			name:    "icmp6type alias",
			input:   "icmp6type 128,129",
			n:       17,
			options: []ipfw.Opt{icmp6Types(128, 129)},
		},
		{
			name: "aliases preserve lists negation grouping and the following option",
			input: "{ not estab or fragment } not tcpflgs syn, !ack " +
				"{ in or not icmp6type 128, 129 } out",
			n: 84,
			options: []ipfw.Opt{
				notOpt(established),
				{Pattern: 1, Kind: ipfw.OptFrag},
				at(1, 0, notOpt(tcpFlags(ipfw.TCPSyn, ipfw.TCPAck))),
				{Block: 2, Kind: ipfw.OptIn},
				at(2, 1, notOpt(icmp6Types(128, 129))),
				{Block: 3, Kind: ipfw.OptOut},
			},
		},
		{
			name:  "estab alias with a suffix",
			input: "estabx",
			err:   ipfw.ErrUnknownOption,
		},
		{
			name:    "fragment alias before a comment",
			input:   "fragment // c",
			n:       13,
			options: []ipfw.Opt{{Kind: ipfw.OptFrag}, at(1, 0, comment(" c"))},
		},
		{
			name:    "tcpflgs alias before a newline",
			input:   "tcpflgs syn\n",
			n:       11,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, 0)},
		},
		{
			name:    "icmp6types before an argument suffix",
			input:   "icmp6types 128x",
			n:       14,
			options: []ipfw.Opt{icmp6Types(128)},
		},
		{
			name:    "icmp6type alias before an argument suffix",
			input:   "icmp6type 128x",
			n:       13,
			options: []ipfw.Opt{icmp6Types(128)},
		},
		{
			name:  "tcpflgs alias without whitespace",
			input: "tcpflgs",
			n:     7,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:    "tcpflgs alias invalid later flag preserves only the preceding option",
			input:   "in tcpflgs syn,!bogus out",
			n:       16,
			err:     ipfw.ErrUnknownTCPFlag,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:  "icmp6type alias without whitespace",
			input: "icmp6type",
			n:     9,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:  "icmp6type alias with a nonnumeric type",
			input: "icmp6type bogus",
			n:     10,
			err:   ipfw.ErrExpectedU8,
		},
		{
			name:    "icmp6type alias invalid later item preserves only the preceding option",
			input:   "in icmp6type 128, 202 out",
			n:       18,
			err:     ipfw.ErrUnknownICMP6Type,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "established before a newline",
			input:   "established\n",
			n:       11,
			options: []ipfw.Opt{established},
		},
		{
			name:    "trailing whitespace leaves CRLF and the next line untouched",
			input:   "established \t\r\nout",
			n:       13,
			options: []ipfw.Opt{established},
		},
		{
			name:    "comment after an option",
			input:   "established // c",
			n:       16,
			options: []ipfw.Opt{established, at(1, 0, comment(" c"))},
		},
		{
			name:    "comment takes the options after it",
			input:   "// in not out \t",
			n:       15,
			options: []ipfw.Opt{comment(" in not out")},
		},
		{
			name:    "comment stops before CRLF",
			input:   "// c \r\nout",
			n:       5,
			options: []ipfw.Opt{comment(" c")},
		},
		{
			name:    "comment keeps a lone carriage return",
			input:   "// a\rb\n",
			n:       6,
			options: []ipfw.Opt{comment(" a\rb")},
		},
		{
			name:    "empty comment",
			input:   "//",
			n:       2,
			options: []ipfw.Opt{comment("")},
		},
		{
			name:    "negated comment",
			input:   "not // c",
			n:       8,
			options: []ipfw.Opt{{Neg: true, Kind: ipfw.OptComment, Text: " c"}},
		},
		{
			name:  "comment leaves its group open",
			input: "{ in or // c }",
			n:     14,
			err:   ipfw.ErrExpectedOr,
			options: []ipfw.Opt{
				{Kind: ipfw.OptIn},
				{Pattern: 1, Kind: ipfw.OptComment, Text: " c }"},
			},
		},
		{name: "lone slash", input: "/ c", n: 0, err: ipfw.ErrUnknownOption},
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
			options: []ipfw.Opt{established, at(1, 0, established)},
		},
		{
			name:  "keyword with a suffix",
			input: "establishedx",
			err:   ipfw.ErrUnknownOption,
		},
		{name: "empty input", input: "", n: 0},
		{name: "newline alone", input: "\n", n: 0},
		{name: "CRLF before another line", input: "\r\nout", n: 0},
		{name: "comment alone", input: "// c", n: 4, options: []ipfw.Opt{comment(" c")}},
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
			name:    "lone carriage return after an option is rejected",
			input:   "in \r",
			n:       3,
			err:     ipfw.ErrUnknownOption,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "unknown option before CRLF is rejected",
			input:   "in bogus\r\n",
			n:       3,
			err:     ipfw.ErrUnknownOption,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
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
			options: []ipfw.Opt{{Neg: true, Kind: ipfw.OptEstablished}, at(1, 0, established)},
		},
		{name: "negated unknown option", input: "not foo", n: 4, err: ipfw.ErrUnknownOption},
		{name: "not glued to a keyword", input: "notestablished", n: 0, err: ipfw.ErrUnknownOption},
		{name: "not alone", input: "not", n: 0, err: ipfw.ErrUnknownOption},
		{name: "nothing after not", input: "not ", n: 4, err: ipfw.ErrUnknownOption},
		{
			name:    "group of two",
			input:   "{ established or established }",
			n:       30,
			options: []ipfw.Opt{established, {Pattern: 1, Kind: ipfw.OptEstablished}},
		},
		{
			name:    "group of two with the pipe",
			input:   "{ established | established }",
			n:       29,
			options: []ipfw.Opt{established, {Pattern: 1, Kind: ipfw.OptEstablished}},
		},
		{
			name:    "tight group",
			input:   "{established or established}",
			n:       28,
			options: []ipfw.Opt{established, {Pattern: 1, Kind: ipfw.OptEstablished}},
		},
		{
			name:    "tight group closure",
			input:   "{in}",
			n:       4,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "tight pipe separator",
			input:   "{ in| out }",
			n:       11,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Pattern: 1, Kind: ipfw.OptOut}},
		},
		{
			name:  "group then a plain option",
			input: "{ not established or established } established",
			n:     46,
			options: []ipfw.Opt{
				{Neg: true, Kind: ipfw.OptEstablished},
				{Pattern: 1, Kind: ipfw.OptEstablished},
				at(1, 0, established),
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
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Block: 1, Kind: ipfw.OptOut}},
		},
		{
			name:    "group of in and out",
			input:   "{ in or out }",
			n:       13,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Pattern: 1, Kind: ipfw.OptOut}},
		},
		{
			name:    "group with trailing space leaves CRLF untouched",
			input:   "{ in or out } \r\nfrag",
			n:       14,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Pattern: 1, Kind: ipfw.OptOut}},
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
			options: []ipfw.Opt{{Kind: ipfw.OptAntiSpoof}, {Block: 1, Kind: ipfw.OptIn}},
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
			name:    "second port shares the pattern of the list",
			input:   "dst-port 22,80",
			n:       14,
			options: []ipfw.Opt{dstPort(22), dstPort(80)},
		},
		{
			name:  "second range shares the pattern of the list",
			input: "dst-port 22,1024-65535",
			n:     22,
			options: []ipfw.Opt{
				dstPort(22),
				{
					Kind:  ipfw.OptDestinationPort,
					Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 1024}, Hi: ipfw.Port{Number: 65535}},
				},
			},
		},
		{
			name:    "negated port list at top level is atomic",
			input:   "not dst-port 22,80",
			n:       18,
			options: []ipfw.Opt{notOpt(dstPort(22)), notOpt(dstPort(80))},
		},
		{
			name:  "group-leading list shares one pattern before the next alternative",
			input: "{ dst-port 22,80 or in }",
			n:     24,
			options: []ipfw.Opt{
				dstPort(22),
				dstPort(80),
				{Pattern: 1, Kind: ipfw.OptIn},
			},
		},
		{
			name:  "negated port list opening a group stays atomic",
			input: "{ not dst-port 22,80 or in }",
			n:     28,
			options: []ipfw.Opt{
				notOpt(dstPort(22)),
				notOpt(dstPort(80)),
				{Pattern: 1, Kind: ipfw.OptIn},
			},
		},
		{
			name:  "group-trailing list shares the pattern after the first alternative",
			input: "{ in or dst-port 22,80 }",
			n:     24,
			options: []ipfw.Opt{
				{Kind: ipfw.OptIn},
				at(0, 1, dstPort(22)),
				at(0, 1, dstPort(80)),
			},
		},
		{
			name:  "group-trailing negated list stays atomic",
			input: "{ in or not dst-port 22,80 }",
			n:     28,
			options: []ipfw.Opt{
				{Kind: ipfw.OptIn},
				at(0, 1, notOpt(dstPort(22))),
				at(0, 1, notOpt(dstPort(80))),
			},
		},
		{
			name:  "adjacent destination port options stay separate",
			input: "{ not dst-port 22,80 or dst-port 81 }",
			n:     37,
			options: []ipfw.Opt{
				notOpt(dstPort(22)),
				notOpt(dstPort(80)),
				at(0, 1, dstPort(81)),
			},
		},
		{
			name:  "blocks count up and patterns restart in every block",
			input: "in { out or frag } not established { via eth0 or dst-port 22,80 }",
			n:     65,
			options: []ipfw.Opt{
				{Kind: ipfw.OptIn},
				{Block: 1, Kind: ipfw.OptOut},
				{Block: 1, Pattern: 1, Kind: ipfw.OptFrag},
				{Neg: true, Block: 2, Kind: ipfw.OptEstablished},
				at(3, 0, viaExact("eth0")),
				at(3, 1, dstPort(22)),
				at(3, 1, dstPort(80)),
			},
		},
		{
			name:  "lists in separate blocks keep their own patterns",
			input: "dst-port 22,80 not src-port 1024-65535,8080",
			n:     43,
			options: []ipfw.Opt{
				dstPort(22),
				dstPort(80),
				{
					Neg:   true,
					Block: 1,
					Kind:  ipfw.OptSourcePort,
					Ports: ipfw.PortRange{Lo: ipfw.Port{Number: 1024}, Hi: ipfw.Port{Number: 65535}},
				},
				at(1, 0, notOpt(srcPort(8080))),
			},
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
			options: []ipfw.Opt{srcPort(22)},
		},
		{
			name:    "port option with a spaced list",
			input:   "dst-port 22, 80",
			n:       15,
			options: []ipfw.Opt{dstPort(22), dstPort(80)},
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
			name:    "proto zero is a name",
			input:   "proto 0",
			n:       7,
			options: []ipfw.Opt{{Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "0"}}},
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
			options: []ipfw.Opt{{Kind: ipfw.OptKeepState}, {Block: 1, Kind: ipfw.OptIn}},
		},
		{
			name:    "duplicate keep-state",
			input:   "in keep-state keep-state out",
			n:       14,
			err:     ipfw.ErrDuplicateDynamicState,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Block: 1, Kind: ipfw.OptKeepState}},
		},
		{
			name:  "keep-state first in a group",
			input: "{ keep-state or in }",
			n:     2,
			err:   ipfw.ErrDynamicStateInGroup,
		},
		{
			name:    "keep-state after an option in a group",
			input:   "{ in or keep-state }",
			n:       8,
			err:     ipfw.ErrDynamicStateInGroup,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
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
			name:    "icmptypes numeric range followed by an option",
			input:   "icmptypes 0,7,31 in",
			n:       19,
			options: []ipfw.Opt{icmpTypes(0, 7, 31), {Block: 1, Kind: ipfw.OptIn}},
		},
		{
			name:  "icmptypes at the uint8 maximum",
			input: "icmptypes 255",
			n:     10,
			err:   ipfw.ErrUnknownICMPType,
		},
		{
			name:    "icmptypes invalid later item preserves only the preceding option",
			input:   "in icmptypes 7, 32 out",
			n:       16,
			err:     ipfw.ErrUnknownICMPType,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "icmptypes with a trailing comma",
			input:   "icmptypes 8,",
			n:       12,
			options: []ipfw.Opt{icmpTypes(8)},
		},
		{
			name:    "icmptypes with a spaced list",
			input:   "icmptypes 3, 8",
			n:       14,
			options: []ipfw.Opt{icmpTypes(3, 8)},
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
			name:    "icmp6types assigned values",
			input:   "icmp6types 1,4,149,151,161",
			n:       26,
			options: []ipfw.Opt{icmp6Types(1, 4, 149, 151, 161)},
		},
		{
			name:    "icmp6types in the former gap",
			input:   "icmp6types 150",
			n:       14,
			options: []ipfw.Opt{icmp6Types(150)},
		},
		{
			name:    "icmp6types numeric range followed by an option",
			input:   "icmp6types 0,5,150,201 in",
			n:       25,
			options: []ipfw.Opt{icmp6Types(0, 5, 150, 201), {Block: 1, Kind: ipfw.OptIn}},
		},
		{
			name:  "icmp6types at the uint8 maximum",
			input: "icmp6types 255",
			n:     11,
			err:   ipfw.ErrUnknownICMP6Type,
		},
		{
			name:    "icmp6types invalid later item preserves only the preceding option",
			input:   "in icmp6types 150, 202 out",
			n:       19,
			err:     ipfw.ErrUnknownICMP6Type,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "icmp6types later overflow preserves only the preceding option",
			input:   "in icmp6types 201, 256 out",
			n:       19,
			err:     ipfw.ErrExpectedU8,
			options: []ipfw.Opt{{Kind: ipfw.OptIn}},
		},
		{
			name:    "tcpflags single",
			input:   "tcpflags rst",
			n:       12,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPRst, 0)},
		},
		{
			name:    "tcpflags with a cleared flag",
			input:   "tcpflags syn,!ack",
			n:       17,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPAck)},
		},
		{
			name:    "tcpflags duplicate set requirement",
			input:   "tcpflags syn,syn",
			n:       16,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, 0)},
		},
		{
			name:    "tcpflags duplicate clear requirement",
			input:   "tcpflags !syn,!syn",
			n:       18,
			options: []ipfw.Opt{tcpFlags(0, ipfw.TCPSyn)},
		},
		{
			name:    "tcpflags contradictory requirements",
			input:   "tcpflags syn,!syn",
			n:       17,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPSyn)},
		},
		{
			name:  "tcpflags all six",
			input: "tcpflags fin,syn,rst,psh,ack,urg",
			n:     32,
			options: []ipfw.Opt{tcpFlags(
				ipfw.TCPFin|ipfw.TCPSyn|ipfw.TCPRst|ipfw.TCPPsh|ipfw.TCPAck|ipfw.TCPUrg,
				0,
			)},
		},
		{
			name:    "tcpflags all cleared",
			input:   "tcpflags !fin,!urg",
			n:       18,
			options: []ipfw.Opt{tcpFlags(0, ipfw.TCPFin|ipfw.TCPUrg)},
		},
		{
			name:  "unknown tcp flag",
			input: "tcpflags foo",
			n:     9,
			err:   ipfw.ErrUnknownTCPFlag,
		},
		{
			name:  "tcpflags with a bare bang",
			input: "tcpflags !",
			n:     10,
			err:   ipfw.ErrUnknownTCPFlag,
		},
		{
			name:    "tcpflags with a trailing comma",
			input:   "tcpflags syn,",
			n:       13,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, 0)},
		},
		{
			name:    "tcpflags with a spaced list",
			input:   "tcpflags syn, !ack",
			n:       18,
			options: []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPAck)},
		},
		{
			name:  "tcpflags without whitespace",
			input: "tcpflags",
			n:     8,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:    "via exact name",
			input:   "via tun0",
			n:       8,
			options: []ipfw.Opt{viaExact("tun0")},
		},
		{
			name:    "via mask with a star",
			input:   "via tun*",
			n:       8,
			options: []ipfw.Opt{viaMask("tun*")},
		},
		{
			name:    "via mask with question marks",
			input:   "via mce??88",
			n:       11,
			options: []ipfw.Opt{viaMask("mce??88")},
		},
		{
			name:    "via mask with a negated class",
			input:   "via tun[!a]",
			n:       11,
			options: []ipfw.Opt{viaMask("tun[!a]")},
		},
		{
			name:    "via name stops at a slash",
			input:   "via eth0/1",
			n:       8,
			options: []ipfw.Opt{viaExact("eth0")},
		},
		{
			name:    "via then in",
			input:   "via eth0 in",
			n:       11,
			options: []ipfw.Opt{viaExact("eth0"), {Block: 1, Kind: ipfw.OptIn}},
		},
		{
			name:  "group of via masks",
			input: "{ via vlan1?? or via vlan2??? or via eth??3??? }",
			n:     48,
			options: []ipfw.Opt{
				viaMask("vlan1??"),
				at(0, 1, viaMask("vlan2???")),
				at(0, 2, viaMask("eth??3???")),
			},
		},
		{
			name:    "via mask with repeated stars",
			input:   "via tun**",
			n:       9,
			options: []ipfw.Opt{viaMask("tun**")},
		},
		{
			name:    "via mask with an unclosed class",
			input:   "via lan[0",
			n:       9,
			options: []ipfw.Opt{viaMask("lan[0")},
		},
		{
			name:    "via mask with an unclosed negated class",
			input:   "via tun[!",
			n:       9,
			options: []ipfw.Opt{viaMask("tun[!")},
		},
		{
			name:    "via mask with an empty class",
			input:   "via tun[]",
			n:       9,
			options: []ipfw.Opt{viaMask("tun[]")},
		},
		{
			name:  "via without whitespace",
			input: "via",
			n:     3,
			err:   ipfw.ErrExpectedWhitespace,
		},
		{
			name:  "via without a name",
			input: "via {",
			n:     4,
			err:   ipfw.ErrExpectedOpt,
		},
		{
			name:    "via table",
			input:   "via table(_JUMP_IN_)",
			n:       20,
			options: []ipfw.Opt{viaTable("_JUMP_IN_", "")},
		},
		{
			name:    "via table with a value",
			input:   "via table(t,:LBL)",
			n:       17,
			options: []ipfw.Opt{viaTable("t", ":LBL")},
		},
		{
			name:    "via table then in",
			input:   "via table(t) in",
			n:       15,
			options: []ipfw.Opt{viaTable("t", ""), {Block: 1, Kind: ipfw.OptIn}},
		},
		{
			name:  "via table with an empty name",
			input: "via table()",
			n:     10,
			err:   ipfw.ErrExpectedTableName,
		},
		{
			name:  "via table with an empty value",
			input: "via table(t,)",
			n:     12,
			err:   ipfw.ErrExpectedTableValue,
		},
		{
			name:  "via table without its closing parenthesis",
			input: "via table(t",
			n:     11,
			err:   ipfw.ErrExpectedPrefix,
		},
		{
			name:  "via table name stops at a space",
			input: "via table(t x)",
			n:     11,
			err:   ipfw.ErrExpectedPrefix,
		},
		{
			name:  "in with a suffix",
			input: "inet",
			err:   ipfw.ErrUnknownOption,
		},
		{name: "inhouse", input: "inhouse", err: ipfw.ErrUnknownOption},
		{name: "protohouse", input: "protohouse", err: ipfw.ErrUnknownOption},
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

// verifies that dynamic state options returned by a hook obey the same
// placement and uniqueness rules as built-in options.
func Test_ParseOptions_HookKeepState(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		n       int
		err     error
		options []ipfw.Opt
	}{
		{
			name:    "duplicate after built-in",
			input:   "keep-state state-option",
			n:       11,
			err:     ipfw.ErrDuplicateDynamicState,
			options: []ipfw.Opt{{Kind: ipfw.OptKeepState}},
		},
		{
			name:  "hook option in group",
			input: "{ state-option or in }",
			n:     2,
			err:   ipfw.ErrDynamicStateInGroup,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			n, err := ipfw.ParseOptions(tc.input, &state, stateOption)
			require.Equal(t, tc.n, n)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.options, state.Options)
		})
	}
}

func stateOption(rest string) (ipfw.Opt, int, error) {
	if !strings.HasPrefix(rest, "state-option") {
		return ipfw.Opt{}, 0, nil
	}
	return ipfw.Opt{Kind: ipfw.OptKeepState}, len("state-option"), nil
}

// verifies that parsing an option list with an or-group into a warmed-up
// state allocates nothing.
func Test_ParseOptions_Group_NoAllocs(t *testing.T) {
	input := "{ not established or established } established " +
		"estab fragment tcpflgs syn,!ack icmp6type 128,129\n"
	var state ipfw.ReduceState
	_, _ = ipfw.ParseOptions(input, &state, nil)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		state.Reset()
		n, err := ipfw.ParseOptions(input, &state, nil)
		if err != nil || n != len(input)-1 {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

// zzOption is an option hook for `zz ARG`, the argument running up to
// whitespace or a closing brace.
func zzOption(rest string) (ipfw.Opt, int, error) {
	if !strings.HasPrefix(rest, "zz ") {
		return ipfw.Opt{}, 0, nil
	}
	arg := rest[len("zz "):]
	if end := strings.IndexAny(arg, " \t\n}"); end >= 0 {
		arg = arg[:end]
	}
	if arg == "" {
		return ipfw.Opt{}, len("zz "), ipfw.ErrExpectedOpt
	}
	return ipfw.Opt{Kind: ipfw.OptCustom, Text: "zz", Arg: arg}, len("zz ") + len(arg), nil
}

func Fuzz_ParseOptions(f *testing.F) {
	f.Add("established in { not out or zz 1 } dst-port 22,80 via table(t,:L)")
	f.Add("{ not estab or fragment } tcpflgs syn,!ack icmp6type 128,129 in")
	f.Add("tcpflgs")
	f.Add("tcpflgs syn,!bogus")
	f.Add("icmp6type")
	f.Add("icmp6type 128,202")
	f.Add("tcpflags syn,!ack icmptypes 0,8 keep-state :f proto 6 zz")
	f.Add("{ not icmptypes 0,7,31 or icmp6types 0,5,150,201 } in")
	f.Add("in icmptypes 7,32")
	f.Add("in icmp6types 201,202")
	f.Add("icmptypes 256")
	f.Add("icmp6types 256")
	f.Add("{ in")
	f.Add("not ")
	f.Add("zz x // c")
	f.Fuzz(func(t *testing.T, input string) {
		var state ipfw.ReduceState
		n, err := ipfw.ParseOptions(input, &state, zzOption)
		require.GreaterOrEqual(t, n, 0)
		require.LessOrEqual(t, n, len(input))
		if err != nil {
			require.NotEmpty(t, err.Error())
		}
		dryN, dryErr := ipfw.ParseOptions(input, ipfw.DiscardState{}, zzOption)
		require.Equal(t, n, dryN, "the dry run must consume the same bytes")
		require.Equal(t, err, dryErr, "the dry run must fail the same way")
	})
}
