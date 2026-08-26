package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

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
