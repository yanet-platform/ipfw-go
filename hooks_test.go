package ipfw_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// allowFromAny is a command hook for `ALLOW_FROM_ANY(PROTO, DST[, PORTS])
// [// comment]`, a syntax the parser does not know.
//
// It reduces the line to a pass rule from any with the exported
// sub-parsers.
func allowFromAny(line string, state ipfw.State) (ipfw.Record, int, error) {
	const keyword = "ALLOW_FROM_ANY("
	if !strings.HasPrefix(line, keyword) {
		return ipfw.Record{}, 0, nil
	}
	pos := len(keyword)
	n, err := ipfw.ParseProtocols(line[pos:], state)
	if err != nil {
		return ipfw.Record{}, pos + n, err
	}
	pos += n
	if !strings.HasPrefix(line[pos:], ",") {
		return ipfw.Record{}, pos, ipfw.ErrExpectedPrefix
	}
	pos = skipSpaces(line, pos+1)
	if rejected := state.OnSourceTarget(ipfw.Target{Kind: ipfw.TargetAny}); rejected != nil {
		return ipfw.Record{}, pos, rejected
	}
	n, err = ipfw.ParseDestinationTargets(line[pos:], state)
	if err != nil {
		return ipfw.Record{}, pos + n, err
	}
	pos += n
	if strings.HasPrefix(line[pos:], ",") {
		pos = skipSpaces(line, pos+1)
		n, err = ipfw.ParseDestinationPorts(line[pos:], state)
		if err != nil {
			return ipfw.Record{}, pos + n, err
		}
		pos += n
	}
	if !strings.HasPrefix(line[pos:], ")") {
		return ipfw.Record{}, pos, ipfw.ErrExpectedPrefix
	}
	pos++
	rec := ipfw.Record{
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}
	if rest := skipSpaces(line, pos); strings.HasPrefix(line[rest:], "//") {
		rec.Instruction.InlineComment = line[rest+2:]
		pos = len(line)
	}
	return rec, pos, nil
}

// skipSpaces returns the offset of the first byte after the spaces at pos.
func skipSpaces(line string, pos int) int {
	for pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
		pos++
	}
	return pos
}

// swallowing is a command hook that consumes an `IGNORE …` line without a
// record.
func swallowing(line string, _ ipfw.State) (ipfw.Record, int, error) {
	if !strings.HasPrefix(line, "IGNORE") {
		return ipfw.Record{}, 0, nil
	}
	return ipfw.Record{}, len(line), nil
}

// verifies that a command hook takes over a line the parser does not know
// and that the parser still ends the line itself.
//
// The record is completed with the position, the state is filled by the
// sub-parsers the hook calls.
func Test_CommandHook_Table(t *testing.T) {
	pass := ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}}
	cases := []struct {
		name        string
		input       string
		instruction ipfw.Instruction
		state       ipfw.ReduceState
	}{
		{
			name:        "protocol, group and range",
			input:       "ALLOW_FROM_ANY(tcp, { _VPN_LOOPBACKS_ }, 1-65535)\n",
			instruction: pass,
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_VPN_LOOPBACKS_"}},
				DestinationPorts: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1}, ipfw.Port{Number: 65535})},
			},
		},
		{
			name:  "port list and inline comment",
			input: "ALLOW_FROM_ANY(udp, { _CDN_NETS_ }, 80,443) // {\"id\": 1}\n",
			instruction: ipfw.Instruction{
				Action:        ipfw.Action{Kind: ipfw.ActionPass},
				InlineComment: " {\"id\": 1}",
			},
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "udp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_CDN_NETS_"}},
				DestinationPorts: []ipfw.PortMatch{portNumber(80), portNumber(443)},
			},
		},
		{
			name:        "no ports",
			input:       "ALLOW_FROM_ANY(esp, { _X_ })\n",
			instruction: pass,
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "esp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_X_"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input, ipfw.WithCommandHook(allowFromAny)).Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line:        1,
				Text:        strings.TrimSuffix(tc.input, "\n"),
				Kind:        ipfw.RecordInstruction,
				Instruction: tc.instruction,
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that a hook consuming a line without a record yields an empty
// record for it, the next line parsing as usual.
func Test_CommandHook_Swallowed(t *testing.T) {
	parser := ipfw.NewParser("IGNORE this line\nadd pass ip from any to any\n", ipfw.WithCommandHook(swallowing))
	next(t, parser, ipfw.Record{Line: 1, Text: "IGNORE this line", Kind: ipfw.RecordEmpty})
	var state ipfw.ReduceState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(2, "add pass ip from any to any"), *rec)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
}

// verifies the failures around a command hook.
//
// Trailing content after what it consumed, its own errors positioned where
// it says, an unhandled line, and no hook at all.
func Test_CommandHook_Errors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name     string
		input    string
		hook     ipfw.CommandHook
		expected ipfw.ParseError
	}{
		{
			name:  "trailing content after the hook",
			input: "ALLOW_FROM_ANY(esp, { _X_ }) x\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 29,
				Text:   "ALLOW_FROM_ANY(esp, { _X_ }) x",
			},
		},
		{
			name:  "error kind from the hook",
			input: "ALLOW_FROM_ANY(esp { _X_ })\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedPrefix,
				Line:   1,
				Column: 18,
				Text:   "ALLOW_FROM_ANY(esp { _X_ })",
			},
		},
		{
			name:  "error kind at a chosen offset",
			input: "CUSTOM line\n",
			hook: func(string, ipfw.State) (ipfw.Record, int, error) {
				return ipfw.Record{}, 5, ipfw.ErrExpectedCommand
			},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedCommand,
				Line:   1,
				Column: 5,
				Text:   "CUSTOM line",
			},
		},
		{
			name:  "plain error from the hook",
			input: "CUSTOM line\n",
			hook: func(string, ipfw.State) (ipfw.Record, int, error) {
				return ipfw.Record{}, 5, boom
			},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrState,
				Err:    boom,
				Line:   1,
				Column: 5,
				Text:   "CUSTOM line",
			},
		},
		{
			name:  "line the hook does not handle",
			input: "CUSTOM line\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedLine,
				Line:   1,
				Column: 0,
				Text:   "CUSTOM line",
			},
		},
		{
			name:  "no hook",
			input: "ALLOW_FROM_ANY(esp, { _X_ })\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedLine,
				Line:   1,
				Column: 0,
				Text:   "ALLOW_FROM_ANY(esp, { _X_ })",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var options []ipfw.ParserOption
			if tc.hook != nil {
				options = append(options, ipfw.WithCommandHook(tc.hook))
			}
			nextError(t, ipfw.NewParser(tc.input, options...), tc.expected)
		})
	}
}

// verifies that a line handled by a hook built from the sub-parsers parses
// into a warmed-up state without allocating.
func Test_CommandHook_NoAllocs(t *testing.T) {
	src := "ALLOW_FROM_ANY(tcp, { _VPN_LOOPBACKS_ }, 1-65535)\n"
	parser := ipfw.NewParser(src, ipfw.WithCommandHook(allowFromAny))
	var state ipfw.ReduceState
	_, _ = parser.Next(&state)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		if _, err := parser.Next(&state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
