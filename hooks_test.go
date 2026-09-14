package ipfw_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw-go"
)

// verifies that an invented command preserves borrowed tokens, implied source and option logic.
func Test_CommandHook_CompatibilitySeam(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		comment string
		inline  string
		state   ipfw.ReduceState
	}{
		{
			name:    "protocol alternatives and a custom token",
			input:   "EX_PASS({ not tcp or udp }, { custom:first }) in # note",
			comment: " note",
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{
					{Neg: true, Proto: ipfw.Proto{Name: "tcp"}},
					{Proto: ipfw.Proto{Name: "udp"}},
				},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "custom:first"}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "custom token and negated port list",
			input: "EX_PASS(tcp, { not custom:second }, not 443,8443) { in or not out }",
			state: ipfw.ReduceState{
				Protos:  []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{
					{Neg: true, Kind: ipfw.TargetCustom, Text: "custom:second"},
				},
				DestinationPorts: []ipfw.PortMatch{
					{Neg: true, Lo: ipfw.Port{Number: 443}, Hi: ipfw.Port{Number: 443}},
					{Neg: true, Lo: ipfw.Port{Number: 8443}, Hi: ipfw.Port{Number: 8443}},
				},
				Options: []ipfw.Opt{{Kind: ipfw.OptIn}, {Or: true, Neg: true, Kind: ipfw.OptOut}},
			},
		},
		{
			name:   "table target and rule comment",
			input:  "EX_PASS(ip6, { table(_EX_TABLE_) }) // note",
			inline: " note",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv6}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetTable, Text: "_EX_TABLE_"}},
			},
		},
		{
			name:   "vertical tab payload",
			input:  "EX_PASS(ip, { any }) // note\v",
			inline: " note\v",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input, ipfw.WithCommandHook(examplePass))
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line: 1, Text: testCase.input, Kind: ipfw.RecordInstruction,
				Comment: testCase.comment,
				Instruction: ipfw.Instruction{
					Action: ipfw.Action{Kind: ipfw.ActionPass}, InlineComment: testCase.inline,
				},
			}, *record)
			require.Equal(t, testCase.state, state)
			next(t, parser, eof)
		})
	}
}

// verifies that built-in labels take precedence over a recognizing command hook.
func Test_CommandHook_Label(t *testing.T) {
	const input = ":EX_HOOK# hash\n"
	for _, testCase := range []struct {
		name    string
		options []ipfw.ParserOption
		calls   int
	}{
		{name: "hook only", calls: 1},
		{name: "built-in labels", options: []ipfw.ParserOption{ipfw.WithLabels()}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			hook := func(line string, _ ipfw.State) (ipfw.Record, int, error) {
				calls++
				if line != ":EX_HOOK" {
					return ipfw.Record{}, 0, nil
				}
				return ipfw.Record{Kind: ipfw.RecordLabel, Label: line[1:]}, len(line), nil
			}
			options := append([]ipfw.ParserOption{ipfw.WithCommandHook(hook)}, testCase.options...)
			parser := ipfw.NewParser(input, options...)
			next(t, parser, ipfw.Record{
				Line: 1, Text: ":EX_HOOK# hash", Kind: ipfw.RecordLabel, Label: "EX_HOOK",
				Comment: " hash",
			})
			next(t, parser, eof)
			require.Equal(t, testCase.calls, calls)
		})
	}
}

// examplePass composes public subparsers over an invented command with grouped destinations.
func examplePass(line string, state ipfw.State) (ipfw.Record, int, error) {
	const keyword = "EX_PASS"
	if !strings.HasPrefix(line, keyword) {
		return ipfw.Record{}, 0, nil
	}
	position := len(keyword)
	if !strings.HasPrefix(line[position:], "(") {
		return ipfw.Record{}, position, ipfw.ErrExpectedPrefix
	}
	position++
	consumed, err := ipfw.ParseProtocols(line[position:], state)
	position += consumed
	if err != nil {
		return ipfw.Record{}, position, err
	}
	if !strings.HasPrefix(line[position:], ",") {
		return ipfw.Record{}, position, ipfw.ErrExpectedPrefix
	}
	position = skipSpaces(line, position+1)
	if err = state.OnSourceTarget(ipfw.Target{Kind: ipfw.TargetAny}); err != nil {
		return ipfw.Record{}, position, err
	}
	consumed, err = ipfw.ParseDestinationTargets(line[position:], state)
	position += consumed
	if err != nil {
		return ipfw.Record{}, position, err
	}
	if strings.HasPrefix(line[position:], ",") {
		position = skipSpaces(line, position+1)
		consumed, err = ipfw.ParseDestinationPorts(line[position:], state)
		position += consumed
		if err != nil {
			return ipfw.Record{}, position, err
		}
	}
	if !strings.HasPrefix(line[position:], ")") {
		return ipfw.Record{}, position, ipfw.ErrExpectedPrefix
	}
	position = skipSpaces(line, position+1)
	consumed, err = ipfw.ParseOptions(line[position:], state, nil)
	position += consumed
	if err != nil {
		return ipfw.Record{}, position, err
	}
	record := ipfw.Record{
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}
	if strings.HasPrefix(line[position:], "//") {
		record.Instruction.InlineComment = strings.TrimRight(line[position+2:], " \t\r\n\f")
		position = len(line)
	}
	return record, position, nil
}

// verifies that command failures retain exact positions and every token emitted before failure.
func Test_CommandHook_CompatibilityErrors(t *testing.T) {
	protocol := ipfw.ReduceState{Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}}}
	body := ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}
	withOption := body
	withOption.Options = []ipfw.Opt{{Kind: ipfw.OptIn}}
	cases := []struct {
		name   string
		input  string
		kind   ipfw.ErrorKind
		column int
		state  ipfw.ReduceState
	}{
		{name: "opening bracket", input: "EX_PASS tcp", kind: ipfw.ErrExpectedPrefix, column: 7},
		{
			name:   "separator",
			input:  "EX_PASS(tcp; { any })",
			kind:   ipfw.ErrExpectedPrefix,
			column: 11,
			state:  protocol,
		},
		{
			name:   "closing bracket",
			input:  "EX_PASS(tcp, { any }",
			kind:   ipfw.ErrExpectedPrefix,
			column: 20,
			state:  body,
		},
		{
			name:   "group bracket",
			input:  "EX_PASS(tcp, { any ])",
			kind:   ipfw.ErrExpectedOr,
			column: 19,
			state:  body,
		},
		{
			name:   "unknown option",
			input:  "EX_PASS(tcp, { any }) in extra",
			kind:   ipfw.ErrUnknownOption,
			column: 25,
			state:  withOption,
		},
		{name: "unknown command", input: "OTHER_PASS(tcp, { any })", kind: ipfw.ErrExpectedLine},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input, ipfw.WithCommandHook(examplePass))
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.NotNil(t, err)
			require.Equal(t, ipfw.ParseError{
				Kind: testCase.kind, Line: 1, Column: testCase.column, Text: testCase.input,
			}, *err)
			require.Equal(t, testCase.state, state)
			next(t, parser, eof)
		})
	}
}

// verifies that a callback failure is attached at the original token and skips exactly one line.
func Test_CommandHook_CompatibilityCallbackFailure(t *testing.T) {
	source := ruleset(`
		EX_PASS(tcp, { any }) in # metadata
		add check-state
	`)
	parser := ipfw.NewParser(source, ipfw.WithCommandHook(examplePass))
	cause := errors.New("example target rejected")
	state := exampleRejectedTarget{Err: cause}
	record, err := parser.Next(&state)
	require.Nil(t, record)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind: ipfw.ErrState, Err: cause, Line: 1, Column: 15,
		Text: "EX_PASS(tcp, { any }) in # metadata",
	}, *err)
	require.ErrorIs(t, err, cause)
	require.Equal(t, ipfw.ReduceState{
		Protos:  []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}, state.ReduceState)
	next(t, parser, ipfw.Record{
		Line: 2, Text: "add check-state", Kind: ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionCheckState}},
	})
	next(t, parser, eof)
}

type exampleRejectedTarget struct {
	ipfw.ReduceState
	Err error
}

// OnDestinationTarget rejects a destination with the configured cause.
func (m *exampleRejectedTarget) OnDestinationTarget(ipfw.Target) error {
	return m.Err
}

// verifies that all public command subparsers compose without allocation after sink warmup.
func Test_CommandHook_CompatibilityNoAllocs(t *testing.T) {
	const input = "EX_PASS(tcp, { custom:first }, 443) { in or not out } // note # hash\n"
	parser := ipfw.NewParser(input, ipfw.WithCommandHook(examplePass))
	var state ipfw.ReduceState
	_, err := parser.Next(&state)
	require.Nil(t, err)
	ok := true
	allocations := testing.AllocsPerRun(100, func() {
		parser.Reset(input)
		state.Reset()
		if _, err := parser.Next(&state); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocations)
}

// verifies that composed subparsers leave exact original remainders and complete raw state.
func Test_CommandHook_SubparserRemainders(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		remainder string
		consumed  int
		parse     func(string, ipfw.State) (int, error)
		state     ipfw.ReduceState
	}{
		{
			name: "protocols", input: "{ not tcp or udp }, after", remainder: ", after",
			consumed: 18, parse: ipfw.ParseProtocols,
			state: ipfw.ReduceState{Protos: []ipfw.ProtoMatch{
				{Neg: true, Proto: ipfw.Proto{Name: "tcp"}}, {Proto: ipfw.Proto{Name: "udp"}},
			}},
		},
		{
			name: "targets", input: "{ custom:first or not custom:second }, after",
			remainder: ", after", consumed: 37, parse: ipfw.ParseDestinationTargets,
			state: ipfw.ReduceState{Destinations: []ipfw.Target{
				{Kind: ipfw.TargetCustom, Text: "custom:first"},
				{Neg: true, Pattern: 1, Kind: ipfw.TargetCustom, Text: "custom:second"},
			}},
		},
		{
			name: "ports", input: "not 443,8443) after", remainder: ") after",
			consumed: 12, parse: ipfw.ParseDestinationPorts,
			state: ipfw.ReduceState{DestinationPorts: []ipfw.PortMatch{
				{Neg: true, Lo: ipfw.Port{Number: 443}, Hi: ipfw.Port{Number: 443}},
				{Neg: true, Lo: ipfw.Port{Number: 8443}, Hi: ipfw.Port{Number: 8443}},
			}},
		},
		{
			name: "options", input: "{ in or not out } // after", remainder: "// after",
			consumed: 18,
			parse: func(input string, state ipfw.State) (int, error) {
				return ipfw.ParseOptions(input, state, nil)
			},
			state: ipfw.ReduceState{Options: []ipfw.Opt{
				{Kind: ipfw.OptIn}, {Or: true, Neg: true, Kind: ipfw.OptOut},
			}},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var state ipfw.ReduceState
			consumed, err := testCase.parse(testCase.input, &state)
			require.NoError(t, err)
			require.Equal(t, testCase.consumed, consumed)
			require.Equal(t, testCase.remainder, testCase.input[consumed:])
			require.Equal(t, testCase.state, state)
		})
	}
}

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
			input:       "ALLOW_FROM_ANY(tcp, { custom:first }, 1-65535)\n",
			instruction: pass,
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "custom:first"}},
				DestinationPorts: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1}, ipfw.Port{Number: 65535})},
			},
		},
		{
			name:  "port list and inline comment",
			input: "ALLOW_FROM_ANY(udp, { custom:second }, 80,443) // {\"id\": 1}\n",
			instruction: ipfw.Instruction{
				Action:        ipfw.Action{Kind: ipfw.ActionPass},
				InlineComment: " {\"id\": 1}",
			},
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "udp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "custom:second"}},
				DestinationPorts: []ipfw.PortMatch{portNumber(80), portNumber(443)},
			},
		},
		{
			name:        "no ports",
			input:       "ALLOW_FROM_ANY(esp, { custom:first })\n",
			instruction: pass,
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "esp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "custom:first"}},
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

// verifies that command hooks receive the command prefix and keep parser-owned hash metadata.
func Test_CommandHook_HashComment(t *testing.T) {
	input := ruleset(`
		ALLOW_FROM_ANY(tcp, any, 00443) # {"id": "HOOK-7"}
		:AFTER
	`)
	var received string
	hook := func(line string, state ipfw.State) (ipfw.Record, int, error) {
		received = line
		return allowFromAny(line, state)
	}
	parser := ipfw.NewParser(input, ipfw.WithCommandHook(hook), ipfw.WithLabels())
	var state ipfw.ReduceState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, "ALLOW_FROM_ANY(tcp, any, 00443) ", received)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        `ALLOW_FROM_ANY(tcp, any, 00443) # {"id": "HOOK-7"}`,
		Kind:        ipfw.RecordInstruction,
		Comment:     ` {"id": "HOOK-7"}`,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *record)
	require.Equal(t, ipfw.ReduceState{
		Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations:     []ipfw.Target{{Kind: ipfw.TargetAny}},
		DestinationPorts: []ipfw.PortMatch{portNumber(443)},
	}, state)
	next(t, parser, ipfw.Record{Line: 2, Text: ":AFTER", Kind: ipfw.RecordLabel, Label: "AFTER"})
	next(t, parser, eof)

	parser = ipfw.NewParser("IGNORE# metadata\n", ipfw.WithCommandHook(swallowing))
	next(t, parser, ipfw.Record{
		Line:    1,
		Text:    "IGNORE# metadata",
		Kind:    ipfw.RecordEmpty,
		Comment: " metadata",
	})
	next(t, parser, eof)
}

// verifies that command-hook consumption and errors stay within the prefix before the hash.
func Test_CommandHook_HashCommentErrors(t *testing.T) {
	boom := errors.New("command failed")
	cases := []struct {
		name     string
		consumed int
		err      error
		kind     ipfw.ErrorKind
		column   int
	}{
		{
			name:     "negative consumption",
			consumed: -1,
			err:      boom,
			kind:     ipfw.ErrState,
			column:   0,
		},
		{
			name:     "error at chosen offset",
			consumed: 5,
			err:      boom,
			kind:     ipfw.ErrState,
			column:   5,
		},
		{
			name:     "error beyond prefix",
			consumed: 1000,
			err:      boom,
			kind:     ipfw.ErrState,
			column:   12,
		},
		{name: "declined command", kind: ipfw.ErrExpectedLine},
		{
			name:     "partial command",
			consumed: 6,
			kind:     ipfw.ErrExpectedNewlineOrEOF,
			column:   7,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := ruleset(`
				CUSTOM line # metadata
				:AFTER
			`)
			hook := func(line string, _ ipfw.State) (ipfw.Record, int, error) {
				require.Equal(t, "CUSTOM line ", line)
				return ipfw.Record{}, testCase.consumed, testCase.err
			}
			parser := ipfw.NewParser(input, ipfw.WithCommandHook(hook), ipfw.WithLabels())
			nextError(t, parser, ipfw.ParseError{
				Kind:   testCase.kind,
				Err:    testCase.err,
				Line:   1,
				Column: testCase.column,
				Text:   "CUSTOM line # metadata",
			})
			next(t, parser, ipfw.Record{
				Line:  2,
				Text:  ":AFTER",
				Kind:  ipfw.RecordLabel,
				Label: "AFTER",
			})
			next(t, parser, eof)
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
			input: "ALLOW_FROM_ANY(esp, { custom:first }) x\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 38,
				Text:   "ALLOW_FROM_ANY(esp, { custom:first }) x",
			},
		},
		{
			name:  "error kind from the hook",
			input: "ALLOW_FROM_ANY(esp { custom:first })\n",
			hook:  allowFromAny,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedPrefix,
				Line:   1,
				Column: 18,
				Text:   "ALLOW_FROM_ANY(esp { custom:first })",
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
			input: "ALLOW_FROM_ANY(esp, { custom:first })\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedLine,
				Line:   1,
				Column: 0,
				Text:   "ALLOW_FROM_ANY(esp, { custom:first })",
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
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "plain",
			input: "ALLOW_FROM_ANY(tcp, { custom:first }, 1-65535)\n",
		},
		{
			name:  "hash comment",
			input: "ALLOW_FROM_ANY(tcp, { custom:first }, 1-65535) # metadata\r\n",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input, ipfw.WithCommandHook(allowFromAny))
			var state ipfw.ReduceState
			_, err := parser.Next(&state)
			require.Nil(t, err)
			ok := true
			allocations := testing.AllocsPerRun(100, func() {
				parser.Reset(testCase.input)
				state.Reset()
				if _, err := parser.Next(&state); err != nil {
					ok = false
				}
			})
			require.True(t, ok)
			require.Zero(t, allocations)
		})
	}
}

// customOptions is an option hook for two options the grammar does not
// know: the keyword `setup` and `uid NAME`.
func customOptions(rest string) (ipfw.Opt, int, error) {
	if strings.HasPrefix(rest, "setup") {
		return ipfw.Opt{Kind: ipfw.OptCustom, Text: "setup"}, len("setup"), nil
	}
	if strings.HasPrefix(rest, "uid ") {
		name := rest[len("uid "):]
		if end := strings.IndexAny(name, " \t\n}"); end >= 0 {
			name = name[:end]
		}
		if name == "" {
			return ipfw.Opt{}, len("uid "), ipfw.ErrExpectedOpt
		}
		return ipfw.Opt{Kind: ipfw.OptCustom, Text: "uid", Arg: name}, len("uid ") + len(name), nil
	}
	return ipfw.Opt{}, 0, nil
}

// verifies that an option hook takes the keywords the grammar does not
// know in every place an option can stand.
//
// The parser owns the negation and grouping flags, and the hook takes part
// in the option-versus-port precedence.
func Test_OptionHook_Table(t *testing.T) {
	anyToAny := []ipfw.Target{{Kind: ipfw.TargetAny}}
	tcp := []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}}
	setup := ipfw.Opt{Kind: ipfw.OptCustom, Text: "setup"}
	cases := []struct {
		name    string
		input   string
		hook    ipfw.OptionHook
		options []ipfw.Opt
	}{
		{
			name:    "keyword then a known option",
			input:   "add allow tcp from any to any setup in\n",
			options: []ipfw.Opt{setup, {Kind: ipfw.OptIn}},
		},
		{
			name:    "keyword in a group",
			input:   "add allow tcp from any to any { setup or in }\n",
			options: []ipfw.Opt{setup, {Or: true, Kind: ipfw.OptIn}},
		},
		{
			name:    "negated keyword",
			input:   "add allow tcp from any to any not setup\n",
			options: []ipfw.Opt{notOpt(setup)},
		},
		{
			name:    "option with an argument",
			input:   "add allow tcp from any to any uid root established\n",
			options: []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "uid", Arg: "root"}, {Kind: ipfw.OptEstablished}},
		},
		{
			name:    "keyword alone is an option, not a port",
			input:   "add allow tcp from any to any setup\n",
			options: []ipfw.Opt{setup},
		},
		{
			name:  "hook-provided port option cannot continue the preceding list",
			input: "add allow tcp from any to any dst-port 22 setup\n",
			hook: func(string) (ipfw.Opt, int, error) {
				opt := dstPort(80)
				opt.PortOr = true
				return opt, len("setup"), nil
			},
			options: []ipfw.Opt{dstPort(22), dstPort(80)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hook := tc.hook
			if hook == nil {
				hook = customOptions
			}
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input, ipfw.WithOptionHook(hook)).Next(&state)
			require.Nil(t, err)
			require.Equal(t, passAnyToAny(1, strings.TrimSuffix(tc.input, "\n")), *rec)
			require.Equal(t, ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      tc.options,
			}, state)
		})
	}
}

// verifies that the hook is consulted for unknown keywords only.
func Test_OptionHook_Precedence(t *testing.T) {
	calls := 0
	counting := func(rest string) (ipfw.Opt, int, error) {
		calls++
		return customOptions(rest)
	}
	input := "add allow tcp from any to any " +
		"in established estab fragment tcpflgs syn,!ack icmp6type 128,129\n"
	var state ipfw.ReduceState
	_, err := ipfw.NewParser(input, ipfw.WithOptionHook(counting)).Next(&state)
	require.Nil(t, err)
	require.Equal(t, 0, calls)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		Options: []ipfw.Opt{
			{Kind: ipfw.OptIn},
			{Kind: ipfw.OptEstablished},
			{Kind: ipfw.OptEstablished},
			{Kind: ipfw.OptFrag},
			tcpFlags(ipfw.TCPSyn, ipfw.TCPAck),
			icmp6Types(128, 129),
		},
	}, state)

	_, err = ipfw.NewParser("add allow tcp from any to any setup\n", ipfw.WithOptionHook(counting)).
		Next(ipfw.DiscardState{})
	require.Nil(t, err)
	require.Positive(t, calls)
}

// verifies that option hooks cannot consume hash payloads or following physical lines.
func Test_OptionHook_HashComment(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		hookInput string
		expected  ipfw.Record
	}{
		{
			name:      "hash on this line",
			input:     "add pass ip from any to any custom # metadata\r\n:AFTER# next\n",
			hookInput: "custom ",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any custom # metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     " metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
		},
		{
			name: "hash on next line after LF",
			input: ruleset(`
				add pass ip from any to any custom
				:AFTER# next
			`),
			hookInput: "custom\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any custom",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
		},
		{
			name:      "hash on next line after CRLF",
			input:     "add pass ip from any to any custom\r\n:AFTER# next\n",
			hookInput: "custom\r\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any custom",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			option := ipfw.Opt{Kind: ipfw.OptCustom, Text: "custom"}
			calls := 0
			hook := func(rest string) (ipfw.Opt, int, error) {
				calls++
				require.Equal(t, testCase.hookInput, rest)
				return option, 1000, nil
			}
			parser := ipfw.NewParser(testCase.input, ipfw.WithOptionHook(hook), ipfw.WithLabels())
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Positive(t, calls)
			require.Equal(t, testCase.expected, *record)
			expectedState := anyToAnyState(ipfw.ProtoIPAny)
			expectedState.Options = []ipfw.Opt{option}
			require.Equal(t, expectedState, state)
			next(t, parser, ipfw.Record{
				Line:    2,
				Text:    ":AFTER# next",
				Kind:    ipfw.RecordLabel,
				Comment: " next",
				Label:   "AFTER",
			})
			next(t, parser, eof)
		})
	}
}

// verifies that option-hook failures retain the original text and prefix-relative positions.
func Test_OptionHook_HashCommentErrors(t *testing.T) {
	cases := []struct {
		name     string
		consumed int
		column   int
	}{
		{name: "negative consumption", consumed: -1, column: 28},
		{name: "error at chosen offset", consumed: 2, column: 30},
		{name: "error beyond prefix", consumed: 1000, column: 35},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := ruleset(`
				add pass ip from any to any custom # metadata
				:AFTER
			`)
			hook := func(rest string) (ipfw.Opt, int, error) {
				require.Equal(t, "custom ", rest)
				return ipfw.Opt{}, testCase.consumed, ipfw.ErrExpectedOpt
			}
			parser := ipfw.NewParser(input, ipfw.WithOptionHook(hook), ipfw.WithLabels())
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.NotNil(t, err)
			require.Equal(t, ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOpt,
				Line:   1,
				Column: testCase.column,
				Text:   "add pass ip from any to any custom # metadata",
			}, *err)
			require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
			next(t, parser, ipfw.Record{
				Line:  2,
				Text:  ":AFTER",
				Kind:  ipfw.RecordLabel,
				Label: "AFTER",
			})
			next(t, parser, eof)
		})
	}
}

// verifies the failures around an option hook.
//
// A declined token is an unknown option, a hook error is positioned at the
// bytes it consumed, an ErrorKind keeping its kind and anything else
// becoming an ErrState.
func Test_OptionHook_Errors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name     string
		input    string
		hook     ipfw.OptionHook
		expected ipfw.ParseError
	}{
		{
			name:  "declined token",
			input: "add allow tcp from any to any established foo",
			hook:  customOptions,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 42,
				Text:   "add allow tcp from any to any established foo",
			},
		},
		{
			name:  "error kind from the hook",
			input: "add allow tcp from any to any established uid \n",
			hook:  customOptions,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOpt,
				Line:   1,
				Column: 45,
				Text:   "add allow tcp from any to any established uid",
			},
		},
		{
			name:  "plain error from the hook",
			input: "add allow tcp from any to any established zz",
			hook: func(string) (ipfw.Opt, int, error) {
				return ipfw.Opt{}, 2, boom
			},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrState,
				Err:    boom,
				Line:   1,
				Column: 44,
				Text:   "add allow tcp from any to any established zz",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input, ipfw.WithOptionHook(tc.hook)), tc.expected)
		})
	}
}

// verifies that the exported option parser passes the hook through.
func Test_ParseOptions_Hook(t *testing.T) {
	var state ipfw.ReduceState
	n, err := ipfw.ParseOptions("setup in", &state, customOptions)
	require.NoError(t, err)
	require.Equal(t, 8, n)
	require.Equal(t, ipfw.ReduceState{
		Options: []ipfw.Opt{{Kind: ipfw.OptCustom, Text: "setup"}, {Kind: ipfw.OptIn}},
	}, state)
}

// verifies that a line with custom options parses into a warmed-up state
// without allocating.
func Test_OptionHook_NoAllocs(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "plain",
			input: "add allow tcp from any to any uid root { setup or in } established\n",
		},
		{
			name: "hash comment",
			input: "add allow tcp from any to any uid root { setup or in } established " +
				"# metadata\r\n",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input, ipfw.WithOptionHook(customOptions))
			var state ipfw.ReduceState
			_, err := parser.Next(&state)
			require.Nil(t, err)
			ok := true
			allocations := testing.AllocsPerRun(100, func() {
				parser.Reset(testCase.input)
				state.Reset()
				if _, err := parser.Next(&state); err != nil {
					ok = false
				}
			})
			require.True(t, ok)
			require.Zero(t, allocations)
		})
	}
}
