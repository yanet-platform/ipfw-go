package ipfw_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

var (
	_ ipfw.State = ipfw.DiscardState{}
	_ ipfw.State = (*ipfw.ReduceState)(nil)
)

// next parses one line and requires it to succeed with the given record and
// an untouched state.
func next(t *testing.T, parser *ipfw.Parser, expected ipfw.Record) {
	t.Helper()
	var state ipfw.ReduceState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, expected, *rec)
	require.Equal(t, ipfw.ReduceState{}, state)
}

// nextError parses one line and requires the given positioned failure.
func nextError(t *testing.T, parser *ipfw.Parser, expected ipfw.ParseError) {
	t.Helper()
	var state ipfw.ReduceState
	_, err := parser.Next(&state)
	require.NotNil(t, err)
	require.Equal(t, expected, *err)
}

// eof is the record every exhausted parser returns.
var eof = ipfw.Record{Kind: ipfw.RecordEOF}

// verifies that an empty input is exhausted at once and stays so.
func Test_Parser_Next_EOF(t *testing.T) {
	parser := ipfw.NewParser("")
	next(t, parser, eof)
	next(t, parser, eof)
}

// verifies that blank lines, with or without whitespace or a final newline,
// are empty records with their line numbers and an empty text.
func Test_Parser_Next_EmptyLines(t *testing.T) {
	cases := []struct {
		name  string
		input string
		lines int
	}{
		{name: "two newlines", input: "\n\n", lines: 2},
		{name: "whitespace only", input: "   \t \n", lines: 1},
		{name: "whitespace without newline", input: "  ", lines: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parser := ipfw.NewParser(tc.input)
			for line := 1; line <= tc.lines; line++ {
				next(t, parser, ipfw.Record{Line: line, Kind: ipfw.RecordEmpty})
			}
			next(t, parser, eof)
		})
	}
}

// verifies that a comment line keeps the raw text after the hash and the
// whole line as text.
func Test_Parser_Next_Comment(t *testing.T) {
	parser := ipfw.NewParser("# Пример комментария\n")
	next(t, parser, ipfw.Record{
		Line:    1,
		Text:    "# Пример комментария",
		Kind:    ipfw.RecordComment,
		Comment: " Пример комментария",
	})
	next(t, ipfw.NewParser("#"), ipfw.Record{Line: 1, Text: "#", Kind: ipfw.RecordComment})
}

// verifies that a label line yields the name without the colon and that a
// missing name or trailing content is a positioned error.
func Test_Parser_Next_Label(t *testing.T) {
	next(
		t,
		ipfw.NewParser(":ENDOFME\n"),
		ipfw.Record{Line: 1, Text: ":ENDOFME", Kind: ipfw.RecordLabel, Label: "ENDOFME"},
	)
	next(
		t,
		ipfw.NewParser(":L  \n"),
		ipfw.Record{Line: 1, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"},
	)
	nextError(
		t,
		ipfw.NewParser(":"),
		ipfw.ParseError{Kind: ipfw.ErrExpectedToken, Line: 1, Column: 1, Text: ":"},
	)
	nextError(
		t,
		ipfw.NewParser(":X # c"),
		ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 3, Text: ":X # c"},
	)
}

// verifies that a line starting with none of the known commands is
// rejected at its first byte with the whole line as text.
func Test_Parser_Next_UnknownLine(t *testing.T) {
	nextError(
		t,
		ipfw.NewParser("foobar\n"),
		ipfw.ParseError{Kind: ipfw.ErrExpectedLine, Line: 1, Column: 0, Text: "foobar"},
	)
}

// verifies that the add and table keywords require whitespace and then
// hand over to parsers that, for now, reject everything.
func Test_Parser_Next_CommandStubs(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "add without whitespace",
			input: "add\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 3,
				Text:   "add",
			},
		},
		{
			name:  "add without action",
			input: "add \n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 3,
				Text:   "add",
			},
		},
		{
			name:  "add glued to a word",
			input: "addx\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 3,
				Text:   "addx",
			},
		},
		{
			name:  "table without whitespace",
			input: "table\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 5,
				Text:   "table",
			},
		},
		{
			name:  "table without command",
			input: "table x\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableCommand,
				Line:   1,
				Column: 6,
				Text:   "table x",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that every physical line counts, blank ones included.
func Test_Parser_Next_LineNumbers(t *testing.T) {
	parser := ipfw.NewParser("# a\n\n:L\n")
	next(t, parser, ipfw.Record{Line: 1, Text: "# a", Kind: ipfw.RecordComment, Comment: " a"})
	next(t, parser, ipfw.Record{Line: 2, Kind: ipfw.RecordEmpty})
	next(t, parser, ipfw.Record{Line: 3, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
	next(t, parser, eof)
}

// verifies that the last line needs no newline.
func Test_Parser_Next_NoTrailingNewline(t *testing.T) {
	parser := ipfw.NewParser(":L")
	next(t, parser, ipfw.Record{Line: 1, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
	next(t, parser, eof)
}

// verifies that a failing line is skipped as a whole, so the next call
// parses the following line and the input is always consumed.
func Test_Parser_Next_SkipsFailedLine(t *testing.T) {
	parser := ipfw.NewParser("bad line\n:L\n")
	nextError(
		t,
		parser,
		ipfw.ParseError{Kind: ipfw.ErrExpectedLine, Line: 1, Column: 0, Text: "bad line"},
	)
	next(t, parser, ipfw.Record{Line: 2, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
	next(t, parser, eof)
}

// verifies that the error text is the line with leading whitespace skipped
// and the column counts from there.
func Test_ParseError_Position(t *testing.T) {
	nextError(
		t,
		ipfw.NewParser("  foo"),
		ipfw.ParseError{Kind: ipfw.ErrExpectedLine, Line: 1, Column: 0, Text: "foo"},
	)
	nextError(
		t,
		ipfw.NewParser("\t:X y\t\n"),
		ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 3, Text: ":X y"},
	)
}

// verifies that the iterator yields every record and stops right after the
// first failure, which is its last value.
func Test_Parser_All_StopsAtError(t *testing.T) {
	parser := ipfw.NewParser(":A\n# c\nbad\n:B\n")
	var records []ipfw.Record
	var errs []*ipfw.ParseError
	for rec, err := range parser.All(ipfw.DiscardState{}) {
		if rec != nil {
			records = append(records, *rec)
		}
		errs = append(errs, err)
	}
	require.Equal(t, []ipfw.Record{
		{Line: 1, Text: ":A", Kind: ipfw.RecordLabel, Label: "A"},
		{Line: 2, Text: "# c", Kind: ipfw.RecordComment, Comment: " c"},
	}, records)
	require.Len(t, errs, 3)
	require.Nil(t, errs[0])
	require.Nil(t, errs[1])
	require.ErrorIs(t, errs[2], ipfw.ErrExpectedLine)
}

// verifies that the iterator ends cleanly at the end of the input and
// honours an early break.
func Test_Parser_All_EOFAndBreak(t *testing.T) {
	count := 0
	for _, err := range ipfw.NewParser(":A\n:B\n").All(ipfw.DiscardState{}) {
		require.Nil(t, err)
		count++
	}
	require.Equal(t, 2, count)

	count = 0
	for range ipfw.NewParser(":A\n:B\n").All(ipfw.DiscardState{}) {
		count++
		break
	}
	require.Equal(t, 1, count)
}

// verifies that the collecting state keeps tokens in order and that a reset
// empties it without giving up the capacity.
func Test_ReduceState_Reset(t *testing.T) {
	var state ipfw.ReduceState
	require.NoError(t, state.OnIPProto(ipfw.ProtoIPMatch{Proto: ipfw.ProtoIPv4}))
	require.NoError(t, state.OnProto(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}}))
	require.NoError(t, state.OnSourceTarget(ipfw.Target{Kind: ipfw.TargetAny}))
	require.NoError(t, state.OnDestinationTarget(ipfw.Target{Kind: ipfw.TargetMe}))
	single := ipfw.PortRange{Lo: ipfw.Port{Number: 1}, Hi: ipfw.Port{Number: 1}}
	span := ipfw.PortRange{Lo: ipfw.Port{Number: 2}, Hi: ipfw.Port{Number: 3}}
	require.NoError(t, state.OnSourcePort(ipfw.PortMatch{Range: single}))
	require.NoError(t, state.OnDestinationPort(ipfw.PortMatch{Neg: true, Range: span}))
	require.NoError(t, state.OnOption(ipfw.Opt{Kind: ipfw.OptIn}))
	require.NoError(t, state.OnOption(ipfw.Opt{Kind: ipfw.OptOut, Or: true}))
	require.Equal(t, ipfw.ReduceState{
		IPProtos:         []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv4}},
		Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations:     []ipfw.Target{{Kind: ipfw.TargetMe}},
		SourcePorts:      []ipfw.PortMatch{{Range: single}},
		DestinationPorts: []ipfw.PortMatch{{Neg: true, Range: span}},
		Options:          []ipfw.Opt{{Kind: ipfw.OptIn}, {Kind: ipfw.OptOut, Or: true}},
	}, state)

	state.Reset()
	require.Empty(t, state.IPProtos)
	require.Empty(t, state.Protos)
	require.Empty(t, state.Sources)
	require.Empty(t, state.Destinations)
	require.Empty(t, state.SourcePorts)
	require.Empty(t, state.DestinationPorts)
	require.Empty(t, state.Options)
	require.Equal(t, 2, cap(state.Options))
}

// verifies that the discarding state accepts every token.
func Test_DiscardState_AcceptsEverything(t *testing.T) {
	var state ipfw.DiscardState
	require.NoError(t, state.OnIPProto(ipfw.ProtoIPMatch{}))
	require.NoError(t, state.OnProto(ipfw.ProtoMatch{}))
	require.NoError(t, state.OnSourceTarget(ipfw.Target{}))
	require.NoError(t, state.OnDestinationTarget(ipfw.Target{}))
	require.NoError(t, state.OnSourcePort(ipfw.PortMatch{}))
	require.NoError(t, state.OnDestinationPort(ipfw.PortMatch{}))
	require.NoError(t, state.OnOption(ipfw.Opt{}))
}

// verifies the version bit set: any contains both versions, a version
// contains itself and not the other.
func Test_ProtoIP_Contains(t *testing.T) {
	require.True(t, ipfw.ProtoIPAny.Contains(ipfw.ProtoIPv4))
	require.True(t, ipfw.ProtoIPAny.Contains(ipfw.ProtoIPv6))
	require.True(t, ipfw.ProtoIPv4.Contains(ipfw.ProtoIPv4))
	require.False(t, ipfw.ProtoIPv4.Contains(ipfw.ProtoIPv6))
	require.False(t, ipfw.ProtoIPv4.Contains(ipfw.ProtoIPAny))
}

// verifies that a protocol or port is numeric exactly when it has no name.
func Test_Proto_Port_IsNumber(t *testing.T) {
	require.True(t, ipfw.Proto{Number: 6}.IsNumber())
	require.False(t, ipfw.Proto{Name: "tcp"}.IsNumber())
	require.True(t, ipfw.Port{Number: 22}.IsNumber())
	require.False(t, ipfw.Port{Name: "ssh"}.IsNumber())
}

// verifies that steady-state parsing of comments, labels and blank lines
// allocates nothing once the parser is reused.
func Test_Parser_Next_NoAllocs(t *testing.T) {
	src := "# c\n:L\n\n"
	parser := ipfw.NewParser(src)
	var state ipfw.ReduceState
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		for calls := 0; ; calls++ {
			rec, err := parser.Next(&state)
			if rec.Kind == ipfw.RecordEOF {
				break
			}
			if err != nil || calls > len(src) {
				ok = false
				break
			}
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

// verifies that arbitrary input never panics, is always consumed, and only
// ever fails with a positioned parse error before reaching the end.
func Fuzz_Parser_Next(f *testing.F) {
	for _, seed := range []string{
		"",
		"# c\n",
		":L\n",
		"add \n",
		"x",
		"\n\n",
		"  :L  # x",
		"table\n",
		":\n",
		"add allow ip from any to any\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		parser := ipfw.NewParser(input)
		var state ipfw.ReduceState
		for calls := 0; ; calls++ {
			require.LessOrEqual(
				t,
				calls,
				len(input)+1,
				"the parser must consume input on every call",
			)
			rec, err := parser.Next(&state)
			if err != nil {
				require.GreaterOrEqual(t, err.Line, 1)
				require.GreaterOrEqual(t, err.Column, 0)
				require.LessOrEqual(t, err.Column, len(err.Text))
				continue
			}
			if rec.Kind == ipfw.RecordEOF {
				return
			}
			require.GreaterOrEqual(t, rec.Line, 1)
		}
	})
}

// verifies that an optional rule number is consumed only when whitespace
// follows it, and that the action is then expected right after.
func Test_Parser_Next_InstructionNumber(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "number then unknown action",
			input: "add 100 x",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 8,
				Text:   "add 100 x",
			},
		},
		{
			name:  "number then tab then unknown action",
			input: "add 50\tx\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 7,
				Text:   "add 50\tx",
			},
		},
		{
			name:  "number at end of input is not a number",
			input: "add 100",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 4,
				Text:   "add 100",
			},
		},
		{
			name:  "overflowing number is not a number",
			input: "add 4294967296 allow",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 4,
				Text:   "add 4294967296 allow",
			},
		},
		{
			name:  "no number",
			input: "add x",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 4,
				Text:   "add x",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that the body starts with a protocol followed by `from`, and
// that each missing piece is positioned where it was expected.
func Test_Parser_Next_BodyProtocol(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "nothing after the protocol",
			input: "add allow tcp\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 13,
				Text:   "add allow tcp",
			},
		},
		{
			name:  "from missing",
			input: "add allow tcp any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedFrom,
				Line:   1,
				Column: 14,
				Text:   "add allow tcp any",
			},
		},
		{
			name:  "nothing after from",
			input: "add allow tcp from",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 18,
				Text:   "add allow tcp from",
			},
		},
		{
			name:  "nothing after the source",
			input: "add allow tcp from any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 22,
				Text:   "add allow tcp from any",
			},
		},
		{
			name:  "targets without or",
			input: "add pass ip from { any any } to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 23,
				Text:   "add pass ip from { any any } to any",
			},
		},
		{
			name:  "target group left open",
			input: "add pass ip from { any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 22,
				Text:   "add pass ip from { any",
			},
		},
		{
			name:  "to missing after the source port",
			input: "add allow tcp from any 22 80 to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedPrefix,
				Line:   1,
				Column: 26,
				Text:   "add allow tcp from any 22 80 to any",
			},
		},
		{
			name:  "source port range without its second port",
			input: "add allow tcp from any 22- to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedPort,
				Line:   1,
				Column: 26,
				Text:   "add allow tcp from any 22- to any",
			},
		},
		{
			name:  "escape of anything but a dash in a port",
			input: "add pass tcp from any ftp\\x to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnexpectedEscape,
				Line:   1,
				Column: 25,
				Text:   "add pass tcp from any ftp\\x to any",
			},
		},
		{
			name:  "nothing after the source port",
			input: "add allow tcp from any 22",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 25,
				Text:   "add allow tcp from any 22",
			},
		},
		{
			name:  "quoted hostname left open",
			input: "add allow ip from `x.y to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedHostnameEscapeClose,
				Line:   1,
				Column: 18,
				Text:   "add allow ip from `x.y to any",
			},
		},
		{
			name:  "table name cut at a space breaks the body",
			input: "add allow ip from table(a b) to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 27,
				Text:   "add allow ip from table(a b) to any",
			},
		},
		{
			name:  "nothing after to",
			input: "add allow ip from any to\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 24,
				Text:   "add allow ip from any to",
			},
		},
		{
			name:  "unknown option after the destination port",
			input: "add allow ip from any to any 80 extra\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 32,
				Text:   "add allow ip from any to any 80 extra",
			},
		},
		{
			name:  "no protocol",
			input: "add allow _ from any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 10,
				Text:   "add allow _ from any",
			},
		},
		{
			name:  "ip keyword then nothing after from",
			input: "add allow ip from",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 17,
				Text:   "add allow ip from",
			},
		},
		{
			name:  "group then nothing after the source",
			input: "add allow { tcp or udp } from any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 33,
				Text:   "add allow { tcp or udp } from any",
			},
		},
		{
			name:  "group without separator",
			input: "add allow { tcp udp } from any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 16,
				Text:   "add allow { tcp udp } from any",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that a token handed to the state stays there when the line fails
// later on: the state is not rolled back.
func Test_Parser_Next_BodyProtocolEmittedBeforeFailure(t *testing.T) {
	var state ipfw.ReduceState
	_, err := ipfw.NewParser("add allow tcp x").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ReduceState{
		Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
	}, state)

	state = ipfw.ReduceState{}
	_, err = ipfw.NewParser("add allow ip x").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ReduceState{
		IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
	}, state)
}

// passAnyToAny is the record of a bare `add pass … from any to any` line.
func passAnyToAny(line int, text string) ipfw.Record {
	return ipfw.Record{
		Line:        line,
		Text:        text,
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}
}

// anyToAnyState is the state of a `VERSION from any to any` body.
func anyToAnyState(version ipfw.ProtoIP) ipfw.ReduceState {
	return ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: version}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}
}

// verifies the simplest complete rule end to end: the record and every
// token of the body in the state.
func Test_Parser_Next_AnyToAny(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add pass ip from any to any\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, "add pass ip from any to any"), *rec)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
}

// verifies that me and me6 reach the state as targets without text, the
// whole token telling me6 from me.
func Test_Parser_Next_MeToMe6(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add pass ip from me to me6\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add pass ip from me to me6",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetMe}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetMe6}},
	}, state)
}

// verifies that IPv4 network text reaches the state as is on both sides.
func Test_Parser_Next_Network4(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add pass ip from 192.0.2.0/24 to 203.0.113.1\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add pass ip from 192.0.2.0/24 to 203.0.113.1",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "203.0.113.1"}},
	}, state)
}

// verifies that IPv6 network text reaches the state as is on both sides.
func Test_Parser_Next_Network6(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add pass ip6 from 2001:db8::/32 to ::1\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add pass ip6 from 2001:db8::/32 to ::1",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv6}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:db8::/32"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "::1"}},
	}, state)
}

// verifies that a colon makes text with dots IPv6, so an IPv4-mapped
// address is not mistaken for the IPv4 text it ends with.
func Test_Parser_Next_Network6MappedIPv4(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add pass ip from ::ffff:192.0.2.1 to 192.0.2.1\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add pass ip from ::ffff:192.0.2.1 to 192.0.2.1",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "::ffff:192.0.2.1"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"}},
	}, state)
}

// verifies that a plain and a quoted hostname reach the state by name,
// the quotes stripped.
func Test_Parser_Next_Hostname(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser(
		"add allow tcp from { host.example.com } to `node-1.example.net'\n",
	).Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add allow tcp from { host.example.com } to `node-1.example.net'",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "host.example.com"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "node-1.example.net"}},
	}, state)
}

// verifies that table targets reach the state by name on both sides.
func Test_Parser_Next_Table(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add allow tcp from { table(_SRV_) } to table(_DST_)\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add allow tcp from { table(_SRV_) } to table(_DST_)",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetTable, Text: "_SRV_"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetTable, Text: "_DST_"}},
	}, state)
}

// verifies that braced groups and negations on both sides of the body
// reach the state element by element, in order.
func Test_Parser_Next_TargetGroups(t *testing.T) {
	cases := []struct {
		name  string
		input string
		state ipfw.ReduceState
	}{
		{
			name:  "protocol and source groups",
			input: "add pass { tcp or udp } from { 192.0.2.0/24 or ::1 } to any\n",
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{
					{Proto: ipfw.Proto{Name: "tcp"}},
					{Proto: ipfw.Proto{Name: "udp"}},
				},
				Sources: []ipfw.Target{
					{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"},
					{Kind: ipfw.TargetNetwork6, Text: "::1"},
				},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "negated source and negation inside the destination group",
			input: "add pass ip from not 192.0.2.0/24 to { me or not me6 }\n",
			state: ipfw.ReduceState{
				IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources: []ipfw.Target{
					{Neg: true, Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"},
				},
				Destinations: []ipfw.Target{
					{Kind: ipfw.TargetMe},
					{Neg: true, Kind: ipfw.TargetMe6},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line:        1,
				Text:        strings.TrimSuffix(tc.input, "\n"),
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that a port after the source or the destination reaches the
// state on its side.
//
// Only `to` followed by whitespace ends the source part, anything else in
// that position is a source port.
func Test_Parser_Next_Ports(t *testing.T) {
	anyToAny := []ipfw.Target{{Kind: ipfw.TargetAny}}
	cases := []struct {
		name    string
		input   string
		comment string
		state   ipfw.ReduceState
	}{
		{
			name:  "source port starting with to",
			input: "add pass ip from any topx to any\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portService("topx")},
			},
		},
		{
			name:  "source port starting with not",
			input: "add pass ip from any notify to any\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portService("notify")},
			},
		},
		{
			name:  "numbers on both sides",
			input: "add allow tcp from any 22 to any 80\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				SourcePorts:      []ipfw.PortMatch{portNumber(22)},
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
			},
		},
		{
			name:  "destination service",
			input: "add allow tcp from any to any domain\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portService("domain")},
			},
		},
		{
			name:  "source service",
			input: "add allow tcp from any http to any\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portService("http")},
			},
		},
		{
			name:  "source port range and destination service",
			input: "add allow tcp from 2001:db8::/32 1024-65535 to any domain\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:db8::/32"}},
				Destinations:     anyToAny,
				SourcePorts:      []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1024}, ipfw.Port{Number: 65535})},
				DestinationPorts: []ipfw.PortMatch{portService("domain")},
			},
		},
		{
			name:  "whole range on the destination",
			input: "add allow tcp from any to any 1-65535\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portSpan(ipfw.Port{Number: 1}, ipfw.Port{Number: 65535})},
			},
		},
		{
			name:  "source port list",
			input: "add pass tcp from any 11,22,33 to any\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portNumber(11), portNumber(22), portNumber(33)},
			},
		},
		{
			name:  "destination port list",
			input: "add pass tcp from any to any 11,22,33\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(11), portNumber(22), portNumber(33)},
			},
		},
		{
			name:  "lists on both sides",
			input: "add pass tcp from any 11,22 to any 33,44\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				SourcePorts:      []ipfw.PortMatch{portNumber(11), portNumber(22)},
				DestinationPorts: []ipfw.PortMatch{portNumber(33), portNumber(44)},
			},
		},
		{
			name:  "destination list with a range",
			input: "add pass tcp from any to any 22,80-90,443\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				DestinationPorts: []ipfw.PortMatch{
					portNumber(22),
					portSpan(ipfw.Port{Number: 80}, ipfw.Port{Number: 90}),
					portNumber(443),
				},
			},
		},
		{
			name:  "negated destination port list",
			input: "add pass tcp from any to any not 11,22,33\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				DestinationPorts: []ipfw.PortMatch{
					negated(portNumber(11)),
					negated(portNumber(22)),
					negated(portNumber(33)),
				},
			},
		},
		{
			name:  "negated source port",
			input: "add pass tcp from any not 22 to any\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{negated(portNumber(22))},
			},
		},
		{
			name:  "negated destination list with a range",
			input: "add pass tcp from any to any not 22-23,80\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				DestinationPorts: []ipfw.PortMatch{
					negated(portSpan(ipfw.Port{Number: 22}, ipfw.Port{Number: 23})),
					negated(portNumber(80)),
				},
			},
		},
		{
			name:  "escaped service name",
			input: "add pass tcp from any ftp\\-data to any\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portService("ftp\\-data")},
			},
		},
		{
			name:    "destination port before an inline comment",
			input:   "add allow tcp from any to any 80 // web\n",
			comment: " web",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line: 1,
				Text: strings.TrimSuffix(tc.input, "\n"),
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Action:        ipfw.Action{Kind: ipfw.ActionPass},
					InlineComment: tc.comment,
				},
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that a trailing comma fails a port list after its elements were
// emitted.
//
// A source list fails the line at the missing port, a destination list is
// abandoned and its first element is then an unknown option.
func Test_Parser_Next_PortListTrailingComma(t *testing.T) {
	var state ipfw.ReduceState
	_, err := ipfw.NewParser("add pass tcp from any 22, to any\n").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedPort,
		Line:   1,
		Column: 25,
		Text:   "add pass tcp from any 22, to any",
	}, *err)
	require.Equal(t, ipfw.ReduceState{
		Protos:      []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:     []ipfw.Target{{Kind: ipfw.TargetAny}},
		SourcePorts: []ipfw.PortMatch{portNumber(22)},
	}, state)

	state = ipfw.ReduceState{}
	_, err = ipfw.NewParser("add pass tcp from any to any 22,\n").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrUnknownOption,
		Line:   1,
		Column: 29,
		Text:   "add pass tcp from any to any 22,",
	}, *err)
	require.Equal(t, ipfw.ReduceState{
		Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations:     []ipfw.Target{{Kind: ipfw.TargetAny}},
		DestinationPorts: []ipfw.PortMatch{portNumber(22)},
	}, state)
}

// verifies that `log [logamount N]` after the action lands in the record
// and leaves the body to the state, check-state included.
func Test_Parser_Next_Log(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		instruction ipfw.Instruction
		state       ipfw.ReduceState
	}{
		{
			name:  "log",
			input: "add deny log ip from 192.0.2.0/24 to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionDeny},
				Log:    ipfw.Log{Enabled: true},
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "log with an amount",
			input: "add deny log logamount 500 ip from 192.0.2.0/24 to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionDeny},
				Log:    ipfw.Log{Enabled: true, HasAmount: true, Amount: 500},
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "rule number then log",
			input: "add 100 pass log ip from any to any\n",
			instruction: ipfw.Instruction{
				Num:    100,
				Action: ipfw.Action{Kind: ipfw.ActionPass},
				Log:    ipfw.Log{Enabled: true},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "check-state with log",
			input: "add check-state log\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionCheckState},
				Log:    ipfw.Log{Enabled: true},
			},
		},
		{
			name:  "check-state with a flow and an amount",
			input: "add check-state :flow log logamount 10\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionCheckState, Flow: "flow"},
				Log:    ipfw.Log{Enabled: true, HasAmount: true, Amount: 10},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
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

// verifies that `tag N` after the log part lands in the record, for
// check-state too, a zero tag being indistinguishable from none.
func Test_Parser_Next_Tag(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		instruction ipfw.Instruction
		state       ipfw.ReduceState
	}{
		{
			name:  "tag",
			input: "add allow tag 653 ip4 from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
				Tag:    653,
			},
			state: anyToAnyState(ipfw.ProtoIPv4),
		},
		{
			name:  "log then tag",
			input: "add allow log tag 5 ip from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
				Log:    ipfw.Log{Enabled: true},
				Tag:    5,
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "logamount then tag",
			input: "add deny log logamount 7 tag 5 ip from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionDeny},
				Log:    ipfw.Log{Enabled: true, HasAmount: true, Amount: 7},
				Tag:    5,
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "check-state with tag",
			input: "add check-state tag 3\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionCheckState},
				Tag:    3,
			},
		},
		{
			name:  "tag zero reads as none",
			input: "add allow tag 0 ip from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
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

// verifies that the tag keyword matches by prefix, needs its number, and
// comes after the log part.
//
// Each failure is positioned where the next piece was due.
func Test_Parser_Next_TagErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "nothing after tag",
			input: "add allow tag\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 13,
				Text:   "add allow tag",
			},
		},
		{
			name:  "tag without a number",
			input: "add allow tag x ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedU32,
				Line:   1,
				Column: 14,
				Text:   "add allow tag x ip from any to any",
			},
		},
		{
			name:  "tag overflow",
			input: "add allow tag 4294967296 ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedU32,
				Line:   1,
				Column: 14,
				Text:   "add allow tag 4294967296 ip from any to any",
			},
		},
		{
			name:  "tag with a suffix",
			input: "add allow tagx 5 ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 13,
				Text:   "add allow tagx 5 ip from any to any",
			},
		},
		{
			name:  "log after tag is a protocol",
			input: "add allow tag 5 log ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedFrom,
				Line:   1,
				Column: 20,
				Text:   "add allow tag 5 log ip from any to any",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that the log keywords match by prefix and that a logamount
// needs its number, each failure positioned where the next piece was due.
func Test_Parser_Next_LogErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "nothing after log",
			input: "add deny log\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 12,
				Text:   "add deny log",
			},
		},
		{
			name:  "nothing after logamount",
			input: "add deny log logamount\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 22,
				Text:   "add deny log logamount",
			},
		},
		{
			name:  "logamount without a number",
			input: "add deny log logamount x ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedU32,
				Line:   1,
				Column: 23,
				Text:   "add deny log logamount x ip from any to any",
			},
		},
		{
			name:  "logamount overflow",
			input: "add deny log logamount 4294967296 ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedU32,
				Line:   1,
				Column: 23,
				Text:   "add deny log logamount 4294967296 ip from any to any",
			},
		},
		{
			name:  "nothing after the amount",
			input: "add deny log logamount 500\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 26,
				Text:   "add deny log logamount 500",
			},
		},
		{
			name:  "logamount without log is read as log",
			input: "add deny logamount 5 ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 12,
				Text:   "add deny logamount 5 ip from any to any",
			},
		},
		{
			name:  "log with a suffix",
			input: "add deny logx ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 12,
				Text:   "add deny logx ip from any to any",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that the option list after the destination reaches the state
// and takes precedence over destination ports.
//
// A token that is an option is one, anything else there is a port, and
// options may follow the port.
func Test_Parser_Next_Options(t *testing.T) {
	anyToAny := []ipfw.Target{{Kind: ipfw.TargetAny}}
	tcp := []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}}
	established := ipfw.Opt{Kind: ipfw.OptEstablished}
	cases := []struct {
		name    string
		input   string
		comment string
		state   ipfw.ReduceState
	}{
		{
			name:  "established",
			input: "add allow tcp from any to any established\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{established},
			},
		},
		{
			name:  "destination port then option",
			input: "add allow tcp from any to any 22 established\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(22)},
				Options:          []ipfw.Opt{established},
			},
		},
		{
			name:  "source port then option",
			input: "add allow tcp from any 22 to any established\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portNumber(22)},
				Options:      []ipfw.Opt{established},
			},
		},
		{
			name:  "token that is not an option is a port",
			input: "add allow tcp from any to any foo\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portService("foo")},
			},
		},
		{
			name:  "negated option",
			input: "add allow tcp from any to any not established\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Neg: true, Kind: ipfw.OptEstablished}},
			},
		},
		{
			name:  "negated token that is not an option is a negated port",
			input: "add allow tcp from any to any not foo\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{negated(portService("foo"))},
			},
		},
		{
			name:  "not glued to a keyword is a port",
			input: "add allow tcp from any to any notestablished\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portService("notestablished")},
			},
		},
		{
			name:  "or-group with a negated member",
			input: "add allow tcp from any to any { established or not established }\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options: []ipfw.Opt{
					established,
					{Neg: true, Or: true, Kind: ipfw.OptEstablished},
				},
			},
		},
		{
			name:  "in",
			input: "add allow tcp from any to me in\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: []ipfw.Target{{Kind: ipfw.TargetMe}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "out",
			input: "add allow udp from me domain to any out\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "udp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetMe}},
				Destinations: anyToAny,
				SourcePorts:  []ipfw.PortMatch{portService("domain")},
				Options:      []ipfw.Opt{{Kind: ipfw.OptOut}},
			},
		},
		{
			name:  "in and out are not exclusive",
			input: "add allow tcp from any to any in out\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}, {Kind: ipfw.OptOut}},
			},
		},
		{
			name:  "group of in and out",
			input: "add allow tcp from any to any { in or out }\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}, {Or: true, Kind: ipfw.OptOut}},
			},
		},
		{
			name:    "in before an inline comment",
			input:   "add allow tcp from any to any in // c\n",
			comment: " c",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "frag",
			input: "add allow ip from any to any frag\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptFrag}},
			},
		},
		{
			name:  "diverted",
			input: "add allow ip from any to any diverted\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptDiverted}},
			},
		},
		{
			name:  "negated diverted",
			input: "add allow ip from any to any not diverted\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Neg: true, Kind: ipfw.OptDiverted}},
			},
		},
		{
			name:  "antispoof",
			input: "add allow ip from any to any antispoof\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptAntiSpoof}},
			},
		},
		{
			name:  "antispoof then in",
			input: "add allow ip from any to any antispoof in\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptAntiSpoof}, {Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "destination port option after a target group",
			input: "add allow udp from 2001:db8::/64 to { ff02::/112 or ff05::/112 } dst-port 11995\n",
			state: ipfw.ReduceState{
				Protos:  []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "udp"}}},
				Sources: []ipfw.Target{{Kind: ipfw.TargetNetwork6, Text: "2001:db8::/64"}},
				Destinations: []ipfw.Target{
					{Kind: ipfw.TargetNetwork6, Text: "ff02::/112"},
					{Kind: ipfw.TargetNetwork6, Text: "ff05::/112"},
				},
				Options: []ipfw.Opt{dstPort(11995)},
			},
		},
		{
			name:  "source port option",
			input: "add allow udp from any to any src-port 179\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "udp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{srcPort(179)},
			},
		},
		{
			name:  "destination port then a port option",
			input: "add allow tcp from any to any 22 dst-port 80\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(22)},
				Options:          []ipfw.Opt{dstPort(80)},
			},
		},
		{
			name:  "port option without its argument is a port range",
			input: "add allow tcp from any to any dst-port\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				DestinationPorts: []ipfw.PortMatch{
					portSpan(ipfw.Port{Name: "dst"}, ipfw.Port{Name: "port"}),
				},
			},
		},
		{
			name:  "negated port list is two and terms",
			input: "add allow tcp from any to any not dst-port 22,80\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{notOpt(dstPort(22)), notOpt(dstPort(80))},
			},
		},
		{
			name:  "proto option",
			input: "add allow ip from any to any proto ipv6\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "ipv6"}}},
			},
		},
		{
			name:  "keep-state",
			input: "add allow icmp from any to any keep-state\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "icmp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptKeepState}},
			},
		},
		{
			name:  "keep-state with a flow",
			input: "add allow tcp from any to any keep-state :flow\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptKeepState, Text: "flow"}},
			},
		},
		{
			name:  "icmptypes",
			input: "add allow icmp from any to any icmptypes 3,8,11,12\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "icmp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{icmpTypes(3, 8, 11, 12)},
			},
		},
		{
			name:  "icmp6types",
			input: "add allow ip from any to any icmp6types 135\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{icmp6Types(135)},
			},
		},
		{
			name:    "option before an inline comment",
			input:   "add allow tcp from any to any established // c\n",
			comment: " c",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{established},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line: 1,
				Text: strings.TrimSuffix(tc.input, "\n"),
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Action:        ipfw.Action{Kind: ipfw.ActionPass},
					InlineComment: tc.comment,
				},
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that a token after the option list, or after a port that was
// not an option, is an unknown option positioned at the token.
//
// Leftovers glued to the ports, with no whitespace to open an option list,
// are trailing content.
func Test_Parser_Next_OptionErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "port after an option",
			input: "add allow tcp from any to any established 22",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 42,
				Text:   "add allow tcp from any to any established 22",
			},
		},
		{
			name:  "unknown option after a port",
			input: "add allow tcp from any to any 22 foo",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 33,
				Text:   "add allow tcp from any to any 22 foo",
			},
		},
		{
			name:  "unknown option after a token taken as a port",
			input: "add allow tcp from any to any foo bar",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 34,
				Text:   "add allow tcp from any to any foo bar",
			},
		},
		{
			name:  "negated unknown option",
			input: "add allow tcp from any to any established not foo",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 46,
				Text:   "add allow tcp from any to any established not foo",
			},
		},
		{
			name:  "option group without or",
			input: "add allow tcp from any to any { established established }",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 44,
				Text:   "add allow tcp from any to any { established established }",
			},
		},
		{
			name:  "option group left open",
			input: "add allow tcp from any to any { established",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 43,
				Text:   "add allow tcp from any to any { established",
			},
		},
		{
			name:  "in with a suffix is in then trailing content",
			input: "add allow ip from any to any inet",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 31,
				Text:   "add allow ip from any to any inet",
			},
		},
		{
			name:  "port after frag",
			input: "add allow ip from any to any frag 22",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 34,
				Text:   "add allow ip from any to any frag 22",
			},
		},
		{
			name:  "port option without its argument",
			input: "add allow tcp from any to any established dst-port\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 50,
				Text:   "add allow tcp from any to any established dst-port",
			},
		},
		{
			name:  "proto option without its argument",
			input: "add allow ip from any to any established proto\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 46,
				Text:   "add allow ip from any to any established proto",
			},
		},
		{
			name:  "keep-state with an empty flow",
			input: "add allow tcp from any to any keep-state :",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 41,
				Text:   "add allow tcp from any to any keep-state :",
			},
		},
		{
			name:  "unknown icmp type",
			input: "add allow icmp from any to any established icmptypes 7",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownICMPType,
				Line:   1,
				Column: 53,
				Text:   "add allow icmp from any to any established icmptypes 7",
			},
		},
		{
			name:  "unknown icmp6 type",
			input: "add allow ip from any to any established icmp6types 150",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownICMP6Type,
				Line:   1,
				Column: 52,
				Text:   "add allow ip from any to any established icmp6types 150",
			},
		},
		{
			name:  "leftover after the ports",
			input: "add allow tcp from any to any 1,1000...\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 36,
				Text:   "add allow tcp from any to any 1,1000...",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that an error a state returns fails the line at the rejected
// token.
//
// An ErrorKind keeps its kind, any other error is an ErrState that wraps
// it.
func Test_Parser_Next_StateError(t *testing.T) {
	_, err := ipfw.NewParser("add allow foobar from any to any\n").
		Next(rejectingState{err: ipfw.ErrExpectedEitherIPOrProto})
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedEitherIPOrProto,
		Line:   1,
		Column: 10,
		Text:   "add allow foobar from any to any",
	}, *err)

	boom := errors.New("boom")
	_, err = ipfw.NewParser("add allow foobar from any to any\n").Next(rejectingState{err: boom})
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrState,
		Err:    boom,
		Line:   1,
		Column: 10,
		Text:   "add allow foobar from any to any",
	}, *err)
	require.ErrorIs(t, err, boom)
	require.ErrorIs(t, err, ipfw.ErrState)
	require.Equal(t, "1:10: state error: boom", err.Error())
}

// verifies that a line with ports and options, the dry run of the options
// included, parses into a warmed-up state without allocating.
func Test_Parser_Next_OptionsNoAllocs(t *testing.T) {
	src := "add pass tcp from any to any 22 established\nadd pass tcp from any to any established\n"
	parser := ipfw.NewParser(src)
	var state ipfw.ReduceState
	for _, err := range parser.All(&state) {
		require.Nil(t, err)
	}
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		for _, err := range parser.All(&state) {
			if err != nil {
				ok = false
			}
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

// verifies that a token of no known shape reaches the state as a custom
// target with its raw text, the line parsing as a whole.
func Test_Parser_Next_CustomTarget(t *testing.T) {
	cases := []struct {
		name  string
		input string
		state ipfw.ReduceState
	}{
		{
			name:  "inet keyword of the extra syntax",
			input: "add allow tcp from any to inet\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "inet"}},
			},
		},
		{
			name:  "macro name in a braced group",
			input: "add allow tcp from { host.example.com } to { _TEST_SERVERS_ }\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "host.example.com"}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "_TEST_SERVERS_"}},
			},
		},
		{
			name:  "keyword with a suffix",
			input: "add allow ip from mex to any\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "mex"}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line:        1,
				Text:        strings.TrimSuffix(tc.input, "\n"),
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that the parser does not validate a network: text of the right
// shape is handed to the state, which is where it gets rejected.
func Test_Parser_Next_Network4Unvalidated(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add allow ip4 from 300.1.1.1 to any\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        "add allow ip4 from 300.1.1.1 to any",
		Kind:        ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *rec)
	require.Equal(t, ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv4}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "300.1.1.1"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}, state)
}

// verifies that a comma list of networks is not supported: the first
// network is emitted and the line fails at the comma.
func Test_Parser_Next_Network4CommaList(t *testing.T) {
	var state ipfw.ReduceState
	_, err := ipfw.NewParser("add allow ip from 192.0.2.1,203.0.113.1 to any").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedWhitespace,
		Line:   1,
		Column: 27,
		Text:   "add allow ip from 192.0.2.1,203.0.113.1 to any",
	}, *err)
	require.Equal(t, ipfw.ReduceState{
		IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		Sources:  []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"}},
	}, state)
}

// verifies that a braced single target and trailing whitespace parse, the
// text being trimmed.
func Test_Parser_Next_TrailingWhitespace(t *testing.T) {
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add allow tcp from any to { any } \n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, "add allow tcp from any to { any }"), *rec)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}, state)
}

// verifies that an inline comment after the body is the raw text after the
// slashes, part of the line text, and that a lone slash is an unknown option.
func Test_Parser_Next_InlineComment(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		comment string
	}{
		{
			name:    "json payload",
			input:   "add pass ip from any to any // {\"id\": \"RULE-42\", \"log\": true}\n",
			comment: " {\"id\": \"RULE-42\", \"log\": true}",
		},
		{name: "empty comment", input: "add pass ip from any to any //", comment: ""},
		{name: "tab before the slashes", input: "add pass ip from any to any\t//x\n", comment: "x"},
		{name: "no comment", input: "add pass ip from any to any\n", comment: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			expected := passAnyToAny(1, strings.TrimSpace(tc.input))
			expected.Instruction.InlineComment = tc.comment
			require.Equal(t, expected, *rec)
			require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
		})
	}
	nextError(t, ipfw.NewParser("add pass ip from any to any / x"), ipfw.ParseError{
		Kind:   ipfw.ErrUnknownOption,
		Line:   1,
		Column: 28,
		Text:   "add pass ip from any to any / x",
	})
}

// verifies that parsing a complete rule into a warmed-up state allocates
// nothing.
func Test_Parser_Body_NoAllocs(t *testing.T) {
	src := "add pass ip from any to any\n"
	parser := ipfw.NewParser(src)
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

// verifies that a long label name is taken whole.
func Test_Parser_Next_LongLabel(t *testing.T) {
	next(t, ipfw.NewParser(":LONG_LABEL_NAME_42\n"), ipfw.Record{
		Line:  1,
		Text:  ":LONG_LABEL_NAME_42",
		Kind:  ipfw.RecordLabel,
		Label: "LONG_LABEL_NAME_42",
	})
}

// The benchmark results are sunk here so the compiler keeps the work.
var (
	benchRecord *ipfw.Record
	benchErr    *ipfw.ParseError
)

// benchmarkNext measures parsing one line over and over with a reused
// parser and a warmed-up state.
func benchmarkNext(b *testing.B, line string) {
	b.Helper()
	parser := ipfw.NewParser(line)
	var state ipfw.ReduceState
	_, _ = parser.Next(&state)
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for b.Loop() {
		parser.Reset(line)
		state.Reset()
		benchRecord, benchErr = parser.Next(&state)
	}
}

func Benchmark_Parser_Next_AnyToAny(b *testing.B) {
	benchmarkNext(b, "add pass ip from any to any\n")
}

func Benchmark_Parser_Next_Comment(b *testing.B) {
	benchmarkNext(b, "# a comment line of an ordinary length\n")
}

func Benchmark_Parser_Next_Label(b *testing.B) {
	benchmarkNext(b, ":LONG_LABEL_NAME_42\n")
}
