package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

var (
	_ ipfw.State = ipfw.DiscardState{}
	_ ipfw.State = (*ipfw.CollectState)(nil)
)

// next parses one line and requires it to succeed with the given record and
// an untouched state.
func next(t *testing.T, parser *ipfw.Parser, expected ipfw.Record) {
	t.Helper()
	var state ipfw.CollectState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, expected, rec)
	require.Equal(t, ipfw.CollectState{}, state)
}

// nextError parses one line and requires the given positioned failure.
func nextError(t *testing.T, parser *ipfw.Parser, expected ipfw.ParseError) {
	t.Helper()
	var state ipfw.CollectState
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
	parser := ipfw.NewParser("# Управляющие серверы\n")
	next(t, parser, ipfw.Record{
		Line:    1,
		Text:    "# Управляющие серверы",
		Kind:    ipfw.RecordComment,
		Comment: " Управляющие серверы",
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
		records = append(records, rec)
		errs = append(errs, err)
	}
	require.Equal(t, []ipfw.Record{
		{Line: 1, Text: ":A", Kind: ipfw.RecordLabel, Label: "A"},
		{Line: 2, Text: "# c", Kind: ipfw.RecordComment, Comment: " c"},
		{},
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

// verifies that a single line parses with or without its newline and that a
// second line is rejected at the end of the first.
//
// An empty input is an empty line rather than an end of input.
func Test_ParseLine_Table(t *testing.T) {
	label := ipfw.Record{Line: 1, Text: ":A", Kind: ipfw.RecordLabel, Label: "A"}
	cases := []struct {
		name     string
		input    string
		expected ipfw.Record
		err      *ipfw.ParseError
	}{
		{name: "with newline", input: ":A\n", expected: label},
		{name: "without newline", input: ":A", expected: label},
		{
			name:     "empty input is an empty line",
			input:    "",
			expected: ipfw.Record{Line: 1, Kind: ipfw.RecordEmpty},
		},
		{
			name:  "second line is rejected",
			input: ":A\n:B",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 2,
				Text:   ":A",
			},
		},
		{
			name:  "unknown line",
			input: "x",
			err:   &ipfw.ParseError{Kind: ipfw.ErrExpectedLine, Line: 1, Column: 0, Text: "x"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ipfw.ParseLine(tc.input, ipfw.DiscardState{})
			if tc.err != nil {
				require.Equal(t, tc.err, err)
				return
			}
			require.Nil(t, err)
			require.Equal(t, tc.expected, rec)
		})
	}
}

// verifies that the collecting state keeps tokens in order and that a reset
// empties it without giving up the capacity.
func Test_CollectState_Reset(t *testing.T) {
	var state ipfw.CollectState
	require.NoError(t, state.IPProto(ipfw.ProtoIPMatch{Proto: ipfw.ProtoIPv4}))
	require.NoError(t, state.Proto(ipfw.ProtoMatch{Proto: ipfw.Proto{Name: "tcp"}}))
	require.NoError(t, state.SourceTarget(ipfw.Target{Kind: ipfw.TargetAny}))
	require.NoError(t, state.DestinationTarget(ipfw.Target{Kind: ipfw.TargetMe}))
	single := ipfw.PortRange{Lo: ipfw.Port{Number: 1}, Hi: ipfw.Port{Number: 1}}
	span := ipfw.PortRange{Lo: ipfw.Port{Number: 2}, Hi: ipfw.Port{Number: 3}}
	require.NoError(t, state.SourcePort(ipfw.PortMatch{Range: single}))
	require.NoError(t, state.DestinationPort(ipfw.PortMatch{Neg: true, Range: span}))
	require.NoError(t, state.Option(ipfw.Opt{Kind: ipfw.OptIn}))
	require.NoError(t, state.Option(ipfw.Opt{Kind: ipfw.OptOut, Or: true}))
	require.Equal(t, ipfw.CollectState{
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
	require.NoError(t, state.IPProto(ipfw.ProtoIPMatch{}))
	require.NoError(t, state.Proto(ipfw.ProtoMatch{}))
	require.NoError(t, state.SourceTarget(ipfw.Target{}))
	require.NoError(t, state.DestinationTarget(ipfw.Target{}))
	require.NoError(t, state.SourcePort(ipfw.PortMatch{}))
	require.NoError(t, state.DestinationPort(ipfw.PortMatch{}))
	require.NoError(t, state.Option(ipfw.Opt{}))
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

// verifies that the type set holds any of the 256 type numbers independently.
func Test_TypeSet_AddHas(t *testing.T) {
	var set ipfw.TypeSet
	require.True(t, set.IsEmpty())
	for typ := range 256 {
		set.Add(uint8(typ))
		require.True(t, set.Has(uint8(typ)))
		require.False(t, set.IsEmpty())
		if typ < 255 {
			require.False(t, set.Has(uint8(typ+1)))
		}
	}
	require.Equal(t, ipfw.TypeSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}, set)
}

// verifies that steady-state parsing of comments, labels and blank lines
// allocates nothing once the parser is reused.
func Test_Parser_Next_NoAllocs(t *testing.T) {
	src := "# c\n:L\n\n"
	parser := ipfw.NewParser(src)
	var state ipfw.CollectState
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
		var state ipfw.CollectState
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

// verifies that a pass action must be followed by whitespace and a body,
// which is not parsed yet.
func Test_Parser_Next_ActionPass(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "body expected",
			input: "add allow _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 10,
				Text:   "add allow _",
			},
		},
		{
			name:  "numbered rule",
			input: "add 100 permit _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 15,
				Text:   "add 100 permit _",
			},
		},
		{
			name:  "no whitespace after the action",
			input: "add allow\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 9,
				Text:   "add allow",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that a deny action hands over to the body and that a keyword
// glued to a longer word fails at the whitespace check after it.
func Test_Parser_Next_ActionDeny(t *testing.T) {
	nextError(
		t,
		ipfw.NewParser("add drop _"),
		ipfw.ParseError{
			Kind:   ipfw.ErrExpectedEitherIPOrProto,
			Line:   1,
			Column: 9,
			Text:   "add drop _",
		},
	)
	nextError(
		t,
		ipfw.NewParser("add denyall ip"),
		ipfw.ParseError{
			Kind:   ipfw.ErrExpectedWhitespace,
			Line:   1,
			Column: 8,
			Text:   "add denyall ip",
		},
	)
}

// verifies that a count action hands over to the body.
func Test_Parser_Next_ActionCount(t *testing.T) {
	nextError(
		t,
		ipfw.NewParser("add count _"),
		ipfw.ParseError{
			Kind:   ipfw.ErrExpectedEitherIPOrProto,
			Line:   1,
			Column: 10,
			Text:   "add count _",
		},
	)
}

// verifies that a skipto action with each target kind hands over to the
// body and that a missing or unknown target is positioned after the keyword.
func Test_Parser_Next_ActionSkipTo(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "number target",
			input: "add skipto 1500 _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 16,
				Text:   "add skipto 1500 _",
			},
		},
		{
			name:  "label target",
			input: "add skipto :X _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 14,
				Text:   "add skipto :X _",
			},
		},
		{
			name:  "tablearg target",
			input: "add skipto tablearg _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 20,
				Text:   "add skipto tablearg _",
			},
		},
		{
			name:  "missing target",
			input: "add skipto",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 10,
				Text:   "add skipto",
			},
		},
		{
			name:  "unknown target",
			input: "add skipto x",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedSkipTo,
				Line:   1,
				Column: 11,
				Text:   "add skipto x",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that a check-state rule has no body: the line ends right after
// the optional flow name, and anything else there is trailing content.
func Test_Parser_Next_ActionCheckState(t *testing.T) {
	checkState := func(line int, text, flow string, num uint32) ipfw.Record {
		return ipfw.Record{
			Line: line,
			Text: text,
			Kind: ipfw.RecordInstruction,
			Instruction: ipfw.Instruction{
				Num:    num,
				Action: ipfw.Action{Kind: ipfw.ActionCheckState, Flow: flow},
			},
		}
	}
	next(
		t,
		ipfw.NewParser("add check-state :any\n"),
		checkState(1, "add check-state :any", "any", 0),
	)
	next(t, ipfw.NewParser("add check-state"), checkState(1, "add check-state", "", 0))
	next(
		t,
		ipfw.NewParser("add 10 check-state :x\n"),
		checkState(1, "add 10 check-state :x", "x", 10),
	)

	// TODO(070): the second line is `add pass ip from any to any` in the reference.
	parser := ipfw.NewParser("add check-state :any\nadd check-state\n")
	next(t, parser, checkState(1, "add check-state :any", "any", 0))
	next(t, parser, checkState(2, "add check-state", "", 0))
	next(t, parser, eof)

	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "colon without a name",
			input: "add check-state :\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 16,
				Text:   "add check-state :",
			},
		},
		{
			name:  "word after the keyword",
			input: "add check-state foo",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 16,
				Text:   "add check-state foo",
			},
		},
		{
			name:  "inline comment is not accepted either",
			input: "add check-state // c",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 16,
				Text:   "add check-state // c",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that a long label name is taken whole.
func Test_Parser_Next_LabelFlowName(t *testing.T) {
	next(
		t,
		ipfw.NewParser(":MEICMP6LOGDOUBLECOLON\n"),
		ipfw.Record{
			Line:  1,
			Text:  ":MEICMP6LOGDOUBLECOLON",
			Kind:  ipfw.RecordLabel,
			Label: "MEICMP6LOGDOUBLECOLON",
		},
	)
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
			name:     "nothing after the protocol",
			input:    "add allow tcp\n",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 13, Text: "add allow tcp"},
		},
		{
			name:     "from missing",
			input:    "add allow tcp any",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedFrom, Line: 1, Column: 14, Text: "add allow tcp any"},
		},
		{
			name:     "nothing after from",
			input:    "add allow tcp from",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 18, Text: "add allow tcp from"},
		},
		{
			name:     "source expected",
			input:    "add allow tcp from any",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedTarget, Line: 1, Column: 19, Text: "add allow tcp from any"},
		},
		{
			name:     "no protocol",
			input:    "add allow _ from any",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedEitherIPOrProto, Line: 1, Column: 10, Text: "add allow _ from any"},
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
	var state ipfw.CollectState
	_, err := ipfw.NewParser("add allow tcp x").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.CollectState{Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}}}, state)
}
