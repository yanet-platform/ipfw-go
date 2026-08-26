package ipfw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// bodyError is the failure of a line whose body is `_`, a token that is
// never a protocol: reaching it proves the header before it parsed.
func bodyError(text string, column int) ipfw.ParseError {
	return ipfw.ParseError{Kind: ipfw.ErrExpectedEitherIPOrProto, Line: 1, Column: column, Text: text}
}

// verifies that every alias of the pass action is recognized by prefix and
// hands over to the body, and that anything else is rejected at the action.
func Test_Parser_Next_ActionPass(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{name: "allow", input: "add allow _", expected: bodyError("add allow _", 10)},
		{name: "pass", input: "add pass _", expected: bodyError("add pass _", 9)},
		{name: "accept", input: "add accept _", expected: bodyError("add accept _", 11)},
		{name: "permit", input: "add permit _", expected: bodyError("add permit _", 11)},
		{name: "numbered rule", input: "add 100 permit _", expected: bodyError("add 100 permit _", 15)},
		{
			name:     "prefix match then whitespace expected",
			input:    "add passthru x",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 8, Text: "add passthru x"},
		},
		{
			name:     "truncated keyword",
			input:    "add pas ip",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedAction, Line: 1, Column: 4, Text: "add pas ip"},
		},
		{
			name:     "no whitespace after the action",
			input:    "add allow\n",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 9, Text: "add allow"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
	var state ipfw.CollectState
	rec, err := ipfw.NewParser("add accept ip from any to any\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, "add accept ip from any to any"), rec)
}

// verifies that both spellings of the deny action are recognized by prefix.
func Test_Parser_Next_ActionDeny(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{name: "deny", input: "add deny _", expected: bodyError("add deny _", 9)},
		{name: "drop", input: "add drop _", expected: bodyError("add drop _", 9)},
		{
			name:     "prefix match then whitespace expected",
			input:    "add denyall _",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 8, Text: "add denyall _"},
		},
		{
			name:     "denied is not deny",
			input:    "add denied _",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedAction, Line: 1, Column: 4, Text: "add denied _"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
	var state ipfw.CollectState
	rec, err := ipfw.NewParser("add deny ip from any to any").Next(&state)
	require.Nil(t, err)
	expected := passAnyToAny(1, "add deny ip from any to any")
	expected.Instruction.Action = ipfw.Action{Kind: ipfw.ActionDeny}
	require.Equal(t, expected, rec)
}

// verifies that the count action is recognized.
func Test_Parser_Next_ActionCount(t *testing.T) {
	nextError(t, ipfw.NewParser("add count _"), bodyError("add count _", 10))
	var state ipfw.CollectState
	rec, err := ipfw.NewParser("add count ip from any to any").Next(&state)
	require.Nil(t, err)
	expected := passAnyToAny(1, "add count ip from any to any")
	expected.Instruction.Action = ipfw.Action{Kind: ipfw.ActionCount}
	require.Equal(t, expected, rec)
}

// verifies that skipto takes a label, a rule number or tablearg after
// whitespace, a missing or unknown target being positioned after the keyword.
func Test_Parser_Next_ActionSkipTo(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{name: "label", input: "add skipto :ADMIN_RULES _", expected: bodyError("add skipto :ADMIN_RULES _", 24)},
		{name: "number", input: "add skipto 1500 _", expected: bodyError("add skipto 1500 _", 16)},
		{name: "tablearg", input: "add skipto tablearg _", expected: bodyError("add skipto tablearg _", 20)},
		{
			name:     "no whitespace",
			input:    "add skipto",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 10, Text: "add skipto"},
		},
		{
			name:     "keyword glued to a word",
			input:    "add skiptox _",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedWhitespace, Line: 1, Column: 10, Text: "add skiptox _"},
		},
		{
			name:     "unknown target",
			input:    "add skipto x",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedSkipTo, Line: 1, Column: 11, Text: "add skipto x"},
		},
		{
			name:     "label without a name",
			input:    "add skipto :",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedToken, Line: 1, Column: 12, Text: "add skipto :"},
		},
		{
			name:     "overflowing number",
			input:    "add skipto 4294967296",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedSkipTo, Line: 1, Column: 11, Text: "add skipto 4294967296"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}

	targets := []struct {
		name   string
		input  string
		num    uint32
		skipTo ipfw.SkipTo
	}{
		{name: "label", input: "add skipto :ADMIN_RULES ip from any to any", skipTo: ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "ADMIN_RULES"}},
		{name: "number", input: "add 100 skipto 200 ip from any to any", num: 100, skipTo: ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 200}},
		{name: "tablearg", input: "add skipto tablearg ip from any to any", skipTo: ipfw.SkipTo{Kind: ipfw.SkipToTableArg}},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.CollectState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			expected := passAnyToAny(1, tc.input)
			expected.Instruction.Num = tc.num
			expected.Instruction.Action = ipfw.Action{Kind: ipfw.ActionSkipTo, SkipTo: tc.skipTo}
			require.Equal(t, expected, rec)
			require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
		})
	}
}

// verifies that a check-state rule has no body: the line ends right after
// the optional flow name, and anything else there is trailing content.
func Test_Parser_Next_ActionCheckState(t *testing.T) {
	checkState := func(line int, text, flow string, num uint32) ipfw.Record {
		return ipfw.Record{
			Line:        line,
			Text:        text,
			Kind:        ipfw.RecordInstruction,
			Instruction: ipfw.Instruction{Num: num, Action: ipfw.Action{Kind: ipfw.ActionCheckState, Flow: flow}},
		}
	}
	next(t, ipfw.NewParser("add check-state :any\n"), checkState(1, "add check-state :any", "any", 0))
	next(t, ipfw.NewParser("add check-state"), checkState(1, "add check-state", "", 0))
	next(t, ipfw.NewParser("add 10 check-state :x\n"), checkState(1, "add 10 check-state :x", "x", 10))

	parser := ipfw.NewParser("add check-state :any\nadd pass ip from any to any\n")
	next(t, parser, checkState(1, "add check-state :any", "any", 0))
	var state ipfw.CollectState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(2, "add pass ip from any to any"), rec)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
	next(t, parser, eof)

	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:     "colon without a name",
			input:    "add check-state :\n",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 16, Text: "add check-state :"},
		},
		{
			name:     "word after the keyword",
			input:    "add check-state foo",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 16, Text: "add check-state foo"},
		},
		{
			name:     "inline comment is not accepted either",
			input:    "add check-state // c",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 16, Text: "add check-state // c"},
		},
		{
			name:     "keyword glued to a word",
			input:    "add check-statex",
			expected: ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 15, Text: "add check-statex"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that an action prints the way it is written in a ruleset.
func Test_Action_String(t *testing.T) {
	cases := []struct {
		name   string
		action ipfw.Action
		text   string
	}{
		{name: "pass", action: ipfw.Action{Kind: ipfw.ActionPass}, text: "pass"},
		{name: "deny", action: ipfw.Action{Kind: ipfw.ActionDeny}, text: "deny"},
		{name: "count", action: ipfw.Action{Kind: ipfw.ActionCount}, text: "count"},
		{
			name:   "skipto label",
			action: ipfw.Action{Kind: ipfw.ActionSkipTo, SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "ADMIN_RULES"}},
			text:   "skipto :ADMIN_RULES",
		},
		{
			name:   "skipto number",
			action: ipfw.Action{Kind: ipfw.ActionSkipTo, SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 100}},
			text:   "skipto 100",
		},
		{
			name:   "skipto tablearg",
			action: ipfw.Action{Kind: ipfw.ActionSkipTo, SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToTableArg}},
			text:   "skipto tablearg",
		},
		{name: "check-state", action: ipfw.Action{Kind: ipfw.ActionCheckState}, text: "check-state"},
		{name: "check-state with flow", action: ipfw.Action{Kind: ipfw.ActionCheckState, Flow: "any"}, text: "check-state :any"},
		{name: "zero value", action: ipfw.Action{}, text: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.text, tc.action.String())
		})
	}
}

// verifies that a skipto target prints the way it is written after skipto.
func Test_SkipTo_String(t *testing.T) {
	require.Equal(t, ":ADMIN_RULES", ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "ADMIN_RULES"}.String())
	require.Equal(t, "100", ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 100}.String())
	require.Equal(t, "tablearg", ipfw.SkipTo{Kind: ipfw.SkipToTableArg}.String())
	require.Empty(t, ipfw.SkipTo{}.String())
}
