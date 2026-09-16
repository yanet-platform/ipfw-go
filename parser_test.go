package ipfw_test

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/yanet-platform/ipfw-go"
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

// verifies that comment-only rules are count instructions with implicit any targets.
func Test_Parser_Next_CommentOnlyRule(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		comment  string
		expected ipfw.Record
	}{
		{
			name:    "comment with LF",
			input:   "add // note\n",
			comment: " note",
			expected: ipfw.Record{
				Line: 1,
				Text: "add // note",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Action: ipfw.Action{Kind: ipfw.ActionCount},
				},
			},
		},
		{
			name:    "number and hash metadata with CRLF",
			input:   "\tadd 100 // note \t# metadata \t\r\n",
			comment: " note",
			expected: ipfw.Record{
				Line:    1,
				Text:    "add 100 // note \t# metadata",
				Kind:    ipfw.RecordInstruction,
				Comment: " metadata",
				Instruction: ipfw.Instruction{
					Num:    100,
					Action: ipfw.Action{Kind: ipfw.ActionCount},
				},
			},
		},
		{
			name:  "empty comment at EOF",
			input: "add //",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add //",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionCount}},
			},
		},
		{
			name:  "empty comment with LF",
			input: "add //\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add //",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionCount}},
			},
		},
		{
			name:  "empty comment with CRLF",
			input: "add //\r\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add //",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionCount}},
			},
		},
		{
			name:  "empty comment before adjacent hash",
			input: "add //# metadata\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add //# metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     " metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionCount}},
			},
		},
		{
			name:    "comment content is not rule syntax",
			input:   "add 200 //\tdeny log tcp from any to any in // more \t",
			comment: "\tdeny log tcp from any to any in // more",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 200 //\tdeny log tcp from any to any in // more",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    200,
					Action: ipfw.Action{Kind: ipfw.ActionCount},
				},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			parser := ipfw.NewParser(test.input)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, test.expected, *record)
			require.Equal(t, ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptComment, Text: test.comment}},
			}, state)
			next(t, parser, eof)
		})
	}
}

// verifies that comment-only rules clear prior metadata and preserve streaming through an error.
func Test_Parser_Next_CommentOnlyRuleStreaming(t *testing.T) {
	parser := ipfw.NewParser(ruleset(`
		add 5 skipto 10 log logamount 3 tag 7 tcp from 192.0.2.1 443 to any in // prior # hash
		add 10 // first
		add 20 //joined
		add pass ip from any to any
	`))
	var state ipfw.ReduceState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:    1,
		Text:    "add 5 skipto 10 log logamount 3 tag 7 tcp from 192.0.2.1 443 to any in // prior # hash",
		Kind:    ipfw.RecordInstruction,
		Comment: " hash",
		Instruction: ipfw.Instruction{
			Num: 5,
			Action: ipfw.Action{
				Kind:   ipfw.ActionSkipTo,
				SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 10},
			},
			Log: ipfw.Log{Enabled: true, HasAmount: true, Amount: 3},
			Tag: 7,
		},
	}, *record)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		SourcePorts:  []ipfw.PortMatch{portNumber(443)},
		Options: []ipfw.Opt{
			{Kind: ipfw.OptIn},
			{Kind: ipfw.OptComment, Text: " prior"},
		},
	}, state)
	state.Reset()
	record, err = parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line: 2,
		Text: "add 10 // first",
		Kind: ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{
			Num:    10,
			Action: ipfw.Action{Kind: ipfw.ActionCount},
		},
	}, *record)
	require.Equal(t, ipfw.ReduceState{
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		Options:      []ipfw.Opt{{Kind: ipfw.OptComment, Text: " first"}},
	}, emptyToNil(state))
	state.Reset()
	record, err = parser.Next(&state)
	require.Nil(t, record)
	require.Equal(t, &ipfw.ParseError{
		Kind:   ipfw.ErrExpectedAction,
		Line:   3,
		Column: 7,
		Text:   "add 20 //joined",
	}, err)
	require.Equal(t, ipfw.ReduceState{}, emptyToNil(state))
	record, err = parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(4, "add pass ip from any to any"), *record)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), emptyToNil(state))
	next(t, parser, eof)
}

// verifies that incomplete or joined slash actions remain positioned errors.
func Test_Parser_Next_CommentOnlyRuleInvalidAction(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "single slash", input: "add /"},
		{name: "three slashes", input: "add ///"},
		{name: "joined payload", input: "add //note"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			parser := ipfw.NewParser(test.input)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.Equal(t, &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 4,
				Text:   test.input,
			}, err)
			require.Equal(t, ipfw.ReduceState{}, state)
			next(t, parser, eof)
		})
	}
}

// verifies that implicit target rejection is positioned at the comment action.
func Test_Parser_Next_CommentOnlyRuleCallbackFailure(t *testing.T) {
	failure := errors.New("target rejected")
	cases := []struct {
		name  string
		state commentRejectingState
		kind  ipfw.ErrorKind
		cause error
		want  ipfw.ReduceState
	}{
		{
			name:  "source error kind",
			state: commentRejectingState{SourceError: ipfw.ErrExpectedTarget},
			kind:  ipfw.ErrExpectedTarget,
		},
		{
			name:  "destination error cause",
			state: commentRejectingState{DestinationError: failure},
			kind:  ipfw.ErrState,
			cause: failure,
			want: ipfw.ReduceState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "comment error kind",
			state: commentRejectingState{OptionError: ipfw.ErrUnknownOption},
			kind:  ipfw.ErrUnknownOption,
			want: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			parser := ipfw.NewParser("add 100 // note # metadata\n")
			record, err := parser.Next(&test.state)
			require.Nil(t, record)
			require.Equal(t, &ipfw.ParseError{
				Kind:   test.kind,
				Err:    test.cause,
				Line:   1,
				Column: 8,
				Text:   "add 100 // note # metadata",
			}, err)
			require.ErrorIs(t, err, test.kind)
			if test.cause != nil {
				require.ErrorIs(t, err, test.cause)
			}
			require.Equal(t, test.want, test.state.ReduceState)
			next(t, parser, eof)
		})
	}
}

// commentRejectingState rejects one implicit target or the comment and retains earlier callbacks.
type commentRejectingState struct {
	ipfw.ReduceState
	SourceError      error
	DestinationError error
	OptionError      error
}

// OnSourceTarget implements State.
func (m *commentRejectingState) OnSourceTarget(target ipfw.Target) error {
	if m.SourceError != nil {
		return m.SourceError
	}
	return m.ReduceState.OnSourceTarget(target)
}

// OnDestinationTarget implements State.
func (m *commentRejectingState) OnDestinationTarget(target ipfw.Target) error {
	if m.DestinationError != nil {
		return m.DestinationError
	}
	return m.ReduceState.OnDestinationTarget(target)
}

// OnOption implements State.
func (m *commentRejectingState) OnOption(opt ipfw.Opt) error {
	if m.OptionError != nil {
		return m.OptionError
	}
	return m.ReduceState.OnOption(opt)
}

// verifies that parsing a comment-only count rule allocates nothing.
func Test_Parser_Next_CommentOnlyRuleNoAllocs(t *testing.T) {
	const input = "add 100 // note # metadata\n"
	parser := ipfw.NewParser(input)
	var state ipfw.ReduceState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.ActionCount, record.Instruction.Action.Kind)
	valid := true
	allocs := testing.AllocsPerRun(1000, func() {
		parser.Reset(input)
		state.Reset()
		record, err := parser.Next(&state)
		if err != nil || record.Instruction.Action.Kind != ipfw.ActionCount {
			valid = false
		}
	})
	require.True(t, valid)
	require.Zero(t, allocs)
	require.Equal(t, ipfw.ReduceState{
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		Options:      []ipfw.Opt{{Kind: ipfw.OptComment, Text: " note"}},
	}, state)
}

// verifies that trailing hash metadata leaves the complete rule and body intact.
func Test_Parser_Next_TrailingHashComment(t *testing.T) {
	const input = "add pass ip from any to any # {\"id\": \"HASH-7\"}\n"
	parser := ipfw.NewParser(input)
	var state ipfw.ReduceState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line:        1,
		Text:        `add pass ip from any to any # {"id": "HASH-7"}`,
		Kind:        ipfw.RecordInstruction,
		Comment:     ` {"id": "HASH-7"}`,
		Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
	}, *record)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
	next(t, parser, eof)
}

// verifies that quoting inside a slash comment does not hide the first hash separator.
func Test_Parser_Next_HashCommentInQuotedText(t *testing.T) {
	const input = `add pass ip from any to any // {"id": "before#after"}`
	parser := ipfw.NewParser(input)
	var state ipfw.ReduceState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	expected := passAnyToAny(1, input)
	expected.Comment = `after"}`
	require.Equal(t, expected, *record)
	expectedState := anyToAnyState(ipfw.ProtoIPAny)
	expectedState.Options = []ipfw.Opt{{Kind: ipfw.OptComment, Text: ` {"id": "before`}}
	require.Equal(t, expectedState, state)
	next(t, parser, eof)
}

// verifies that the first hash separates borrowed metadata for every supported record kind.
func Test_Parser_Next_HashComments(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		options  []ipfw.ParserOption
		expected ipfw.Record
		state    ipfw.ReduceState
	}{
		{
			name:  "rule with LF",
			input: "\t add pass ip from any to any # metadata \t\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any # metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     " metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "rule with CRLF",
			input: "\t add pass ip from any to any # metadata \t\r\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any # metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     " metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "rule at EOF",
			input: "\t add pass ip from any to any # metadata \t",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any # metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     " metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "empty rule comment",
			input: "add pass ip from any to any # \t\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any #",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "adjacent empty rule comment",
			input: "add pass ip from any to any#",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any#",
				Kind:        ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "adjacent rule metadata",
			input: "add pass ip from any to any#metadata\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any#metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     "metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "check-state",
			input: "add check-state# metadata\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add check-state# metadata",
				Kind:        ipfw.RecordInstruction,
				Comment:     " metadata",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionCheckState}},
			},
		},
		{
			name:  "table create",
			input: "table META create type addr#metadata\n",
			expected: ipfw.Record{
				Line:    1,
				Text:    "table META create type addr#metadata",
				Kind:    ipfw.RecordTable,
				Comment: "metadata",
				Table:   ipfw.Table{Name: "META", Kind: ipfw.TableCreate, Type: ipfw.TableTypeAddr},
			},
		},
		{
			name:  "table key without value",
			input: "table META add 192.0.2.0/24# key\n",
			expected: ipfw.Record{
				Line:    1,
				Text:    "table META add 192.0.2.0/24# key",
				Kind:    ipfw.RecordTable,
				Comment: " key",
				Table: ipfw.Table{
					Name: "META",
					Kind: ipfw.TableAdd,
					Key:  ipfw.TableKey{Kind: ipfw.TableKeyNetwork4, Text: "192.0.2.0/24"},
				},
			},
		},
		{
			name:  "table key with value",
			input: "table META add 2001:db8::/32 :NEXT# value\r\n",
			expected: ipfw.Record{
				Line:    1,
				Text:    "table META add 2001:db8::/32 :NEXT# value",
				Kind:    ipfw.RecordTable,
				Comment: " value",
				Table: ipfw.Table{
					Name:  "META",
					Kind:  ipfw.TableAdd,
					Key:   ipfw.TableKey{Kind: ipfw.TableKeyNetwork6, Text: "2001:db8::/32"},
					Value: ":NEXT",
				},
			},
		},
		{
			name:    "label",
			input:   ":NEXT# label\n",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			expected: ipfw.Record{
				Line:    1,
				Text:    ":NEXT# label",
				Kind:    ipfw.RecordLabel,
				Comment: " label",
				Label:   "NEXT",
			},
		},
		{
			name:  "standalone JSON metadata",
			input: "\t # \t{\"id\": \"HASH-7\", \"enabled\": true} \t\r\n",
			expected: ipfw.Record{
				Line:    1,
				Text:    "# \t{\"id\": \"HASH-7\", \"enabled\": true}",
				Kind:    ipfw.RecordComment,
				Comment: " \t{\"id\": \"HASH-7\", \"enabled\": true}",
			},
		},
		{
			name:     "standalone empty comment",
			input:    "#",
			expected: ipfw.Record{Line: 1, Text: "#", Kind: ipfw.RecordComment},
		},
		{
			name:     "standalone whitespace comment",
			input:    "\t # \t\n",
			expected: ipfw.Record{Line: 1, Text: "#", Kind: ipfw.RecordComment},
		},
		{
			name:  "repeated hashes",
			input: "add pass ip from any to any ##first # second\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any ##first # second",
				Kind:        ipfw.RecordInstruction,
				Comment:     "#first # second",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "carriage return in payload",
			input: "add pass ip from any to any # left\rright\n",
			expected: ipfw.Record{
				Line:        1,
				Text:        "add pass ip from any to any # left\rright",
				Kind:        ipfw.RecordInstruction,
				Comment:     " left\rright",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "rule slash comment",
			input: "add pass ip from any to any // {\"id\": \"SLASH-4\"} # metadata\n",
			expected: ipfw.Record{
				Line:    1,
				Text:    `add pass ip from any to any // {"id": "SLASH-4"} # metadata`,
				Kind:    ipfw.RecordInstruction,
				Comment: " metadata",
				Instruction: ipfw.Instruction{
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptComment, Text: ` {"id": "SLASH-4"}`}},
			},
		},
		{
			name:  "check-state slash comment",
			input: "add check-state // state#metadata",
			expected: ipfw.Record{
				Line:    1,
				Text:    "add check-state // state#metadata",
				Kind:    ipfw.RecordInstruction,
				Comment: "metadata",
				Instruction: ipfw.Instruction{
					Action: ipfw.Action{Kind: ipfw.ActionCheckState},
				},
			},
			state: ipfw.ReduceState{
				Options: []ipfw.Opt{{Kind: ipfw.OptComment, Text: " state"}},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input, testCase.options...)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, testCase.expected, *record)
			require.Equal(t, testCase.state, state)
			next(t, parser, eof)
		})
	}
}

// verifies that hash metadata neither changes decimal ports nor flattens trailing options.
func Test_Parser_Next_HashCommentPortOptions(t *testing.T) {
	const input = "add pass tcp from any 00443 to any 00443 " +
		"not src-port 00443 { dst-port 08443 or proto ipv6 }# guard"
	parser := ipfw.NewParser(input + "\n")
	var state ipfw.ReduceState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	expected := passAnyToAny(1, input)
	expected.Comment = " guard"
	require.Equal(t, expected, *record)
	require.Equal(t, ipfw.ReduceState{
		Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations:     []ipfw.Target{{Kind: ipfw.TargetAny}},
		SourcePorts:      []ipfw.PortMatch{portNumber(443)},
		DestinationPorts: []ipfw.PortMatch{portNumber(443)},
		Options: []ipfw.Opt{
			notOpt(srcPort(443)),
			dstPort(8443),
			{Or: true, Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "ipv6"}},
		},
	}, state)
	next(t, parser, eof)
}

// verifies that a hash keeps exact failures and partial state at the invalid prefix.
func Test_Parser_Next_HashCommentErrors(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		options []ipfw.ParserOption
		kind    ipfw.ErrorKind
		column  int
		state   ipfw.ReduceState
	}{
		{
			name:   "missing command whitespace",
			input:  "add# metadata",
			kind:   ipfw.ErrExpectedWhitespace,
			column: 3,
		},
		{
			name:   "missing action",
			input:  "add # metadata",
			kind:   ipfw.ErrExpectedAction,
			column: 4,
		},
		{
			name:   "missing destination",
			input:  "add pass ip from any to # metadata",
			kind:   ipfw.ErrExpectedTarget,
			column: 24,
			state: ipfw.ReduceState{
				IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:  []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:   "unclosed option group",
			input:  "add pass ip from any to any { in # metadata",
			kind:   ipfw.ErrExpectedOr,
			column: len("add pass ip from any to any { in "),
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:   "dangling or in option group",
			input:  "add pass ip from any to any { in or # metadata",
			kind:   ipfw.ErrUnknownOption,
			column: len("add pass ip from any to any { in or "),
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:   "missing table command",
			input:  "table META # metadata",
			kind:   ipfw.ErrExpectedTableCommand,
			column: 11,
		},
		{
			name:   "missing table key",
			input:  "table META add # metadata",
			kind:   ipfw.ErrExpectedTableKey,
			column: 15,
		},
		{
			name:   "missing table type",
			input:  "table META create type # metadata",
			kind:   ipfw.ErrExpectedTableType,
			column: 23,
		},
		{
			name:    "missing label",
			input:   ":# metadata",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			kind:    ipfw.ErrExpectedToken,
			column:  1,
		},
		{
			name:    "label with trailing token",
			input:   ":NEXT extra# metadata",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			kind:    ipfw.ErrExpectedNewlineOrEOF,
			column:  6,
		},
		{
			name:  "standalone slash comment",
			input: "// legacy# metadata",
			kind:  ipfw.ErrExpectedLine,
		},
		{
			name:   "table slash comment",
			input:  "table META create // legacy# metadata",
			kind:   ipfw.ErrExpectedNewlineOrEOF,
			column: 18,
		},
		{
			name:    "label slash comment",
			input:   ":NEXT // legacy# metadata",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			kind:    ipfw.ErrExpectedNewlineOrEOF,
			column:  6,
		},
		{
			name:    "lone carriage return before hash",
			input:   ":NEXT\r# metadata",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			kind:    ipfw.ErrExpectedNewlineOrEOF,
			column:  5,
		},
		{
			name:   "source-position src-port",
			input:  "add pass tcp from any src-port 00443 to any# excluded",
			kind:   ipfw.ErrExpectedPrefix,
			column: 31,
			state: ipfw.ReduceState{
				Protos:  []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources: []ipfw.Target{{Kind: ipfw.TargetAny}},
				SourcePorts: []ipfw.PortMatch{
					portSpan(ipfw.Port{Name: "src"}, ipfw.Port{Name: "port"}),
				},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input, testCase.options...)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.NotNil(t, err)
			require.Equal(t, ipfw.ParseError{
				Kind:   testCase.kind,
				Line:   1,
				Column: testCase.column,
				Text:   testCase.input,
			}, *err)
			require.Equal(t, testCase.state, state)
			next(t, parser, eof)
		})
	}
}

// verifies that saved records survive later lines and resets without comment carryover.
func Test_Parser_Next_HashCommentStreaming(t *testing.T) {
	source := ruleset(`
		add pass ip from any to any
		add pass ip from any to any // slash # hash
		:NEXT# label
		add pass ip from any to any
		# final
	`)
	expected := []ipfw.Record{
		passAnyToAny(1, "add pass ip from any to any"),
		{
			Line:    2,
			Text:    "add pass ip from any to any // slash # hash",
			Kind:    ipfw.RecordInstruction,
			Comment: " hash",
			Instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
			},
		},
		{Line: 3, Text: ":NEXT# label", Kind: ipfw.RecordLabel, Comment: " label", Label: "NEXT"},
		passAnyToAny(4, "add pass ip from any to any"),
		{Line: 5, Text: "# final", Kind: ipfw.RecordComment, Comment: " final"},
	}
	parser := ipfw.NewParser(source, ipfw.WithLabels())
	var state ipfw.ReduceState
	var saved []ipfw.Record
	for _, expectedRecord := range expected {
		state.Reset()
		record, err := parser.Next(&state)
		require.Nil(t, err)
		require.Equal(t, expectedRecord, *record)
		expectedState := ipfw.ReduceState{}
		if expectedRecord.Kind == ipfw.RecordInstruction {
			expectedState = anyToAnyState(ipfw.ProtoIPAny)
		}
		if expectedRecord.Line == 2 {
			expectedState.Options = []ipfw.Opt{{Kind: ipfw.OptComment, Text: " slash"}}
		}
		require.Equal(t, expectedState, emptyToNil(state))
		saved = append(saved, *record)
	}
	next(t, parser, eof)
	parser.Reset("# replacement\n")
	next(t, parser, ipfw.Record{
		Line:    1,
		Text:    "# replacement",
		Kind:    ipfw.RecordComment,
		Comment: " replacement",
	})
	require.Equal(t, expected, saved)
}

// ruleset removes the opening newline and closing indentation from a rule literal.
func ruleset(text string) string {
	return strings.TrimRight(strings.TrimPrefix(text, "\n"), "\t ")
}

// verifies that an explicit state reset after a hash-commented failure clears partial tokens.
func Test_Parser_Next_HashCommentStateAfterFailure(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name: "LF",
			input: ruleset(`
				add pass tcp from 192.0.2.1 00443 to any in bogus # failed
				add pass ip from any to any # recovered
			`),
		},
		{
			name: "CRLF",
			input: "\t add pass tcp from 192.0.2.1 00443 to any in bogus # failed\r\n" +
				"add pass ip from any to any # recovered\r\n",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.NotNil(t, err)
			require.Equal(t, ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 44,
				Text:   "add pass tcp from 192.0.2.1 00443 to any in bogus # failed",
			}, *err)
			require.Equal(t, ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"}},
				SourcePorts:  []ipfw.PortMatch{portNumber(443)},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			}, state)

			state.Reset()
			record, err = parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line:        2,
				Text:        "add pass ip from any to any # recovered",
				Kind:        ipfw.RecordInstruction,
				Comment:     " recovered",
				Instruction: ipfw.Instruction{Action: ipfw.Action{Kind: ipfw.ActionPass}},
			}, *record)
			require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), emptyToNil(state))
			record, err = parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, eof, *record)
			require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), emptyToNil(state))
		})
	}
}

// verifies that hash-comment paths allocate nothing with an explicitly reset, warmed state.
func Test_Parser_Next_HashCommentsNoAllocs(t *testing.T) {
	source := ruleset(`
		add pass tcp from any 00443 to any 00443 not src-port 80 # rule
		add check-state // state # check
		table META create type addr# create
		table META add 192.0.2.0/24# key
		table META add 2001:db8::/32 :NEXT# value
		:NEXT# label
		# {"id": "HASH-7"}
	`)
	parser := ipfw.NewParser(source, ipfw.WithLabels())
	var state ipfw.ReduceState
	for range 7 {
		state.Reset()
		_, err := parser.Next(&state)
		require.Nil(t, err)
	}
	ok := true
	allocations := testing.AllocsPerRun(100, func() {
		parser.Reset(source)
		for range 7 {
			state.Reset()
			if _, err := parser.Next(&state); err != nil {
				ok = false
			}
		}
	})
	require.True(t, ok)
	require.Zero(t, allocations)
}

// verifies that label declarations require their own opt-in.
func Test_Parser_Next_LabelsOptIn(t *testing.T) {
	const input = ":EXAMPLE_NEXT\n"
	for _, testCase := range []struct {
		name     string
		accepted bool
		options  []ipfw.ParserOption
	}{
		{name: "default"},
		{name: "explicit labels", accepted: true, options: []ipfw.ParserOption{ipfw.WithLabels()}},
		{
			name: "option hook only",
			options: []ipfw.ParserOption{ipfw.WithOptionHook(func(string) (ipfw.Opt, int, error) {
				return ipfw.Opt{}, 0, ipfw.ErrUnknownOption
			})},
		},
		{
			name: "declining command hook only",
			options: []ipfw.ParserOption{
				ipfw.WithCommandHook(func(string, ipfw.State) (ipfw.Record, int, error) {
					return ipfw.Record{}, 0, nil
				}),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(input, testCase.options...)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			if !testCase.accepted {
				require.Nil(t, record)
				require.NotNil(t, err)
				require.Equal(t, ipfw.ParseError{
					Kind: ipfw.ErrExpectedLine, Line: 1, Column: 0, Text: ":EXAMPLE_NEXT",
				}, *err)
			} else {
				require.Nil(t, err)
				require.Equal(t, ipfw.Record{
					Line: 1, Text: ":EXAMPLE_NEXT", Kind: ipfw.RecordLabel, Label: "EXAMPLE_NEXT",
				}, *record)
			}
			require.Equal(t, ipfw.ReduceState{}, state)
			next(t, parser, eof)
		})
	}
}

// verifies that labels retain hash metadata and reject missing names or trailing tokens.
func Test_Parser_Next_Label(t *testing.T) {
	next(
		t,
		ipfw.NewParser(":ENDOFME\n", ipfw.WithLabels()),
		ipfw.Record{Line: 1, Text: ":ENDOFME", Kind: ipfw.RecordLabel, Label: "ENDOFME"},
	)
	next(
		t,
		ipfw.NewParser(":L  \n", ipfw.WithLabels()),
		ipfw.Record{Line: 1, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"},
	)
	nextError(
		t,
		ipfw.NewParser(":", ipfw.WithLabels()),
		ipfw.ParseError{Kind: ipfw.ErrExpectedToken, Line: 1, Column: 1, Text: ":"},
	)
	next(
		t,
		ipfw.NewParser(":X # c", ipfw.WithLabels()),
		ipfw.Record{Line: 1, Text: ":X # c", Kind: ipfw.RecordLabel, Comment: " c", Label: "X"},
	)
	nextError(
		t,
		ipfw.NewParser(":X // c", ipfw.WithLabels()),
		ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 3, Text: ":X // c"},
	)
}

// verifies that embedded slashes remain in label names when labels are enabled.
func Test_Parser_Next_LabelEmbeddedSlashes(t *testing.T) {
	const input = ":finish//part\n"
	parser := ipfw.NewParser(input, ipfw.WithLabels())
	next(t, parser, ipfw.Record{
		Line: 1, Text: ":finish//part", Kind: ipfw.RecordLabel, Label: "finish//part",
	})
	next(t, parser, eof)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that every physical line counts, blank ones included.
func Test_Parser_Next_LineNumbers(t *testing.T) {
	source := ruleset(`
		# a

		:L
	`)
	parser := ipfw.NewParser(source, ipfw.WithLabels())
	next(t, parser, ipfw.Record{Line: 1, Text: "# a", Kind: ipfw.RecordComment, Comment: " a"})
	next(t, parser, ipfw.Record{Line: 2, Kind: ipfw.RecordEmpty})
	next(t, parser, ipfw.Record{Line: 3, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
	next(t, parser, eof)
}

// verifies that CRLF preserves record text, error positions and advancement across physical lines.
func Test_Parser_Next_CRLF(t *testing.T) {
	t.Run("records", func(t *testing.T) {
		source := ruleset("\n\t\tadd pass ip from any to any \t\r\n\t\t\r\n\t\t:L\r\n\t")
		parser := ipfw.NewParser(source, ipfw.WithLabels())
		var state ipfw.ReduceState
		rec, err := parser.Next(&state)
		require.Nil(t, err)
		require.Equal(t, passAnyToAny(1, "add pass ip from any to any"), *rec)
		require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
		next(t, parser, ipfw.Record{Line: 2, Kind: ipfw.RecordEmpty})
		next(t, parser, ipfw.Record{Line: 3, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
		next(t, parser, eof)
	})

	t.Run("options", func(t *testing.T) {
		source := ruleset("\n\t\tadd 115 allow ip from any to any in \t\r\n\t\t# after\n\t")
		parser := ipfw.NewParser(source)
		var state ipfw.ReduceState
		record, err := parser.Next(&state)
		require.Nil(t, err)
		require.Equal(t, ipfw.Record{
			Line: 1,
			Text: "add 115 allow ip from any to any in",
			Kind: ipfw.RecordInstruction,
			Instruction: ipfw.Instruction{
				Num:    115,
				Action: ipfw.Action{Kind: ipfw.ActionPass},
			},
		}, *record)
		require.Equal(t, ipfw.ReduceState{
			IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
			Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
			Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
		}, state)
		next(t, parser, ipfw.Record{
			Line: 2, Text: "# after", Kind: ipfw.RecordComment, Comment: " after",
		})
		next(t, parser, eof)
	})

	t.Run("positioned error", func(t *testing.T) {
		source := ruleset("\n\t\t:X y\t\r\n\t\t:L\r\n\t")
		parser := ipfw.NewParser(source, ipfw.WithLabels())
		nextError(
			t,
			parser,
			ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 3,
				Text:   ":X y",
			},
		)
		next(t, parser, ipfw.Record{Line: 2, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
		next(t, parser, eof)
	})
}

// verifies that the last line needs no newline.
func Test_Parser_Next_NoTrailingNewline(t *testing.T) {
	parser := ipfw.NewParser(":L", ipfw.WithLabels())
	next(t, parser, ipfw.Record{Line: 1, Text: ":L", Kind: ipfw.RecordLabel, Label: "L"})
	next(t, parser, eof)
}

// verifies that a failing line is consumed and the next call parses the following line.
func Test_Parser_Next_SkipsFailedLine(t *testing.T) {
	source := ruleset(`
		bad line
		:L
	`)
	parser := ipfw.NewParser(source, ipfw.WithLabels())
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
		ipfw.NewParser("\t:X y\t\n", ipfw.WithLabels()),
		ipfw.ParseError{Kind: ipfw.ErrExpectedNewlineOrEOF, Line: 1, Column: 3, Text: ":X y"},
	)
}

// verifies that the iterator yields every record and stops after the first failure.
func Test_Parser_All_StopsAtError(t *testing.T) {
	source := ruleset(`
		:A
		# c
		bad
		:B
	`)
	parser := ipfw.NewParser(source, ipfw.WithLabels())
	var records []ipfw.Record
	var errs []*ipfw.ParseError
	for rec, err := range parser.Records(ipfw.DiscardState{}) {
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

// verifies that the iterator stops at EOF and honours an early break.
func Test_Parser_All_EOFAndBreak(t *testing.T) {
	source := ruleset(`
		:A
		:B
	`)
	count := 0
	for _, err := range ipfw.NewParser(source, ipfw.WithLabels()).Records(ipfw.DiscardState{}) {
		require.Nil(t, err)
		count++
	}
	require.Equal(t, 2, count)

	count = 0
	for range ipfw.NewParser(source, ipfw.WithLabels()).Records(ipfw.DiscardState{}) {
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
	single := ipfw.PortMatch{Lo: ipfw.Port{Number: 1}, Hi: ipfw.Port{Number: 1}}
	span := ipfw.PortMatch{Neg: true, Lo: ipfw.Port{Number: 2}, Hi: ipfw.Port{Number: 3}}
	require.NoError(t, state.OnSourcePort(single))
	require.NoError(t, state.OnDestinationPort(span))
	require.NoError(t, state.OnOption(ipfw.Opt{Kind: ipfw.OptIn}))
	require.NoError(t, state.OnOption(ipfw.Opt{Kind: ipfw.OptOut, Or: true}))
	require.Equal(t, ipfw.ReduceState{
		IPProtos:         []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPv4}},
		Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations:     []ipfw.Target{{Kind: ipfw.TargetMe}},
		SourcePorts:      []ipfw.PortMatch{single},
		DestinationPorts: []ipfw.PortMatch{span},
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

// verifies that repeated parsing of comments, labels and blank lines allocates nothing.
func Test_Parser_Next_NoAllocs(t *testing.T) {
	src := ruleset(`
		# c
		:L

	`)
	parser := ipfw.NewParser(src, ipfw.WithLabels())
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

// verifies that pass aliases parse by prefix and invalid actions fail at the expected position.
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
		{
			name:     "numbered rule",
			input:    "add 100 permit _",
			expected: bodyError("add 100 permit _", 15),
		},
		{
			name:  "prefix match then whitespace expected",
			input: "add passthru x",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 8,
				Text:   "add passthru x",
			},
		},
		{
			name:  "truncated keyword",
			input: "add pas ip",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 4,
				Text:   "add pas ip",
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
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add accept ip from any to any\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, "add accept ip from any to any"), *rec)
}

// bodyError is the failure of a line whose body is `_`, a token that is
// never a protocol: reaching it proves the header before it parsed.
func bodyError(text string, column int) ipfw.ParseError {
	return ipfw.ParseError{
		Kind:   ipfw.ErrExpectedEitherIPOrProto,
		Line:   1,
		Column: column,
		Text:   text,
	}
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
			name:  "prefix match then whitespace expected",
			input: "add denyall _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 8,
				Text:   "add denyall _",
			},
		},
		{
			name:  "denied is not deny",
			input: "add denied _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedAction,
				Line:   1,
				Column: 4,
				Text:   "add denied _",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add deny ip from any to any").Next(&state)
	require.Nil(t, err)
	expected := passAnyToAny(1, "add deny ip from any to any")
	expected.Instruction.Action = ipfw.Action{Kind: ipfw.ActionDeny}
	require.Equal(t, expected, *rec)
}

// verifies that the count action is recognized.
func Test_Parser_Next_ActionCount(t *testing.T) {
	nextError(t, ipfw.NewParser("add count _"), bodyError("add count _", 10))
	var state ipfw.ReduceState
	rec, err := ipfw.NewParser("add count ip from any to any").Next(&state)
	require.Nil(t, err)
	expected := passAnyToAny(1, "add count ip from any to any")
	expected.Instruction.Action = ipfw.Action{Kind: ipfw.ActionCount}
	require.Equal(t, expected, *rec)
}

// verifies that symbolic skipto requires the explicit label option.
func Test_Parser_Next_SkipToLabelsOptIn(t *testing.T) {
	const input = "add skipto :EXAMPLE_NEXT ip from any to any"
	for _, testCase := range []struct {
		name    string
		labels  bool
		options []ipfw.ParserOption
	}{
		{name: "default"},
		{name: "labels", labels: true, options: []ipfw.ParserOption{ipfw.WithLabels()}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(input, testCase.options...)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			if testCase.labels {
				require.Nil(t, err)
				require.Equal(t, ipfw.Record{
					Line: 1, Text: input, Kind: ipfw.RecordInstruction,
					Instruction: ipfw.Instruction{Action: ipfw.Action{
						Kind:   ipfw.ActionSkipTo,
						SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "EXAMPLE_NEXT"},
					}},
				}, *record)
				require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
			} else {
				require.Nil(t, record)
				require.NotNil(t, err)
				require.Equal(t, ipfw.ParseError{
					Kind: ipfw.ErrExpectedSkipTo, Line: 1, Column: 11, Text: input,
				}, *err)
				require.Equal(t, ipfw.ReduceState{}, state)
			}
			next(t, parser, eof)
		})
	}
}

// verifies that numeric jumps and state-flow names retain their default syntax and metadata.
func Test_Parser_Next_StandardActionsWithoutCompatibility(t *testing.T) {
	rule := ipfw.Opt{Kind: ipfw.OptComment, Text: " rule"}
	cases := []struct {
		name   string
		input  string
		action ipfw.Action
		state  ipfw.ReduceState
	}{
		{
			name: "numeric jump", input: "add skipto 100 ip from any to any // rule # hash",
			action: ipfw.Action{
				Kind: ipfw.ActionSkipTo, SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 100},
			},
			state: withOptions(anyToAnyState(ipfw.ProtoIPAny), rule),
		},
		{
			name: "tablearg", input: "add skipto tablearg ip from any to any // rule # hash",
			action: ipfw.Action{Kind: ipfw.ActionSkipTo, SkipTo: ipfw.SkipTo{Kind: ipfw.SkipToTableArg}},
			state:  withOptions(anyToAnyState(ipfw.ProtoIPAny), rule),
		},
		{
			name: "state flow", input: "add check-state :flow // rule # hash",
			action: ipfw.Action{Kind: ipfw.ActionCheckState, Flow: "flow"},
			state:  withOptions(ipfw.ReduceState{}, rule),
		},
		{
			name: "keep flow", input: "add pass ip from any to any keep-state :flow // rule # hash",
			action: ipfw.Action{Kind: ipfw.ActionPass},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptKeepState, Text: "flow"}, rule},
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parser := ipfw.NewParser(testCase.input)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, ipfw.Record{
				Line: 1, Text: testCase.input, Kind: ipfw.RecordInstruction, Comment: " hash",
				Instruction: ipfw.Instruction{Action: testCase.action},
			}, *record)
			require.Equal(t, testCase.state, state)
			next(t, parser, eof)
		})
	}
}

// verifies that skipto accepts enabled labels, positive numbers and tablearg, with exact errors.
func Test_Parser_Next_ActionSkipTo(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		options  []ipfw.ParserOption
		expected ipfw.ParseError
	}{
		{
			name:     "label",
			input:    "add skipto :ADMIN_RULES _",
			options:  []ipfw.ParserOption{ipfw.WithLabels()},
			expected: bodyError("add skipto :ADMIN_RULES _", 24),
		},
		{name: "number", input: "add skipto 1500 _", expected: bodyError("add skipto 1500 _", 16)},
		{
			name:     "tablearg",
			input:    "add skipto tablearg _",
			expected: bodyError("add skipto tablearg _", 20),
		},
		{
			name:  "no whitespace",
			input: "add skipto",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 10,
				Text:   "add skipto",
			},
		},
		{
			name:  "keyword glued to a word",
			input: "add skiptox _",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 10,
				Text:   "add skiptox _",
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
		{
			name:    "label without a name",
			input:   "add skipto :",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedToken,
				Line:   1,
				Column: 12,
				Text:   "add skipto :",
			},
		},
		{
			name:  "overflowing number",
			input: "add skipto 4294967296",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedSkipTo,
				Line:   1,
				Column: 11,
				Text:   "add skipto 4294967296",
			},
		},
		{
			name:  "zero target",
			input: "add skipto 0",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedSkipTo,
				Line:   1,
				Column: 11,
				Text:   "add skipto 0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input, tc.options...), tc.expected)
		})
	}

	targets := []struct {
		name    string
		input   string
		options []ipfw.ParserOption
		num     uint32
		skipTo  ipfw.SkipTo
	}{
		{
			name:    "label",
			input:   "add skipto :ADMIN_RULES ip from any to any",
			options: []ipfw.ParserOption{ipfw.WithLabels()},
			skipTo:  ipfw.SkipTo{Kind: ipfw.SkipToLabel, Label: "ADMIN_RULES"},
		},
		{
			name:   "number",
			input:  "add 100 skipto 200 ip from any to any",
			num:    100,
			skipTo: ipfw.SkipTo{Kind: ipfw.SkipToNumber, Number: 200},
		},
		{
			name:   "tablearg",
			input:  "add skipto tablearg ip from any to any",
			skipTo: ipfw.SkipTo{Kind: ipfw.SkipToTableArg},
		},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input, tc.options...).Next(&state)
			require.Nil(t, err)
			expected := passAnyToAny(1, tc.input)
			expected.Instruction.Num = tc.num
			expected.Instruction.Action = ipfw.Action{Kind: ipfw.ActionSkipTo, SkipTo: tc.skipTo}
			require.Equal(t, expected, *rec)
			require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), state)
		})
	}
}

// verifies that check-state accepts an optional flow and comment, rejecting other trailing tokens.
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

	source := ruleset(`
		add check-state :any // comment
		add pass ip from any to any
	`)
	parser := ipfw.NewParser(source)
	var state ipfw.ReduceState
	rec, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, checkState(1, "add check-state :any // comment", "any", 0), *rec)
	require.Equal(t, ipfw.ReduceState{
		Options: []ipfw.Opt{{Kind: ipfw.OptComment, Text: " comment"}},
	}, state)
	state.Reset()
	rec, err = parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(2, "add pass ip from any to any"), *rec)
	require.Equal(t, anyToAnyState(ipfw.ProtoIPAny), emptyToNil(state))
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
			name:  "keyword glued to a word",
			input: "add check-statex",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 15,
				Text:   "add check-statex",
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
			name:  "proto group separator glued to its element",
			input: "add pass { tcp orudp } from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 15,
				Text:   "add pass { tcp orudp } from any to any",
			},
		},
		{
			name:  "protocol negation before a closing brace",
			input: "add pass { not} from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 11,
				Text:   "add pass { not} from any to any",
			},
		},
		{
			name:  "protocol negation after a group alternative",
			input: "add pass { tcp or not} from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 18,
				Text:   "add pass { tcp or not} from any to any",
			},
		},
		{
			name:  "target negation before a closing brace",
			input: "add pass ip from { not} to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 22,
				Text:   "add pass ip from { not} to any",
			},
		},
		{
			name:  "target negation after a group alternative",
			input: "add pass ip from { any or not} to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 29,
				Text:   "add pass ip from { any or not} to any",
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
			name:  "nested source target group",
			input: "add pass ip from { {foo } to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 19,
				Text:   "add pass ip from { {foo } to any",
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
			name:  "empty source table name",
			input: "add allow ip from table() to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableName,
				Line:   1,
				Column: 18,
				Text:   "add allow ip from table() to any",
			},
		},
		{
			name:  "empty destination table name",
			input: "add allow ip from any to table()",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableName,
				Line:   1,
				Column: 25,
				Text:   "add allow ip from any to table()",
			},
		},
		{
			name:  "text after source table target",
			input: "add pass ip from table(a)b) to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 25,
				Text:   "add pass ip from table(a)b) to any",
			},
		},
		{
			name:  "text after destination table target",
			input: "add pass ip from any to table(a)b)",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 32,
				Text:   "add pass ip from any to table(a)b)",
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
			name:  "IPv4 source list contains IPv6",
			input: "add pass ip from 192.0.2.1,2001:db8::1 to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 27,
				Text:   "add pass ip from 192.0.2.1,2001:db8::1 to any",
			},
		},
		{
			name:  "IPv6 destination list contains IPv4",
			input: "add pass ip from any to 2001:db8::1,192.0.2.1",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 36,
				Text:   "add pass ip from any to 2001:db8::1,192.0.2.1",
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

// withOptions is the state with the options appended after its own.
func withOptions(state ipfw.ReduceState, options ...ipfw.Opt) ipfw.ReduceState {
	state.Options = append(state.Options, options...)
	return state
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

// verifies that option-only bodies preserve complete records and emit implicit any targets.
func Test_Parser_Next_OptionOnly(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.Record
		state    ipfw.ReduceState
	}{
		{
			name:  "direction with LF",
			input: "add 110 allow in\n",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 110 allow in",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    110,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "protocol option at EOF",
			input: "add 120 allow proto tcp",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 120 allow proto tcp",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    120,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options: []ipfw.Opt{
					{Kind: ipfw.OptProto, Proto: ipfw.Proto{Name: "tcp"}},
				},
			},
		},
		{
			name:  "interface with modifiers and both comments on CRLF",
			input: "\tadd 130 allow log logamount 3 tag 7 via vlan17 // memo \t# metadata \t\r\n",
			expected: ipfw.Record{
				Line:    1,
				Text:    "add 130 allow log logamount 3 tag 7 via vlan17 // memo \t# metadata",
				Kind:    ipfw.RecordInstruction,
				Comment: " metadata",
				Instruction: ipfw.Instruction{
					Num:    130,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
					Log:    ipfw.Log{Enabled: true, HasAmount: true, Amount: 3},
					Tag:    7,
				},
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options: []ipfw.Opt{
					{Kind: ipfw.OptVia, Via: ipfw.Via{Kind: ipfw.ViaExact, Name: "vlan17"}},
					{Kind: ipfw.OptComment, Text: " memo"},
				},
			},
		},
		{
			name:  "group with negation",
			input: "add 140 allow { not in or out }\n",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 140 allow { not in or out }",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    140,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options: []ipfw.Opt{
					{Neg: true, Kind: ipfw.OptIn},
					{Or: true, Kind: ipfw.OptOut},
				},
			},
		},
		{
			name:  "comment body at EOF",
			input: "add 150 allow // memo",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 150 allow // memo",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    150,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptComment, Text: " memo"}},
			},
		},
		{
			name:  "negated comment body",
			input: "add 155 allow not // never\n",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 155 allow not // never",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    155,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Neg: true, Kind: ipfw.OptComment, Text: " never"}},
			},
		},
		{
			name:  "complete legacy header takes precedence",
			input: "add 160 allow in from any to any\n",
			expected: ipfw.Record{
				Line: 1,
				Text: "add 160 allow in from any to any",
				Kind: ipfw.RecordInstruction,
				Instruction: ipfw.Instruction{
					Num:    160,
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			},
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "in"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			if strings.HasSuffix(input, "\n") {
				input += "# after"
			}
			parser := ipfw.NewParser(input)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, test.expected, *record)
			require.Equal(t, test.state, state)
			if strings.HasSuffix(test.input, "\n") {
				next(t, parser, ipfw.Record{
					Line:    2,
					Text:    "# after",
					Kind:    ipfw.RecordComment,
					Comment: " after",
				})
			}
			next(t, parser, eof)
		})
	}
}

// verifies that malformed option-only bodies retain exact errors, partial state and recovery.
func Test_Parser_Next_OptionOnlyErrors(t *testing.T) {
	failure := errors.New("custom option rejected")
	rejectingHook := func(string) (ipfw.Opt, int, error) {
		return ipfw.Opt{}, 0, failure
	}
	cases := []struct {
		name     string
		input    string
		hook     ipfw.OptionHook
		expected ipfw.ParseError
		state    ipfw.ReduceState
	}{
		{
			name:  "protocol option without an argument",
			input: "add 210 allow proto\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 19,
				Text:   "add 210 allow proto",
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "interface table without a name",
			input: "add 220 allow via table()\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableName,
				Line:   1,
				Column: 24,
				Text:   "add 220 allow via table()",
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "unknown first token preserves legacy failure",
			input: "add 230 allow mystery\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 21,
				Text:   "add 230 allow mystery",
			},
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "mystery"}}},
			},
		},
		{
			name:  "unknown later group member retains the first option",
			input: "add 240 allow { in or mystery }\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 22,
				Text:   "add 240 allow { in or mystery }",
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "empty body at EOF never reaches the hook",
			input: "add 250 allow ",
			hook:  rejectingHook,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 13,
				Text:   "add 250 allow",
			},
			state: ipfw.ReduceState{},
		},
		{
			name:  "empty body with LF never reaches the hook",
			input: "add 250 allow \n",
			hook:  rejectingHook,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 13,
				Text:   "add 250 allow",
			},
			state: ipfw.ReduceState{},
		},
		{
			name:  "empty body with CRLF never reaches the hook",
			input: "add 250 allow \r\n",
			hook:  rejectingHook,
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedEitherIPOrProto,
				Line:   1,
				Column: 13,
				Text:   "add 250 allow",
			},
			state: ipfw.ReduceState{},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			if strings.HasSuffix(input, "\n") {
				input += "# after"
			}
			hookCalls := 0
			hook := test.hook
			if hook != nil {
				hook = func(rest string) (ipfw.Opt, int, error) {
					hookCalls++
					return test.hook(rest)
				}
			}
			parser := ipfw.NewParser(input, ipfw.WithOptionHook(hook))
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.Equal(t, &test.expected, err)
			require.ErrorIs(t, err, test.expected.Kind)
			require.Equal(t, test.state, state)
			require.Zero(t, hookCalls)
			if strings.HasSuffix(test.input, "\n") {
				next(t, parser, ipfw.Record{
					Line:    2,
					Text:    "# after",
					Kind:    ipfw.RecordComment,
					Comment: " after",
				})
			}
			next(t, parser, eof)
		})
	}
}

// verifies that rejected implicit targets and legacy protocols stop the selected grammar.
func Test_Parser_Next_OptionOnlyStateError(t *testing.T) {
	failure := errors.New("implicit destination rejected")
	cases := []struct {
		name  string
		state commentRejectingState
		kind  ipfw.ErrorKind
		cause error
		want  ipfw.ReduceState
	}{
		{
			name:  "implicit source error kind",
			state: commentRejectingState{SourceError: ipfw.ErrExpectedTarget},
			kind:  ipfw.ErrExpectedTarget,
			want:  ipfw.ReduceState{},
		},
		{
			name:  "implicit destination error cause",
			state: commentRejectingState{DestinationError: failure},
			kind:  ipfw.ErrState,
			cause: failure,
			want: ipfw.ReduceState{
				Sources: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			parser := ipfw.NewParser(ruleset(`
				add 310 allow in proto tcp
				# after
			`))
			record, err := parser.Next(&test.state)
			require.Nil(t, record)
			require.Equal(t, &ipfw.ParseError{
				Kind:   test.kind,
				Err:    test.cause,
				Line:   1,
				Column: 14,
				Text:   "add 310 allow in proto tcp",
			}, err)
			require.ErrorIs(t, err, test.kind)
			if test.cause != nil {
				require.ErrorIs(t, err, test.cause)
			}
			require.Equal(t, test.want, test.state.ReduceState)
			next(t, parser, ipfw.Record{
				Line:    2,
				Text:    "# after",
				Kind:    ipfw.RecordComment,
				Comment: " after",
			})
			next(t, parser, eof)
		})
	}
	t.Run("legacy protocol error does not select options", func(t *testing.T) {
		parser := ipfw.NewParser(ruleset(`
			add 320 allow in from any to any
			# after
		`))
		state := &bodyRejectingProtoState{Error: ipfw.ErrExpectedFrom}
		record, err := parser.Next(state)
		require.Nil(t, record)
		require.Equal(t, &ipfw.ParseError{
			Kind:   ipfw.ErrExpectedFrom,
			Line:   1,
			Column: 14,
			Text:   "add 320 allow in from any to any",
		}, err)
		require.ErrorIs(t, err, ipfw.ErrExpectedFrom)
		require.Equal(t, ipfw.ReduceState{}, state.ReduceState)
		require.Equal(t, 1, state.ProtoCalls)
		next(t, parser, ipfw.Record{
			Line:    2,
			Text:    "# after",
			Kind:    ipfw.RecordComment,
			Comment: " after",
		})
		next(t, parser, eof)
	})
}

// bodyRejectingProtoState records protocol attempts and rejects the selected header.
type bodyRejectingProtoState struct {
	ipfw.ReduceState
	Error      error
	ProtoCalls int
}

// OnProto implements State.
func (m *bodyRejectingProtoState) OnProto(ipfw.ProtoMatch) error {
	m.ProtoCalls++
	return m.Error
}

// inAndTCP knows `in` and `tcp` as protocols, an option keyword among them.
var inAndTCP = ipfw.ProtoCheckerFunc(func(name string) bool {
	return name == "in" || name == "tcp"
})

// verifies that a proto checker commits a body to the legacy grammar exactly
// when its first protocol is known, whatever an option start would suggest.
func Test_Parser_Next_ProtoChecker(t *testing.T) {
	option := ipfw.Opt{Kind: ipfw.OptCustom, Text: "tcp:note"}
	hook := func(rest string) (ipfw.Opt, int, error) {
		if strings.HasPrefix(rest, "tcp:note") {
			return option, len("tcp:note"), nil
		}
		return ipfw.Opt{}, 0, nil
	}
	anyToAny := ipfw.ReduceState{
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}
	cases := []struct {
		name  string
		input string
		hook  ipfw.OptionHook
		state ipfw.ReduceState
	}{
		{
			name:  "known option-shaped protocol",
			input: "add pass in from any to any",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "in"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "unknown first name selects options",
			input: "add pass out",
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptOut}},
			},
		},
		{
			name:  "compact protocol group",
			input: "add pass {tcp} from any to any",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "punctuated option",
			input: "add pass tcp:note",
			hook:  hook,
			state: ipfw.ReduceState{
				Sources:      anyToAny.Sources,
				Destinations: anyToAny.Destinations,
				Options:      []ipfw.Opt{option},
			},
		},
		{
			name:  "grouped punctuated option",
			input: "add pass { tcp:note }",
			hook:  hook,
			state: ipfw.ReduceState{
				Sources:      anyToAny.Sources,
				Destinations: anyToAny.Destinations,
				Options:      []ipfw.Opt{option},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			parser := ipfw.NewParser(
				ruleset(test.input+"\n# after\n"),
				ipfw.WithProtoChecker(inAndTCP),
				ipfw.WithOptionHook(test.hook),
			)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, passAnyToAny(1, test.input), *record)
			require.Equal(t, test.state, state)
			next(t, parser, ipfw.Record{
				Line:    2,
				Text:    "# after",
				Kind:    ipfw.RecordComment,
				Comment: " after",
			})
			next(t, parser, eof)
		})
	}
}

// verifies that a body the proto checker commits to one grammar fails in that
// grammar rather than falling back to the other.
func Test_Parser_Next_ProtoCheckerErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
		state    ipfw.ReduceState
	}{
		{
			name:  "known option-shaped protocol needs from",
			input: "add allow in proto tcp",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedFrom,
				Line:   1,
				Column: 13,
				Text:   "add allow in proto tcp",
			},
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "in"}}},
			},
		},
		{
			name:  "known option-shaped protocol alone",
			input: "add allow in",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 12,
				Text:   "add allow in",
			},
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "in"}}},
			},
		},
		{
			name:  "unknown later group member keeps the legacy grammar",
			input: "add allow { not in or out }",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 27,
				Text:   "add allow { not in or out }",
			},
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{
					{Neg: true, Proto: ipfw.Proto{Name: "in"}},
					{Proto: ipfw.Proto{Name: "out"}},
				},
			},
		},
		{
			name:  "unknown protocol name selects options",
			input: "add allow udp from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 10,
				Text:   "add allow udp from any to any",
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "protocol zero is a name",
			input: "add allow 0 from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownOption,
				Line:   1,
				Column: 10,
				Text:   "add allow 0 from any to any",
			},
			state: ipfw.ReduceState{
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			parser := ipfw.NewParser(
				ruleset(test.input+"\n# after\n"),
				ipfw.WithProtoChecker(inAndTCP),
			)
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, record)
			require.Equal(t, &test.expected, err)
			require.Equal(t, test.state, state)
			next(t, parser, ipfw.Record{
				Line:    2,
				Text:    "# after",
				Kind:    ipfw.RecordComment,
				Comment: " after",
			})
			next(t, parser, eof)
		})
	}
}

// verifies that IP version keywords and protocol numbers commit to the legacy
// grammar without asking the proto checker.
func Test_Parser_Next_ProtoCheckerKeywords(t *testing.T) {
	var asked []string
	checker := ipfw.ProtoCheckerFunc(func(name string) bool {
		asked = append(asked, name)
		return false
	})
	cases := []struct {
		name  string
		input string
		state ipfw.ReduceState
	}{
		{
			name:  "IP version keyword",
			input: "add pass ip6 from any to any",
			state: anyToAnyState(ipfw.ProtoIPv6),
		},
		{
			name:  "protocol number",
			input: "add pass 6 from any to any",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Number: 6}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			asked = nil
			parser := ipfw.NewParser(test.input, ipfw.WithProtoChecker(checker))
			var state ipfw.ReduceState
			record, err := parser.Next(&state)
			require.Nil(t, err)
			require.Equal(t, passAnyToAny(1, test.input), *record)
			require.Equal(t, test.state, state)
			require.Empty(t, asked)
			next(t, parser, eof)
		})
	}
}

// protoLookupState is a raw state that also happens to look protocols up.
type protoLookupState struct {
	ipfw.ReduceState
}

// ResolveProto knows no protocol.
func (m *protoLookupState) ResolveProto(string) (uint8, bool) {
	return 0, false
}

// verifies that a state looking protocols up has no say in the grammar, which
// only the parser's proto checker chooses.
func Test_Parser_Next_ProtoCheckerNotFromState(t *testing.T) {
	const input = "add 160 allow in from any to any"
	parser := ipfw.NewParser(input)
	var state protoLookupState
	record, err := parser.Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line: 1,
		Text: input,
		Kind: ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{
			Num:    160,
			Action: ipfw.Action{Kind: ipfw.ActionPass},
		},
	}, *record)
	require.Equal(t, ipfw.ReduceState{
		Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "in"}}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
	}, state.ReduceState)
	next(t, parser, eof)
}

// verifies that ProtoCheckerFunc asks its function.
func Test_ProtoCheckerFunc_IsProto(t *testing.T) {
	assert.True(t, inAndTCP.IsProto("tcp"))
	assert.True(t, inAndTCP.IsProto("in"))
	assert.False(t, inAndTCP.IsProto("udp"))
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
					{Pattern: 1, Kind: ipfw.TargetNetwork6, Text: "::1"},
				},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
		{
			name:  "protocol and source groups with the deprecated separator",
			input: "add pass { tcp o udp } from { 192.0.2.0/24 o ::1 } to any\n",
			state: ipfw.ReduceState{
				Protos: []ipfw.ProtoMatch{
					{Proto: ipfw.Proto{Name: "tcp"}},
					{Proto: ipfw.Proto{Name: "udp"}},
				},
				Sources: []ipfw.Target{
					{Kind: ipfw.TargetNetwork4, Text: "192.0.2.0/24"},
					{Pattern: 1, Kind: ipfw.TargetNetwork6, Text: "::1"},
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
					{Neg: true, Pattern: 1, Kind: ipfw.TargetMe6},
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
		name  string
		input string
		state ipfw.ReduceState
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
			name:  "spaced destination port list",
			input: "add pass tcp from any to any 11, 22, 33\n",
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
			name:  "destination port before a comment",
			input: "add allow tcp from any to any 80 // web\n",
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
				Options:          []ipfw.Opt{{Kind: ipfw.OptComment, Text: " web"}},
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
					Action: ipfw.Action{Kind: ipfw.ActionPass},
				},
			}, *rec)
			require.Equal(t, tc.state, state)
		})
	}
}

// verifies that a comma joins following whitespace to the list, while a
// line-final comma is discarded.
//
// A following keyword therefore becomes a service name before the missing
// structural keyword fails the line.
func Test_Parser_Next_PortListTrailingComma(t *testing.T) {
	var state ipfw.ReduceState
	_, err := ipfw.NewParser("add pass tcp from any 22, to any\n").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrExpectedPrefix,
		Line:   1,
		Column: 29,
		Text:   "add pass tcp from any 22, to any",
	}, *err)
	require.Equal(t, ipfw.ReduceState{
		Protos:      []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
		Sources:     []ipfw.Target{{Kind: ipfw.TargetAny}},
		SourcePorts: []ipfw.PortMatch{portNumber(22), portService("to")},
	}, state)

	state = ipfw.ReduceState{}
	rec, err := ipfw.NewParser("add pass tcp from any to any 22,\n").Next(&state)
	require.Nil(t, err)
	require.Equal(t, ipfw.Record{
		Line: 1,
		Text: "add pass tcp from any to any 22,",
		Kind: ipfw.RecordInstruction,
		Instruction: ipfw.Instruction{
			Action: ipfw.Action{Kind: ipfw.ActionPass},
		},
	}, *rec)
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

// verifies that tag reaches the record after log, for check-state and the positive 32-bit range.
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
			name:  "minimum tag",
			input: "add allow tag 1 ip from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
				Tag:    1,
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "tag above native range",
			input: "add allow tag 65535 ip from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
				Tag:    65535,
			},
			state: anyToAnyState(ipfw.ProtoIPAny),
		},
		{
			name:  "maximum tag",
			input: "add allow tag 4294967295 ip from any to any\n",
			instruction: ipfw.Instruction{
				Action: ipfw.Action{Kind: ipfw.ActionPass},
				Tag:    4294967295,
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

// verifies that tag requires a positive 32-bit number after the optional log part.
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
			name:  "tag zero",
			input: "add allow tag 0 ip from any to any",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTag,
				Line:   1,
				Column: 14,
				Text:   "add allow tag 0 ip from any to any",
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
		name  string
		input string
		err   *ipfw.ParseError
		state ipfw.ReduceState
	}{
		{
			name:  "estab alias immediately after destination",
			input: "add allow tcp from any to any estab\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{established},
			},
		},
		{
			name:  "fragment alias immediately after destination",
			input: "add allow ip from any to any fragment\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptFrag}},
			},
		},
		{
			name:  "tcpflgs alias immediately after destination",
			input: "add allow tcp from any to any tcpflgs syn,!ack\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPAck)},
			},
		},
		{
			name:  "icmp6type alias immediately after destination",
			input: "add allow ip from any to any icmp6type 128,129\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{icmp6Types(128, 129)},
			},
		},
		{
			name:  "destination port then aliases",
			input: "add allow ip from any to any 80 estab fragment tcpflgs syn,!ack icmp6type 128,129\n",
			state: ipfw.ReduceState{
				IPProtos:         []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
				Options: []ipfw.Opt{
					established,
					{Kind: ipfw.OptFrag},
					tcpFlags(ipfw.TCPSyn, ipfw.TCPAck),
					icmp6Types(128, 129),
				},
			},
		},
		{
			name: "aliases preserve lists negation grouping and the following option",
			input: "add allow ip from any to any { not estab or fragment } " +
				"not tcpflgs syn, !ack { in or not icmp6type 128, 129 } out\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options: []ipfw.Opt{
					notOpt(established),
					{Or: true, Kind: ipfw.OptFrag},
					notOpt(tcpFlags(ipfw.TCPSyn, ipfw.TCPAck)),
					{Kind: ipfw.OptIn},
					orOpt(notOpt(icmp6Types(128, 129))),
					{Kind: ipfw.OptOut},
				},
			},
		},
		{
			name:  "alias before a comment at EOF",
			input: "add allow tcp from any to any estab // alias spelling",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options: []ipfw.Opt{
					established,
					{Kind: ipfw.OptComment, Text: " alias spelling"},
				},
			},
		},
		{
			name:  "tcpflgs alias without an argument",
			input: "add allow tcp from any to any tcpflgs\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 37,
				Text:   "add allow tcp from any to any tcpflgs",
			},
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
			},
		},
		{
			name:  "tcpflgs alias with an invalid later flag",
			input: "add allow tcp from any to any tcpflgs syn,!bogus\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrUnknownTCPFlag,
				Line:   1,
				Column: 43,
				Text:   "add allow tcp from any to any tcpflgs syn,!bogus",
			},
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
			},
		},
		{
			name:  "icmp6type alias without an argument",
			input: "add allow ip from any to any icmp6type\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 38,
				Text:   "add allow ip from any to any icmp6type",
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
			},
		},
		{
			name:  "icmp6type alias with a nonnumeric type",
			input: "add allow ip from any to any icmp6type bogus\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedU8,
				Line:   1,
				Column: 39,
				Text:   "add allow ip from any to any icmp6type bogus",
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
			},
		},
		{
			name:  "icmp6type alias with an invalid later item",
			input: "add allow ip from any to any icmp6type 128,202\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrUnknownICMP6Type,
				Line:   1,
				Column: 43,
				Text:   "add allow ip from any to any icmp6type 128,202",
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
			},
		},
		{
			name:  "fragment alias suffix remains trailing content",
			input: "add allow ip from any to any fragmentx\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 37,
				Text:   "add allow ip from any to any fragmentx",
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptFrag}},
			},
		},
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
			name:  "or-group joined by the pipe",
			input: "add allow tcp from any to any { established | not established }\n",
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
			name:  "in before a comment",
			input: "add allow tcp from any to any in // c\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}, {Kind: ipfw.OptComment, Text: " c"}},
			},
		},
		{
			name:  "negated comment",
			input: "add allow tcp from any to any in not // never\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options: []ipfw.Opt{
					{Kind: ipfw.OptIn},
					{Neg: true, Kind: ipfw.OptComment, Text: " never"},
				},
			},
		},
		{
			name:  "comment right after the destination",
			input: "add allow tcp from any to any // c { in or out }\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{{Kind: ipfw.OptComment, Text: " c { in or out }"}},
			},
		},
		{
			name:  "comment inside a group",
			input: "add allow tcp from any to any { in or // c }\n",
			err: &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedOr,
				Line:   1,
				Column: 44,
				Text:   "add allow tcp from any to any { in or // c }",
			},
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options: []ipfw.Opt{
					{Kind: ipfw.OptIn},
					{Or: true, Kind: ipfw.OptComment, Text: " c }"},
				},
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
					{Pattern: 1, Kind: ipfw.TargetNetwork6, Text: "ff05::/112"},
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
			name:  "negated port list is atomic",
			input: "add allow tcp from any to any not dst-port 22,80\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options: []ipfw.Opt{
					notOpt(dstPort(22)),
					portOr(notOpt(dstPort(80))),
				},
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
			name:  "spaced icmptypes numeric range followed by an option",
			input: "add allow icmp from any to any icmptypes 0, 7, 8, 31 in\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "icmp"}}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{icmpTypes(0, 7, 8, 31), {Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "icmp6types numeric range followed by an option",
			input: "add allow ip from any to any icmp6types 0,5,135,150,201 in\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{icmp6Types(0, 5, 135, 150, 201), {Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "tcpflags",
			input: "add allow tcp from any to any tcpflags rst\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{tcpFlags(ipfw.TCPRst, 0)},
			},
		},
		{
			name:  "spaced tcpflags with a cleared flag",
			input: "add allow tcp from any to any tcpflags syn, !ack\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{tcpFlags(ipfw.TCPSyn, ipfw.TCPAck)},
			},
		},
		{
			name:  "group of via names",
			input: "add allow ip from me to me { via lo0 or via lo1 }\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetMe}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetMe}},
				Options:      []ipfw.Opt{viaExact("lo0"), orOpt(viaExact("lo1"))},
			},
		},
		{
			name:  "via then in",
			input: "add allow ip from any to any via eth0 in\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{viaExact("eth0"), {Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "via mask with repeated stars",
			input: "add pass tcp from any to any 80 via tun**\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
				Options:          []ipfw.Opt{viaMask("tun**")},
			},
		},
		{
			name:  "via mask with an unclosed class",
			input: "add pass tcp from any to any 80 via lan[0\n",
			state: ipfw.ReduceState{
				Protos:           tcp,
				Sources:          anyToAny,
				Destinations:     anyToAny,
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
				Options:          []ipfw.Opt{viaMask("lan[0")},
			},
		},
		{
			name:  "via table then in",
			input: "add allow ip from any to any via table(t) in\n",
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{viaTable("t", ""), {Kind: ipfw.OptIn}},
			},
		},
		{
			name:  "option before a comment",
			input: "add allow tcp from any to any established // c\n",
			state: ipfw.ReduceState{
				Protos:       tcp,
				Sources:      anyToAny,
				Destinations: anyToAny,
				Options:      []ipfw.Opt{established, {Kind: ipfw.OptComment, Text: " c"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parser := ipfw.NewParser(tc.input)
			var state ipfw.ReduceState
			rec, err := parser.Next(&state)
			require.Equal(t, tc.err, err)
			if err == nil {
				require.Equal(t, ipfw.Record{
					Line: 1,
					Text: strings.TrimSuffix(tc.input, "\n"),
					Kind: ipfw.RecordInstruction,
					Instruction: ipfw.Instruction{
						Action: ipfw.Action{Kind: ipfw.ActionPass},
					},
				}, *rec)
			} else {
				require.Nil(t, rec)
			}
			require.Equal(t, tc.state, state)
			next(t, parser, eof)
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
			name:  "leading port option without its argument",
			input: "add allow tcp from any to any dst-port\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 38,
				Text:   "add allow tcp from any to any dst-port",
			},
		},
		{
			name:  "later port option without its argument",
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
			name:  "icmp type outside the range after a valid item",
			input: "add allow icmp from any to any established icmptypes 7,32",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownICMPType,
				Line:   1,
				Column: 55,
				Text:   "add allow icmp from any to any established icmptypes 7,32",
			},
		},
		{
			name:  "icmp6 type outside the range after a valid item",
			input: "add allow ip from any to any established icmp6types 150,202",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownICMP6Type,
				Line:   1,
				Column: 56,
				Text:   "add allow ip from any to any established icmp6types 150,202",
			},
		},
		{
			name:  "unknown tcp flag",
			input: "add allow tcp from any to any established tcpflags foo",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrUnknownTCPFlag,
				Line:   1,
				Column: 51,
				Text:   "add allow tcp from any to any established tcpflags foo",
			},
		},
		{
			name:  "via table with an empty name",
			input: "add allow ip from any to any established via table()",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableName,
				Line:   1,
				Column: 51,
				Text:   "add allow ip from any to any established via table()",
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

// verifies that dynamic state options are unique, stay outside OR groups,
// and use fresh context for every rule.
func Test_Parser_Next_KeepStateContext(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
		state    ipfw.ReduceState
	}{
		{
			name:  "duplicate after destination port",
			input: "add pass tcp from any to any 80 keep-state keep-state\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrDuplicateDynamicState,
				Line:   1,
				Column: 43,
				Text:   "add pass tcp from any to any 80 keep-state keep-state",
			},
			state: ipfw.ReduceState{
				Protos:           []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:          []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations:     []ipfw.Target{{Kind: ipfw.TargetAny}},
				DestinationPorts: []ipfw.PortMatch{portNumber(80)},
				Options:          []ipfw.Opt{{Kind: ipfw.OptKeepState}},
			},
		},
		{
			name:  "inside OR group",
			input: "add pass ip from any to any { in or keep-state }\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrDynamicStateInGroup,
				Line:   1,
				Column: 36,
				Text:   "add pass ip from any to any { in or keep-state }",
			},
			state: ipfw.ReduceState{
				IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
				Options:      []ipfw.Opt{{Kind: ipfw.OptIn}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			_, err := ipfw.NewParser(tc.input).Next(&state)
			require.NotNil(t, err)
			require.Equal(t, tc.expected, *err)
			require.Equal(t, tc.state, state)
		})
	}

	parser := ipfw.NewParser("add pass ip from any to any keep-state\n" +
		"add pass ip from any to any keep-state\n")
	for range 2 {
		var state ipfw.ReduceState
		_, err := parser.Next(&state)
		require.Nil(t, err)
		require.Equal(t, []ipfw.Opt{{Kind: ipfw.OptKeepState}}, state.Options)
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

	input := ruleset(`

		add allow foobar from any to any # callback
		:AFTER# next
	`)
	parser := ipfw.NewParser(input, ipfw.WithLabels())
	next(t, parser, ipfw.Record{Line: 1, Kind: ipfw.RecordEmpty})
	_, err = parser.Next(rejectingState{err: boom})
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrState,
		Err:    boom,
		Line:   2,
		Column: 10,
		Text:   "add allow foobar from any to any # callback",
	}, *err)
	require.ErrorIs(t, err, boom)
	require.ErrorIs(t, err, ipfw.ErrState)
	next(t, parser, ipfw.Record{
		Line:    3,
		Text:    ":AFTER# next",
		Kind:    ipfw.RecordLabel,
		Comment: " next",
		Label:   "AFTER",
	})
	next(t, parser, eof)
}

// verifies that an option list failing past its first option fails the
// line at that option.
//
// The options before it stay in the state and no port is read out of the
// keyword.
func Test_Parser_Next_OptionListFailsAtOption(t *testing.T) {
	var state ipfw.ReduceState
	_, err := ipfw.NewParser("add allow ip from any to any established foo\n").Next(&state)
	require.NotNil(t, err)
	require.Equal(t, ipfw.ParseError{
		Kind:   ipfw.ErrUnknownOption,
		Line:   1,
		Column: 41,
		Text:   "add allow ip from any to any established foo",
	}, *err)
	require.Equal(t, ipfw.ReduceState{
		IPProtos:     []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		Sources:      []ipfw.Target{{Kind: ipfw.TargetAny}},
		Destinations: []ipfw.Target{{Kind: ipfw.TargetAny}},
		Options:      []ipfw.Opt{{Kind: ipfw.OptEstablished}},
	}, state)
}

// verifies that a line with ports and options parses into a warmed-up
// state without allocating, the first option's dry run included.
func Test_Parser_Next_OptionsNoAllocs(t *testing.T) {
	src := "add pass tcp from any to any 22 established\n" +
		"add pass tcp from any to any established \t\r\n" +
		"add pass icmp from any to any icmptypes 0,7,31 in\n" +
		"add pass ip from any to any not icmp6types 0,5,150,201 in\n" +
		"add pass tcp from any to any estab\n" +
		"add pass ip from any to any fragment\n" +
		"add pass tcp from any to any tcpflgs syn,!ack\n" +
		"add pass ip from any to any not icmp6type 128,129 in\n" +
		"add 410 allow in\n" +
		"add 420 allow { not in or out } proto tcp via vlan17\n"
	parser := ipfw.NewParser(src)
	var state ipfw.ReduceState
	for _, err := range parser.Records(&state) {
		require.Nil(t, err)
	}
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		state.Reset()
		for _, err := range parser.Records(&state) {
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
			name:  "custom token in a braced group",
			input: "add allow tcp from { host.example.com } to { custom:first }\n",
			state: ipfw.ReduceState{
				Protos:       []ipfw.ProtoMatch{{Proto: ipfw.Proto{Name: "tcp"}}},
				Sources:      []ipfw.Target{{Kind: ipfw.TargetHostname, Text: "host.example.com"}},
				Destinations: []ipfw.Target{{Kind: ipfw.TargetCustom, Text: "custom:first"}},
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

// verifies that source and destination address lists keep their common
// negation and every member in parser state.
func Test_Parser_Next_AddressLists(t *testing.T) {
	var state ipfw.ReduceState
	src := "add allow ip from not 192.0.2.1,\f203.0.113.1 " +
		"to 2001:db8::1,2001:db8::2,\n"
	rec, err := ipfw.NewParser(src).Next(&state)
	require.Nil(t, err)
	require.Equal(t, passAnyToAny(1, strings.TrimSpace(src)), *rec)
	require.Equal(t, ipfw.ReduceState{
		IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
		Sources: []ipfw.Target{
			{Neg: true, Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
			{Neg: true, Kind: ipfw.TargetNetwork4, Text: "203.0.113.1"},
		},
		Destinations: []ipfw.Target{
			{Kind: ipfw.TargetNetwork6, Text: "2001:db8::1"},
			{Kind: ipfw.TargetNetwork6, Text: "2001:db8::2"},
		},
	}, state)
}

// verifies that malformed address lists fail at the missing or invalid member
// and keep every token emitted before it.
func Test_Parser_Next_AddressListErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		err   ipfw.ParseError
		state ipfw.ReduceState
	}{
		{
			name:  "empty destination member",
			input: "add allow ip from any to 192.0.2.1,,203.0.113.1",
			err: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 35,
				Text:   "add allow ip from any to 192.0.2.1,,203.0.113.1",
			},
			state: ipfw.ReduceState{
				IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:  []ipfw.Target{{Kind: ipfw.TargetAny}},
				Destinations: []ipfw.Target{
					{Kind: ipfw.TargetNetwork4, Text: "192.0.2.1"},
				},
			},
		},
		{
			name:  "reserved destination not before comma",
			input: "add pass ip from any to not,",
			err: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTarget,
				Line:   1,
				Column: 24,
				Text:   "add pass ip from any to not,",
			},
			state: ipfw.ReduceState{
				IPProtos: []ipfw.ProtoIPMatch{{Proto: ipfw.ProtoIPAny}},
				Sources:  []ipfw.Target{{Kind: ipfw.TargetAny}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			_, err := ipfw.NewParser(tc.input).Next(&state)
			require.NotNil(t, err)
			require.Equal(t, tc.err, *err)
			require.Equal(t, tc.state, state)
		})
	}
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

// verifies that a comment after the body is an option holding the raw text
// after the slashes, part of the line text, and that a lone slash is an
// unknown option.
func Test_Parser_Next_CommentOption(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		options []ipfw.Opt
	}{
		{
			name:    "json payload",
			input:   "add pass ip from any to any // {\"id\": \"RULE-42\", \"log\": true}\n",
			options: []ipfw.Opt{comment(" {\"id\": \"RULE-42\", \"log\": true}")},
		},
		{
			name:    "empty comment",
			input:   "add pass ip from any to any //",
			options: []ipfw.Opt{comment("")},
		},
		{
			name:    "trailing whitespace is trimmed",
			input:   "add pass ip from any to any // c \t\n",
			options: []ipfw.Opt{comment(" c")},
		},
		{
			name:    "carriage return before LF is trimmed",
			input:   "add pass ip from any to any // c\r\n",
			options: []ipfw.Opt{comment(" c")},
		},
		{
			name:    "tab before the slashes",
			input:   "add pass ip from any to any\t//x\n",
			options: []ipfw.Opt{comment("x")},
		},
		{
			name:    "slashes right after an option",
			input:   "add pass ip from any to any in// c\n",
			options: []ipfw.Opt{{Kind: ipfw.OptIn}, comment(" c")},
		},
		{
			name:    "options inside the comment",
			input:   "add pass ip from any to any // in not out\n",
			options: []ipfw.Opt{comment(" in not out")},
		},
		{
			name:    "negated comment",
			input:   "add pass ip from any to any not // never\n",
			options: []ipfw.Opt{{Neg: true, Kind: ipfw.OptComment, Text: " never"}},
		},
		{name: "no comment", input: "add pass ip from any to any\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var state ipfw.ReduceState
			rec, err := ipfw.NewParser(tc.input).Next(&state)
			require.Nil(t, err)
			require.Equal(t, passAnyToAny(1, strings.TrimSpace(tc.input)), *rec)
			require.Equal(t, withOptions(anyToAnyState(ipfw.ProtoIPAny), tc.options...), state)
		})
	}
	nextError(t, ipfw.NewParser("add pass ip from any to any / x"), ipfw.ParseError{
		Kind:   ipfw.ErrUnknownOption,
		Line:   1,
		Column: 28,
		Text:   "add pass ip from any to any / x",
	})
}

// verifies that parsing the simplest rule and one with address lists into a
// warmed-up state allocates nothing.
func Test_Parser_Body_NoAllocs(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "any to any",
			src:  "add pass ip from any to any\n",
		},
		{
			name: "address lists",
			src: "add pass ip from not 192.0.2.1,198.51.100.1 " +
				"to 2001:db8::1,2001:db8::2\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parser := ipfw.NewParser(tc.src)
			var state ipfw.ReduceState
			_, _ = parser.Next(&state)
			ok := true
			allocs := testing.AllocsPerRun(100, func() {
				parser.Reset(tc.src)
				state.Reset()
				if _, err := parser.Next(&state); err != nil {
					ok = false
				}
			})
			require.True(t, ok)
			require.Zero(t, allocs)
		})
	}
}

// verifies that a comment keeps its leading space and loses its trailing
// whitespace, like the text of the line.
//
// The record is then a function of its text.
func Test_Parser_Next_CommentTrailingWhitespace(t *testing.T) {
	next(t, ipfw.NewParser("# c \t\n"), ipfw.Record{
		Line:    1,
		Text:    "# c",
		Kind:    ipfw.RecordComment,
		Comment: " c",
	})
	next(t, ipfw.NewParser("# \n"), ipfw.Record{Line: 1, Text: "#", Kind: ipfw.RecordComment})
}

// verifies that a long label name is taken whole.
func Test_Parser_Next_LongLabel(t *testing.T) {
	next(t, ipfw.NewParser(":LONG_LABEL_NAME_42\n", ipfw.WithLabels()), ipfw.Record{
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
func benchmarkNext(b *testing.B, line string, options ...ipfw.ParserOption) {
	b.Helper()
	parser := ipfw.NewParser(line, options...)
	var state ipfw.ReduceState
	if _, err := parser.Next(&state); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for b.Loop() {
		parser.Reset(line)
		state.Reset()
		benchRecord, benchErr = parser.Next(&state)
	}
	if benchErr != nil {
		b.Fatal(benchErr)
	}
}

// verifies that no exported sub-parser reads past the end of a physical line.
//
// The Parser bounds each line itself, so this is the invariant that lets a
// hook hand a sub-parser the line it was given without trimming it first.
// Groups are drawn whole because only a well-formed one reaches the code
// that skips whitespace between elements.
func Test_SubParsers_LineBounded(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := drawGroup(t)
		if rapid.Bool().Draw(t, "soup") {
			var builder strings.Builder
			for range rapid.IntRange(0, 12).Draw(t, "pieces") {
				builder.WriteString(rapid.SampledFrom(lineBoundedPieces).Draw(t, "piece"))
			}
			input = builder.String()
		}
		for _, sub := range lineBoundedSubParsers {
			n, _ := sub.parse(input, ipfw.DiscardState{})
			require.NotContains(t, input[:n], "\n",
				"%s read past the end of the line in %q", sub.name, input)
		}
	})
}

// drawGroup builds a brace group whose whitespace runs may hold a newline.
func drawGroup(t *rapid.T) string {
	space := func(label string) string {
		return rapid.SampledFrom(lineBoundedSpaces).Draw(t, label)
	}
	element := func(label string) string {
		return rapid.SampledFrom(lineBoundedElements).Draw(t, label)
	}
	var builder strings.Builder
	builder.WriteString("{")
	builder.WriteString(space("open"))
	builder.WriteString(element("first"))
	for range rapid.IntRange(0, 3).Draw(t, "more") {
		builder.WriteString(space("before"))
		builder.WriteString(rapid.SampledFrom([]string{"or", "o", "|"}).Draw(t, "separator"))
		builder.WriteString(space("after"))
		builder.WriteString(element("next"))
	}
	builder.WriteString(space("close"))
	builder.WriteString("}")
	builder.WriteString(rapid.SampledFrom(lineBoundedSuffixes).Draw(t, "suffix"))
	return builder.String()
}

// lineBoundedSubParsers are the exported body parsers the line invariant covers.
var lineBoundedSubParsers = []struct {
	name  string
	parse func(string, ipfw.State) (int, error)
}{
	{name: "protocols", parse: ipfw.ParseProtocols},
	{name: "source targets", parse: ipfw.ParseSourceTargets},
	{name: "destination targets", parse: ipfw.ParseDestinationTargets},
	{name: "source ports", parse: ipfw.ParseSourcePorts},
	{name: "destination ports", parse: ipfw.ParseDestinationPorts},
	{
		name: "options",
		parse: func(s string, state ipfw.State) (int, error) {
			return ipfw.ParseOptions(s, state, nil)
		},
	},
}

var (
	// lineBoundedSpaces are the whitespace runs drawn between group parts.
	lineBoundedSpaces = []string{"", " ", "\t", "\n", " \n", "\r\n", " \t", "\n\t"}
	// lineBoundedElements are what a drawn group holds.
	lineBoundedElements = []string{
		"tcp", "udp", "any", "me", "22", "80,443", "192.0.2.0/24", "2001:db8::/32",
		"table(_T_)", "in", "out", "established", "not tcp", "src-port 22",
	}
	// lineBoundedSuffixes follow a drawn group.
	lineBoundedSuffixes = []string{"", " x", " to any", "\n", " in\nout"}
	// lineBoundedPieces are drawn into a free-form input, the newlines among
	// them being what the property is about.
	lineBoundedPieces = []string{
		"tcp", "udp", "ip", "any", "me", "22", "80,443", "1-65535",
		"192.0.2.0/24", "2001:db8::/32", "table(_T_)", "`host.example.com'",
		"{", "}", "or", " or ", " o ", " | ", ",", " ", "\t", "\n", "\r\n",
		"not ", "in", "out", "established", "frag", "via vlan1", "via table(_T_,v)",
		"src-port 22", "dst-port 8080,8443", "proto tcp", "tcpflags syn,!ack",
		"icmptypes 0,8", "keep-state :flow", "//", "#", "x",
	}
)

// fuzzSeeds are one line per syntax form plus the shapes that trip
// parsers.
//
// Odd bytes, long tokens, unbalanced groups, comments in odd places and
// several lines at once.
var fuzzSeeds = []string{
	"",
	"\n",
	"add pass ip from any to any\n",
	"add 100 deny log logamount 5 tag 7 tcp from any 22 to any 80 established\n",
	"add allow { tcp or udp } from { 192.0.2.0/24 or not ::1 } 1024-65535 to me domain\n",
	"add skipto :LBL ip from table(t) to host.example.com { in or out }\n",
	"add count ip from `node-1.example.net' to custom:first via vlan1?? keep-state :flow\n",
	"add check-state :flow log\n",
	"add deny ip from any to any not dst-port 22,80 tcpflags syn,!ack icmptypes 0,8\n",
	"add pass ip from any to any proto tcp via table(t,:L) antispoof frag diverted // c\n",
	"add allow udp from any src-port 1,2-3,ftp\\-data to any icmp6types 135\n",
	"add pass tcp from any to any estab\n",
	"add pass ip from any to any fragment\n",
	"add pass tcp from any to any tcpflgs syn,!ack\n",
	"add pass ip from any to any icmp6type 128,129\n",
	"add pass tcp from any to any tcpflgs\n",
	"add pass tcp from any to any tcpflgs syn,!bogus\n",
	"add pass ip from any to any icmp6type\n",
	"add pass ip from any to any icmp6type 128,202\n",
	"table _T_ create type iface\n",
	"table _T_ add 192.0.2.0/24 :L\n",
	"table _T_ add vlan7\n",
	":LABEL\n",
	"# comment\n",
	"  add pass ip from any to any  \n\n# c\n:L\n",
	"add pass ip from any to any\r\n",
	"add pass ip from any\x00 to any\n",
	"add pass ip from { any\n",
	"add pass ip from any to any {\n",
	"add pass ip from any to any established }\n",
	"// not a comment\n",
	"add pass ip from any to any # trailing\n",
	"add pass tcp from any 00443 to any 00443 " +
		"not src-port 80 { dst-port 8443 or proto ipv6 }# id\n",
	"add check-state // state # {\"id\": \"CHECK-7\"}\r\n",
	"add pass ip from any to any // {\"id\": \"before#after\"}",
	"table META create type addr# metadata\r\n",
	"table META add 192.0.2.0/24 # metadata\n",
	"table META add 2001:db8::/32 :NEXT# metadata",
	":NEXT# adjacent\n## repeated # hash\n",
	"add pass ip from any to # missing\r\n:RECOVERED# ok",
	":NEXT\r# lone carriage return\n",
	"add pass ip from any to any\n# next line only",
	"#",
	"add pass ip from any to any //",
	"add 100 // note # metadata\r\n",
	"add //",
	"add //joined\n",
	"add pass ip from " + strings.Repeat("a", 4096) + ".example.com to any\n",
	"add pass ip from any to any " + strings.Repeat("{ ", 64) + "in\n",
	"add pass\n",
	"add \n",
	"table\n",
	":\n",
	"foobar\n",
	"  :L  # x",
	"x",
	"\n\n",
}

func Fuzz_Parser_Next(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		for _, options := range [][]ipfw.ParserOption{
			nil,
			{ipfw.WithLabels()},
		} {
			parser := ipfw.NewParser(input, options...)
			replay := ipfw.NewParser("", options...)
			var state, again ipfw.ReduceState
			for lines := 0; ; lines++ {
				require.LessOrEqual(t, lines, strings.Count(input, "\n")+1, "the parser must terminate")
				state.Reset()
				rec, err := parser.Next(&state)
				if err != nil {
					require.GreaterOrEqual(t, err.Line, 1)
					require.GreaterOrEqual(t, err.Column, 0)
					require.LessOrEqual(t, err.Column, len(err.Text))
					require.Contains(t, input, err.Text)
					require.NotEmpty(t, err.Error())
					continue
				}
				if rec.Kind == ipfw.RecordEOF {
					break
				}
				require.Contains(t, input, rec.Text)
				if rec.Kind == ipfw.RecordEmpty {
					continue
				}
				expected := *rec
				expected.Line = 1
				again.Reset()
				replay.Reset(rec.Text)
				replayed, replayErr := replay.Next(&again)
				require.Nil(t, replayErr, "the text of a record must parse again")
				require.Equal(t, expected, *replayed)
				require.Equal(t, emptyToNil(state), emptyToNil(again))
			}
		}
	})
}

// emptyToNil makes the empty slices of a state nil.
//
// Two states then compare by content whatever their history of resets.
func emptyToNil(state ipfw.ReduceState) ipfw.ReduceState {
	if len(state.IPProtos) == 0 {
		state.IPProtos = nil
	}
	if len(state.Protos) == 0 {
		state.Protos = nil
	}
	if len(state.Sources) == 0 {
		state.Sources = nil
	}
	if len(state.Destinations) == 0 {
		state.Destinations = nil
	}
	if len(state.SourcePorts) == 0 {
		state.SourcePorts = nil
	}
	if len(state.DestinationPorts) == 0 {
		state.DestinationPorts = nil
	}
	if len(state.Options) == 0 {
		state.Options = nil
	}
	return state
}

func ExampleParser_Next() {
	parser := ipfw.NewParser("add 100 deny log tcp from 192.0.2.0/24 to any 22 // bots\nadd pass ip from any to any\n")
	var state ipfw.ReduceState
	for {
		rec, err := parser.Next(&state)
		if err != nil {
			fmt.Println(ipfw.NewDiag(err))
			return
		}
		if rec.Kind == ipfw.RecordEOF {
			break
		}
		note := ""
		for _, opt := range state.Options {
			if opt.Kind == ipfw.OptComment {
				note = opt.Text
			}
		}
		fmt.Printf("%d: %s, log %v, from %q, %d destination ports, comment %q\n",
			rec.Instruction.Num, rec.Instruction.Action, rec.Instruction.Log.Enabled,
			state.Sources[0].Text, len(state.DestinationPorts), note)
		state.Reset()
	}
	// Output:
	//
	// 100: deny, log true, from "192.0.2.0/24", 1 destination ports, comment " bots"
	// 0: pass, log false, from "", 0 destination ports, comment ""
}

// syntheticRuleset is a ruleset of about ten thousand lines mixing every
// syntax form, the same on every call.
//
// Its length is the point: a long input through one reused parser and
// state is where an allocation the short cases do not reach would show.
var syntheticRuleset = sync.OnceValue(func() string {
	random := rand.New(rand.NewPCG(1, 2))
	pick := func(choices ...string) string {
		return choices[random.IntN(len(choices))]
	}
	var b strings.Builder
	for idx := range 10000 {
		switch random.IntN(20) {
		case 0:
			fmt.Fprintf(&b, "table _T%d_ create type %s\n", idx%8, pick("iface", "addr"))
		case 1:
			fmt.Fprintf(&b, "table _T%d_ add %s\n", idx%8, pick(
				"192.0.2.0/24", "2001:db8::/48 :L", "vlan7 :JUMP", "198.51.100.1",
			))
		case 2:
			fmt.Fprintf(&b, ":LABEL_%d\n", idx)
		case 3:
			fmt.Fprintf(&b, "# rule %d of the synthetic set\n", idx)
		case 4:
			b.WriteString("\n")
		case 5:
			fmt.Fprintf(&b, "add %d check-state%s\n", idx, pick("", " :flow", " log"))
		default:
			b.WriteString("add ")
			if random.IntN(2) == 0 {
				fmt.Fprintf(&b, "%d ", idx)
			}
			b.WriteString(pick("pass", "deny", "count", "skipto :LABEL_1", "skipto 100"))
			b.WriteString(pick("", " log", " log logamount 50", " tag 3"))
			b.WriteString(pick(" ip", " tcp", " udp", " icmp", " { tcp or udp }", " not tcp"))
			b.WriteString(" from ")
			b.WriteString(pick(
				"any", "me", "192.0.2.0/24", "2001:db8::/32", "host.example.com",
				"table(_T1_)", "{ 192.0.2.1 or ::1 or me6 }", "not 198.51.100.0/24", "custom:first",
			))
			b.WriteString(pick("", "", " 22", " 1024-65535", " 22,80,443", " not 22"))
			b.WriteString(" to ")
			b.WriteString(pick(
				"any", "me6", "203.0.113.0/24", "2001:db8:1::/48", "`node-1.example.net'",
				"table(_T2_)", "{ any or table(_T3_) }", "not 192.0.2.128/25",
			))
			b.WriteString(pick("", "", " 80", " 1-65535", " 53,443"))
			b.WriteString(pick(
				"", "", " in", " out", " established", " keep-state :flow", " proto tcp",
				" tcpflags syn,!ack", " dst-port 8080,8443", " src-port 1024-65535",
				" via vlan1??", " via table(_T4_)", " icmptypes 0,8", " { in or out }",
				" not diverted", " antispoof", " frag", " in via eth0 established",
			))
			b.WriteString(pick("", "", " // {\"id\": 1}"))
			b.WriteString("\n")
		}
	}
	return b.String()
})

// verifies that the whole synthetic ruleset parses into a warmed-up state
// without a single allocation.
func Test_Parser_SyntheticRuleset_NoAllocs(t *testing.T) {
	src := syntheticRuleset()
	parser := ipfw.NewParser(src, ipfw.WithLabels())
	var state ipfw.ReduceState
	for _, err := range parser.Records(&state) {
		require.Nil(t, err)
	}
	ok := true
	allocs := testing.AllocsPerRun(1, func() {
		parser.Reset(src)
		for {
			state.Reset()
			rec, err := parser.Next(&state)
			if err != nil {
				ok = false
				return
			}
			if rec.Kind == ipfw.RecordEOF {
				return
			}
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}

func Benchmark_Parser_Next_Discard(b *testing.B) {
	src := syntheticRuleset()
	parser := ipfw.NewParser(src, ipfw.WithLabels())
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for b.Loop() {
		parser.Reset(src)
		for {
			rec, err := parser.Next(ipfw.DiscardState{})
			if err != nil {
				b.Fatal(err)
			}
			if rec.Kind == ipfw.RecordEOF {
				break
			}
		}
	}
}

func Benchmark_Parser_Next_Reduce(b *testing.B) {
	src := syntheticRuleset()
	parser := ipfw.NewParser(src, ipfw.WithLabels())
	var state ipfw.ReduceState
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for b.Loop() {
		parser.Reset(src)
		for {
			state.Reset()
			rec, err := parser.Next(&state)
			if err != nil {
				b.Fatal(err)
			}
			if rec.Kind == ipfw.RecordEOF {
				break
			}
		}
	}
}

func Benchmark_Parser_Next_AnyToAny(b *testing.B) {
	benchmarkNext(b, "add pass ip from any to any\n")
}

// Benchmark_Parser_Next_Grammar compares grammar selection with and without a proto checker.
func Benchmark_Parser_Next_Grammar(b *testing.B) {
	for _, test := range []struct {
		name  string
		input string
		hook  ipfw.OptionHook
	}{
		{name: "LegacyIP", input: "add pass ip from any to any\n"},
		{name: "LegacyTCP", input: "add pass tcp from any to any\n"},
		{name: "LegacyGroup", input: "add pass { tcp or udp } from any to any\n"},
		{name: "OptionIn", input: "add pass in\n"},
		{name: "OptionProto", input: "add pass proto tcp\n"},
		{name: "OptionGroup", input: "add pass { not in or out }\n"},
		{
			name: "HookLegacy", hook: zzOption,
			input: "add pass ip from { 192.0.2.0/24 or 192.0.2.16/28 or 198.51.100.0/24 or" +
				" 203.0.113.0/24 or 2001:db8::/32 } to { 192.0.2.1 or 198.51.100.1 or" +
				" 203.0.113.1 or 2001:db8::1 or ::1 }\n",
		},
		{name: "HookOption", input: "add pass zz 17\n", hook: zzOption},
		{name: "Ruleset", input: syntheticRuleset()},
	} {
		b.Run(test.name, func(b *testing.B) {
			for _, mode := range []string{"Raw", "RawChecker", "Resolver", "ResolverChecker"} {
				b.Run(mode, func(b *testing.B) {
					options := []ipfw.ParserOption{ipfw.WithLabels(), ipfw.WithOptionHook(test.hook)}
					if strings.HasSuffix(mode, "Checker") {
						options = append(options, ipfw.WithProtoChecker(protoChecker(fakeProtos{})))
					}
					parser := ipfw.NewParser(test.input, options...)
					var raw ipfw.ReduceState
					var sink ipfw.ReduceVMState[net4, net6]
					var state ipfw.State = &raw
					reset := raw.Reset
					if strings.HasPrefix(mode, "Resolver") {
						state = ipfw.NewResolver(&sink, ipfw.Environment[net4, net6]{
							Networks: nets, Protos: fakeProtos{}, Services: fakeServices{},
							Targets: newGrammarBenchmarkTargets(),
						})
						reset = sink.Reset
					}
					for {
						reset()
						record, err := parser.Next(state)
						if err != nil {
							b.Fatal(err)
						}
						if record.Kind == ipfw.RecordEOF {
							break
						}
					}
					b.SetBytes(int64(len(test.input)))
					b.ReportAllocs()
					for b.Loop() {
						parser.Reset(test.input)
						for {
							reset()
							benchRecord, benchErr = parser.Next(state)
							if benchErr != nil {
								b.Fatal(benchErr)
							}
							if benchRecord.Kind == ipfw.RecordEOF {
								break
							}
						}
					}
				})
			}
		})
	}
}

// grammarOpaqueState forwards the State callbacks and nothing else.
type grammarOpaqueState struct {
	ipfw.State
}

// grammarBenchmarkTargets keeps target lookup independent of repeated network parsing.
type grammarBenchmarkTargets struct {
	Hosts4  []net4
	Hosts6  []net6
	Custom4 []net4
}

func newGrammarBenchmarkTargets() grammarBenchmarkTargets {
	return grammarBenchmarkTargets{
		Hosts4: []net4{must4("192.0.2.1/32")}, Hosts6: []net6{must6("2001:db8::1/128")},
		Custom4: []net4{must4("192.0.2.0/24"), must4("198.51.100.0/24")},
	}
}

// ResolveTarget resolves only names in the synthetic benchmark fixture.
func (m grammarBenchmarkTargets) ResolveTarget(target ipfw.Target) ([]net4, []net6, error) {
	switch target.Text {
	case "host.example.com", "node-1.example.net":
		return m.Hosts4, m.Hosts6, nil
	case "custom:first":
		return m.Custom4, nil, nil
	default:
		return nil, nil, ipfw.ErrUnresolvedTarget
	}
}

func Benchmark_Parser_Next_TenNetworks(b *testing.B) {
	benchmarkNext(b, "add pass ip from { 192.0.2.0/24 or 192.0.2.16/28 or 198.51.100.0/24 or"+
		" 203.0.113.0/24 or 2001:db8::/32 } to { 192.0.2.1 or 198.51.100.1 or 203.0.113.1 or"+
		" 2001:db8::1 or ::1 }\n")
}

func Benchmark_Parser_Next_TenOptions(b *testing.B) {
	benchmarkNext(b, "add allow tcp from any 1024-65535 to any 22,80,443 in via vlan1?? established"+
		" keep-state :flow proto tcp tcpflags syn,!ack dst-port 8080,8443 not frag antispoof"+
		" { src-port 22 or out }\n")
}

func Benchmark_Parser_Next_OptionsAfterTarget(b *testing.B) {
	benchmarkNext(b, "add allow tcp from any to any in via vlan1?? established keep-state :flow"+
		" proto tcp tcpflags syn,!ack dst-port 8080,8443 not frag antispoof { src-port 22 or out }\n")
}

func Benchmark_Parser_Next_Comment(b *testing.B) {
	benchmarkNext(b, "# a comment line of an ordinary length\n")
}

func Benchmark_Parser_Next_CommentOnlyRule(b *testing.B) {
	benchmarkNext(b, "add 100 // a comment-only rule\n")
}

func Benchmark_Parser_Next_CommentLong(b *testing.B) {
	benchmarkNext(b, "# "+strings.Repeat("example comment ", 256)+"\n")
}

func Benchmark_Parser_Next_CommentOptionLong(b *testing.B) {
	benchmarkNext(b, "add pass ip from any to any // "+strings.Repeat("example comment ", 256)+"\n")
}

func Benchmark_Parser_Next_Label(b *testing.B) {
	benchmarkNext(b, ":LONG_LABEL_NAME_42\n", ipfw.WithLabels())
}
