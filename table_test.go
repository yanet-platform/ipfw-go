package ipfw_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// verifies that `table NAME create [type T]…` parses into a table record,
// the last type winning and a missing one staying unset.
func Test_Parser_Next_TableCreate(t *testing.T) {
	cases := []struct {
		name  string
		input string
		table ipfw.Table
	}{
		{
			name:  "iface",
			input: "table _JUMP_IN_ create type iface\n",
			table: ipfw.Table{Name: "_JUMP_IN_", Kind: ipfw.TableCreate, Type: ipfw.TableTypeIface},
		},
		{
			name:  "addr",
			input: "table t create type addr\n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableTypeAddr},
		},
		{
			name:  "number",
			input: "table t create type number\n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableTypeNumber},
		},
		{
			name:  "flow",
			input: "table t create type flow\n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableTypeFlow},
		},
		{
			name:  "mac",
			input: "table t create type mac\n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableTypeMAC},
		},
		{
			name:  "last type wins",
			input: "table t create type addr type mac\n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableTypeMAC},
		},
		{
			name:  "no type needs the trailing whitespace",
			input: "table t create \n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate},
		},
		{
			name:  "type then trailing whitespace",
			input: "table t create type addr \n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate, Type: ipfw.TableTypeAddr},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next(t, ipfw.NewParser(tc.input), ipfw.Record{
				Line:  1,
				Text:  strings.TrimSpace(tc.input),
				Kind:  ipfw.RecordTable,
				Table: tc.table,
			})
		})
	}
}

// verifies that each missing or wrong piece of a table command is a
// positioned error.
//
// The whitespace after `create` is required even without options.
func Test_Parser_Next_TableErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "nothing after the name",
			input: "table x\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 7,
				Text:   "table x",
			},
		},
		{
			name:  "unknown command",
			input: "table t drop\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableCommand,
				Line:   1,
				Column: 8,
				Text:   "table t drop",
			},
		},
		{
			name:  "nothing after create",
			input: "table t create\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 14,
				Text:   "table t create",
			},
		},
		{
			name:  "unknown create option is trailing content",
			input: "table t create x\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 15,
				Text:   "table t create x",
			},
		},
		{
			name:  "nothing after type",
			input: "table t create type\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 19,
				Text:   "table t create type",
			},
		},
		{
			name:  "unknown type",
			input: "table t create type foo\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableType,
				Line:   1,
				Column: 20,
				Text:   "table t create type foo",
			},
		},
		{
			name:  "token after the type is trailing content",
			input: "table t create type addr x\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 25,
				Text:   "table t create type addr x",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that parsing a table command allocates nothing.
func Test_Parser_Table_NoAllocs(t *testing.T) {
	src := "table _JUMP_IN_ create type iface\n"
	parser := ipfw.NewParser(src)
	ok := true
	allocs := testing.AllocsPerRun(100, func() {
		parser.Reset(src)
		if _, err := parser.Next(ipfw.DiscardState{}); err != nil {
			ok = false
		}
	})
	require.True(t, ok)
	require.Zero(t, allocs)
}
