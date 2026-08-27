package ipfw_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw-go"
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
			name:  "no type",
			input: "table t create\n",
			table: ipfw.Table{Name: "t", Kind: ipfw.TableCreate},
		},
		{
			name:  "no type with trailing whitespace",
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

// verifies that `table NAME add KEY [VALUE]` parses into a table record,
// the key classified by shape without validation and the value kept raw.
func Test_Parser_Next_TableAdd(t *testing.T) {
	cases := []struct {
		name  string
		input string
		table ipfw.Table
	}{
		{
			name:  "IPv4 network",
			input: "table _ACCESS_NETS_ add 192.0.2.0/28\n",
			table: ipfw.Table{
				Name: "_ACCESS_NETS_",
				Kind: ipfw.TableAdd,
				Key:  ipfw.TableKey{Kind: ipfw.TableKeyNetwork4, Text: "192.0.2.0/28"},
			},
		},
		{
			name:  "IPv6 network with a value",
			input: "table t add 2001:db8::/32 x\n",
			table: ipfw.Table{
				Name:  "t",
				Kind:  ipfw.TableAdd,
				Key:   ipfw.TableKey{Kind: ipfw.TableKeyNetwork6, Text: "2001:db8::/32"},
				Value: "x",
			},
		},
		{
			name:  "interface name with a label value",
			input: "table _JUMP_EARLY_OUT_ add vlan42 :JUMPED\n",
			table: ipfw.Table{
				Name:  "_JUMP_EARLY_OUT_",
				Kind:  ipfw.TableAdd,
				Key:   ipfw.TableKey{Kind: ipfw.TableKeyIfName, Text: "vlan42"},
				Value: ":JUMPED",
			},
		},
		{
			name:  "interface name without a value",
			input: "table t add eth0\n",
			table: ipfw.Table{
				Name: "t",
				Kind: ipfw.TableAdd,
				Key:  ipfw.TableKey{Kind: ipfw.TableKeyIfName, Text: "eth0"},
			},
		},
		{
			name:  "trailing whitespace is not a value",
			input: "table t add eth0 \n",
			table: ipfw.Table{
				Name: "t",
				Kind: ipfw.TableAdd,
				Key:  ipfw.TableKey{Kind: ipfw.TableKeyIfName, Text: "eth0"},
			},
		},
		{
			name:  "network text is not validated",
			input: "table t add 300.1.1.1\n",
			table: ipfw.Table{
				Name: "t",
				Kind: ipfw.TableAdd,
				Key:  ipfw.TableKey{Kind: ipfw.TableKeyNetwork4, Text: "300.1.1.1"},
			},
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

// verifies that a missing or malformed key of a table add is a positioned
// error and that a key cut by a slash leaves trailing content.
func Test_Parser_Next_TableAddErrors(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected ipfw.ParseError
	}{
		{
			name:  "nothing after add",
			input: "table t add\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedWhitespace,
				Line:   1,
				Column: 11,
				Text:   "table t add",
			},
		},
		{
			name:  "key starting with a brace",
			input: "table t add {x\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedTableKey,
				Line:   1,
				Column: 12,
				Text:   "table t add {x",
			},
		},
		{
			name:  "interface name cut by a slash",
			input: "table t add eth0/1\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 16,
				Text:   "table t add eth0/1",
			},
		},
		{
			name:  "second value is trailing content",
			input: "table t add x y z\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 16,
				Text:   "table t add x y z",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextError(t, ipfw.NewParser(tc.input), tc.expected)
		})
	}
}

// verifies that each missing or wrong piece of a table command is a
// positioned error.
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
			name:  "token glued to create is trailing content",
			input: "table t createx\n",
			expected: ipfw.ParseError{
				Kind:   ipfw.ErrExpectedNewlineOrEOF,
				Line:   1,
				Column: 14,
				Text:   "table t createx",
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
