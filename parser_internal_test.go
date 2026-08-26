package ipfw

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// verifies that an inline comment is the raw text after the slashes up to
// the newline, and that anything else leaves the input untouched.
func Test_ParseInlineComment_Table(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		comment string
		rest    string
	}{
		{name: "comment with leading space", input: " // x", comment: " x", rest: ""},
		{name: "comment up to the newline", input: "// {\"id\": 1}\n:L", comment: " {\"id\": 1}", rest: "\n:L"},
		{name: "empty comment", input: "//", comment: "", rest: ""},
		{name: "no comment", input: "x", comment: "", rest: "x"},
		{name: "whitespace without comment is kept", input: "  x", comment: "", rest: "  x"},
		{name: "single slash is not a comment", input: " / x", comment: "", rest: " / x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			comment, rest := parseInlineComment(tc.input)
			require.Equal(t, tc.comment, comment)
			require.Equal(t, tc.rest, rest)
		})
	}
}
