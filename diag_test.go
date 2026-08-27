package ipfw_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
)

// lines joins the lines of an expected rendering, the trailing newline
// included, so trailing spaces stay visible in the source.
func lines(s ...string) string {
	return strings.Join(s, "\n") + "\n"
}

// unknownAction is the error the step's example is rendered from.
var unknownAction = &ipfw.ParseError{
	Kind:   ipfw.ErrExpectedAction,
	Line:   3,
	Column: 4,
	Text:   "add foobar :any # WOW",
}

// verifies the rustc layout with a path: header, position with a 1-based
// column, gutter, source line and carets under the whole token.
func Test_Diagnostic_WithDiagPath(t *testing.T) {
	require.Equal(t, lines(
		"error: expected action",
		"  --> fw.conf:3:5",
		"   |",
		" 3 | add foobar :any # WOW",
		"   |     ^^^^^^",
	), ipfw.NewDiagnostic(unknownAction, ipfw.WithDiagPath("fw.conf")).String())
}

// verifies that a style wraps each role of the rendering and nothing
// else, the layout staying what it is without one.
func Test_Diagnostic_WithDiagStyle(t *testing.T) {
	style := ipfw.Style{
		Error:   "<e>",
		Message: "<m>",
		Info:    "<i>",
		Span:    "<s>",
		Dimmed:  "<d>",
		Reset:   "<r>",
	}
	require.Equal(t, lines(
		"<e>error<r><m>: expected action<r>",
		"<i>  --> fw.conf:3:5<r>",
		"<i>   |<r>",
		"<i> 3 | <r>add foobar :any # WOW",
		"<i>   | <r>    <s>^^^^^^<r>",
	), ipfw.NewDiagnostic(
		unknownAction,
		ipfw.WithDiagPath("fw.conf"),
		ipfw.WithDiagStyle(style),
	).String())
}

// verifies that a style dims the markers of a cut line on either side and
// that its escapes leave the layout, the width included, as it was.
func Test_Diagnostic_WithDiagStyle_Cut(t *testing.T) {
	err := &ipfw.ParseError{
		Kind:   ipfw.ErrExpectedAction,
		Line:   3,
		Column: 41,
		Text:   "add pass ip from 192.0.2.0/24 to any not frobnicate 1024-65535 established",
	}
	styled := ipfw.NewDiagnostic(err, ipfw.WithDiagWidth(48), ipfw.WithDiagStyle(ipfw.DiagStyle())).String()
	require.Contains(t, styled, "\x1b[2m... \x1b[0m")
	require.Contains(t, styled, "\x1b[2m ...\x1b[0m")
	require.Equal(t, ipfw.NewDiagnostic(err, ipfw.WithDiagWidth(48)).String(), plain(styled))
}

// verifies that a style is chosen for the writer it will be rendered to.
//
// The palette for a terminal, nothing for a file, a pipe, a writer that is
// no file at all, or an environment asking for no colour.
func Test_DiagStyleFor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")

	file, err := os.CreateTemp(t.TempDir(), "diag")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.Equal(t, ipfw.Style{}, ipfw.DiagStyleFor(file))

	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	t.Cleanup(func() { require.NoError(t, writer.Close()) })
	require.Equal(t, ipfw.Style{}, ipfw.DiagStyleFor(writer))

	require.Equal(t, ipfw.Style{}, ipfw.DiagStyleFor(&strings.Builder{}))
	require.Equal(t, ipfw.Style{}, ipfw.DiagStyleFor(nil))

	terminal, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, terminal.Close()) })
	require.Equal(t, ipfw.DiagStyle(), ipfw.DiagStyleFor(terminal))

	t.Setenv("NO_COLOR", "1")
	require.Equal(t, ipfw.Style{}, ipfw.DiagStyleFor(terminal))

	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	require.Equal(t, ipfw.Style{}, ipfw.DiagStyleFor(terminal))
}

// verifies that the palette of DiagStyle wraps every role in ANSI
// escapes and that an empty style leaves the rendering untouched.
func Test_Diagnostic_DiagStyle(t *testing.T) {
	colored := ipfw.NewDiagnostic(unknownAction, ipfw.WithDiagStyle(ipfw.DiagStyle())).String()
	require.Contains(t, colored, "\x1b[1;91merror\x1b[0m")
	require.Contains(t, colored, "\x1b[1;94m  --> 3:5\x1b[0m")
	require.Contains(t, colored, "\x1b[1;93m^^^^^^\x1b[0m")
	require.Equal(t, plain(ipfw.NewDiagnostic(unknownAction).String()), plain(colored))

	require.Equal(
		t,
		ipfw.NewDiagnostic(unknownAction).String(),
		ipfw.NewDiagnostic(unknownAction, ipfw.WithDiagStyle(ipfw.Style{})).String(),
	)
}

// plain strips the ANSI escapes from a rendering.
func plain(s string) string {
	for {
		start := strings.Index(s, "\x1b[")
		if start < 0 {
			return s
		}
		end := strings.IndexByte(s[start:], 'm')
		s = s[:start] + s[start+end+1:]
	}
}

// verifies that without a path the position line holds line and column
// only.
func Test_Diagnostic_WithoutDiagPath(t *testing.T) {
	require.Equal(t, lines(
		"error: expected action",
		"  --> 3:5",
		"   |",
		" 3 | add foobar :any # WOW",
		"   |     ^^^^^^",
	), ipfw.NewDiagnostic(unknownAction).String())
}

// verifies that an error straight from the parser renders with the carets
// under the token the parser stopped at.
func Test_Diagnostic_FromParser(t *testing.T) {
	_, err := ipfw.NewParser("add foobar :any # WOW\n").Next(ipfw.DiscardState{})
	require.NotNil(t, err)
	require.Equal(t, lines(
		"error: expected action",
		"  --> 1:5",
		"   |",
		" 1 | add foobar :any # WOW",
		"   |     ^^^^^^",
	), ipfw.NewDiagnostic(err).String())
}

// verifies that an error at the end of the line puts one caret under the
// last byte.
func Test_Diagnostic_EndOfLine(t *testing.T) {
	err := &ipfw.ParseError{
		Kind:   ipfw.ErrExpectedWhitespace,
		Line:   1,
		Column: 12,
		Text:   "add deny log",
	}
	require.Equal(t, lines(
		"error: expected whitespace",
		"  --> 1:13",
		"   |",
		" 1 | add deny log",
		"   |            ^",
	), ipfw.NewDiagnostic(err).String())
}

// verifies that an empty line gets a single caret at the first column.
func Test_Diagnostic_EmptyText(t *testing.T) {
	err := &ipfw.ParseError{Kind: ipfw.ErrExpectedTarget, Line: 2, Column: 0, Text: ""}
	require.Equal(t, lines(
		"error: expected target",
		"  --> 2:1",
		"   |",
		" 2 | ",
		"   | ^",
	), ipfw.NewDiagnostic(err).String())
}

// verifies that the error a state returned follows the kind in the header.
func Test_Diagnostic_StateError(t *testing.T) {
	err := &ipfw.ParseError{
		Kind:   ipfw.ErrState,
		Err:    errors.New("boom"),
		Line:   1,
		Column: 9,
		Text:   "add pass ip from any to any",
	}
	require.Equal(t, lines(
		"error: state error: boom",
		"  --> 1:10",
		"   |",
		" 1 | add pass ip from any to any",
		"   |          ^^",
	), ipfw.NewDiagnostic(err).String())
}

// verifies that the gutter grows with the line number and the arrow moves
// with it.
func Test_Diagnostic_WideGutter(t *testing.T) {
	err := &ipfw.ParseError{
		Kind:   ipfw.ErrExpectedAction,
		Line:   12345,
		Column: 4,
		Text:   "add foobar :any",
	}
	require.Equal(t, lines(
		"error: expected action",
		"      --> 12345:5",
		"       |",
		" 12345 | add foobar :any",
		"       |     ^^^^^^",
	), ipfw.NewDiagnostic(err).String())
}

// verifies the four width cases of the reference, the cut sides marked
// and the carets staying under their token.
//
// A fitting line is left alone, a long one is cut on the right, the left
// or both sides around the caret. Width 40 leaves 35 columns next to a
// one-digit gutter.
func Test_Diagnostic_WithDiagWidth(t *testing.T) {
	cases := []struct {
		name     string
		column   int
		text     string
		expected string
	}{
		{
			name:   "fits",
			column: 4,
			text:   "add psss tcp from any to any",
			expected: lines(
				"error: unexpected token",
				"  --> 1:5",
				"   |",
				" 1 | add psss tcp from any to any",
				"   |     ^^^^",
			),
		},
		{
			name:   "cut on the right",
			column: 4,
			text:   "add psss tcp from { _LARGER_TABLE_NAME_ } to any",
			expected: lines(
				"error: unexpected token",
				"  --> 1:5",
				"   |",
				" 1 | add psss tcp from { _LARGER_TAB ...",
				"   |     ^^^^",
			),
		},
		{
			name:   "cut on the left",
			column: 42,
			text:   "add pass tcp from { _LARGER_TABLE_NAME_ } t2o any",
			expected: lines(
				"error: unexpected token",
				"  --> 1:43",
				"   |",
				" 1 | ... { _LARGER_TABLE_NAME_ } t2o any",
				"   |                             ^^^",
			),
		},
		{
			name:   "cut on both sides",
			column: 42,
			text:   "add pass tcp from { _LARGER_TABLE_NAME_ } t2o { _LARGER_TABLE_NAME_ } to any",
			expected: lines(
				"error: unexpected token",
				"  --> 1:43",
				"   |",
				" 1 | ... ABLE_NAME_ } t2o { _LARGER_ ...",
				"   |                  ^^^",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &ipfw.ParseError{
				Kind:   ipfw.ErrExpectedPrefix,
				Line:   1,
				Column: tc.column,
				Text:   tc.text,
			}
			require.Equal(t, tc.expected, ipfw.NewDiagnostic(err, ipfw.WithDiagWidth(40)).String())
		})
	}
}

// verifies that WriteTo writes exactly the rendering and reports its
// length.
func Test_Diagnostic_WriteTo(t *testing.T) {
	diagnostic := ipfw.NewDiagnostic(unknownAction, ipfw.WithDiagPath("fw.conf"))
	var buf strings.Builder
	n, err := diagnostic.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, diagnostic.String(), buf.String())
	require.Equal(t, int64(len(diagnostic.String())), n)
}
