package ipfw

import (
	"io"
	"strconv"
	"strings"
)

// diagnosticOptions is what a DiagnosticOption configures.
type diagnosticOptions struct {
	// Path is printed before the position, none when empty.
	Path string
	// Width is the room the rendering may take, unlimited when zero.
	Width int
}

func newDiagnosticOptions() diagnosticOptions {
	return diagnosticOptions{}
}

// DiagnosticOption configures a Diagnostic, see the With functions.
type DiagnosticOption func(*diagnosticOptions)

// WithPath names the file in the position line, as `path:line:column`.
func WithPath(path string) DiagnosticOption {
	return func(opts *diagnosticOptions) {
		opts.Path = path
	}
}

// WithWidth limits the width of the rendering, zero meaning unlimited.
//
// A source line that does not fit next to the gutter is cut around the
// caret, the cut sides marked with `...`. A width too small to hold the
// gutter and both markers behaves as the smallest usable one.
func WithWidth(width int) DiagnosticOption {
	return func(opts *diagnosticOptions) {
		opts.Width = width
	}
}

// Diagnostic renders a ParseError the way rustc reports errors.
//
// The rendering is the message, the position, and the source line with
// carets under the token the parser stopped at. This is the error path,
// it may allocate.
type Diagnostic struct {
	err  *ParseError
	opts diagnosticOptions
}

// NewDiagnostic wraps err for rendering.
func NewDiagnostic(err *ParseError, options ...DiagnosticOption) Diagnostic {
	opts := newDiagnosticOptions()
	for _, option := range options {
		option(&opts)
	}
	return Diagnostic{err: err, opts: opts}
}

// String renders the diagnostic, a trailing newline included.
func (m Diagnostic) String() string {
	var b strings.Builder
	number := strconv.Itoa(m.err.Line)
	gutter := strings.Repeat(" ", len(number))
	line, caret := m.sourceLine(len(number))

	b.WriteString("error: ")
	b.WriteString(m.err.Kind.Error())
	if m.err.Err != nil {
		b.WriteString(": ")
		b.WriteString(m.err.Err.Error())
	}
	b.WriteString("\n ")
	b.WriteString(gutter)
	b.WriteString("--> ")
	if m.opts.Path != "" {
		b.WriteString(m.opts.Path)
		b.WriteByte(':')
	}
	b.WriteString(number)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(m.err.Column + 1))
	b.WriteString("\n ")
	b.WriteString(gutter)
	b.WriteString(" |\n ")
	b.WriteString(number)
	b.WriteString(" | ")
	b.WriteString(line)
	b.WriteString("\n ")
	b.WriteString(gutter)
	b.WriteString(" | ")
	b.WriteString(strings.Repeat(" ", caret))
	b.WriteString(strings.Repeat("^", caretLen(line, caret)))
	b.WriteByte('\n')
	return b.String()
}

// WriteTo writes the rendering to w.
func (m Diagnostic) WriteTo(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, m.String())
	return int64(n), err
}

// sourceLine returns the source line as displayed and the caret column in
// it, the caret clamped to the last byte.
//
// When the line does not fit the room left by the gutter, the four cases
// of the reference apply: cut on the right when the caret is in the first
// half of the room, on the left when the room reaches the end of the line
// from the caret, on both sides otherwise. Each cut side loses four bytes
// to its marker, so the caret column is the same before and after.
func (m Diagnostic) sourceLine(gutter int) (string, int) {
	text := m.err.Text
	caret := min(max(m.err.Column, 0), max(len(text)-1, 0))
	room := max(m.opts.Width-gutter-4, 8)
	if m.opts.Width <= 0 || len(text) <= room {
		return text, caret
	}
	var start, end int
	switch {
	case caret < room/2:
		start, end = 0, room
	case caret-room/2+room > len(text):
		start, end = len(text)-room, len(text)
	default:
		start, end = caret-room/2, caret-room/2+room
	}
	line := text[start:end]
	if start > 0 {
		line = "... " + line[4:]
	}
	if end < len(text) {
		line = line[:len(line)-4] + " ..."
	}
	return line, caret - start
}

// caretLen is the length of the token under the caret, up to the next
// ASCII whitespace, at least one.
func caretLen(line string, caret int) int {
	if caret >= len(line) {
		return 1
	}
	word, _ := token(line[caret:])
	return max(len(word), 1)
}
