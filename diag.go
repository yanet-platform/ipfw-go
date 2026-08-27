package ipfw

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// diagOptions is what a DiagOption configures.
type diagOptions struct {
	// Path is printed before the position, none when empty.
	Path string
	// Width is the room the rendering may take, unlimited when zero.
	Width int
	// Style wraps the parts of the rendering, the zero value none.
	Style DiagStyle
}

func newDiagOptions() diagOptions {
	return diagOptions{}
}

// DiagOption configures a Diag, see the With functions.
type DiagOption func(*diagOptions)

// WithDiagPath names the file in the position line, as `path:line:column`.
func WithDiagPath(path string) DiagOption {
	return func(opts *diagOptions) {
		opts.Path = path
	}
}

// WithDiagWidth limits the width of the rendering, zero meaning unlimited.
//
// A source line that does not fit next to the gutter is cut around the
// caret, the cut sides marked with `...`. A width too small to hold the
// gutter and both markers behaves as the smallest usable one.
func WithDiagWidth(width int) DiagOption {
	return func(opts *diagOptions) {
		opts.Width = width
	}
}

// DiagStyle is what each part of a rendering is wrapped in, the zero value
// adding nothing.
//
// A role holds what opens its part and Reset what ends every one. The
// roles are meant for ANSI escapes, see ColorDiagStyle, but anything a
// consumer's terminal or markup takes will do, and whatever they hold
// does not count against the width.
type DiagStyle struct {
	// Error opens the word `error`.
	Error string
	// Message opens the text of the error.
	Message string
	// Info opens the position line and the gutter.
	Info string
	// Span opens the carets.
	Span string
	// Dimmed opens the markers of a cut line.
	Dimmed string
	// Reset ends every role.
	Reset string
}

// ColorDiagStyle is the palette of a terminal that takes ANSI escapes.
func ColorDiagStyle() DiagStyle {
	return DiagStyle{
		Error:   "\x1b[1;91m",
		Message: "\x1b[1m",
		Info:    "\x1b[1;94m",
		Span:    "\x1b[1;93m",
		Dimmed:  "\x1b[2m",
		Reset:   "\x1b[0m",
	}
}

// DiagStyleFor is the palette when w is a terminal that takes colour and
// the zero DiagStyle otherwise, so that a rendering piped into a file stays plain.
//
// A terminal is a character device the environment does not speak against:
// NO_COLOR set to anything, or TERM naming a dumb one, means no colour.
// Anything that is not an *os.File is not a terminal. The check is the one
// the standard library affords, so a character device that is no terminal,
// os.DevNull among them, passes for one, and on Windows it says nothing
// about whether the console takes the escapes.
func DiagStyleFor(w io.Writer) DiagStyle {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return DiagStyle{}
	}
	file, ok := w.(*os.File)
	if !ok || file == nil {
		return DiagStyle{}
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return DiagStyle{}
	}
	return ColorDiagStyle()
}

// WithDiagStyle wraps the parts of the rendering in the style, the zero value
// leaving it plain.
func WithDiagStyle(style DiagStyle) DiagOption {
	return func(opts *diagOptions) {
		opts.Style = style
	}
}

// Diag renders a ParseError as a diagnostic message.
//
// The rendering is the message, the position, and the source line with
// carets under the token the parser stopped at. This is the error path,
// it may allocate.
type Diag struct {
	err  *ParseError
	opts diagOptions
}

// NewDiag wraps err for rendering.
func NewDiag(err *ParseError, options ...DiagOption) Diag {
	opts := newDiagOptions()
	for _, option := range options {
		option(&opts)
	}
	return Diag{err: err, opts: opts}
}

// String renders the diagnostic, a trailing newline included.
func (m Diag) String() string {
	var b strings.Builder
	style := m.opts.Style
	number := strconv.Itoa(m.err.Line)
	gutter := strings.Repeat(" ", len(number))
	line, caret, left, right := m.sourceLine(len(number))
	carets := strings.Repeat("^", caretLen(line, caret))

	b.WriteString(style.Error)
	b.WriteString("error")
	style.reset(&b, style.Error)
	b.WriteString(style.Message)
	b.WriteString(": ")
	b.WriteString(m.err.Kind.Error())
	if m.err.Err != nil {
		b.WriteString(": ")
		b.WriteString(m.err.Err.Error())
	}
	style.reset(&b, style.Message)

	b.WriteByte('\n')
	b.WriteString(style.Info)
	b.WriteByte(' ')
	b.WriteString(gutter)
	b.WriteString("--> ")
	if m.opts.Path != "" {
		b.WriteString(m.opts.Path)
		b.WriteByte(':')
	}
	b.WriteString(number)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(m.err.Column + 1))
	style.reset(&b, style.Info)

	b.WriteByte('\n')
	b.WriteString(style.Info)
	b.WriteByte(' ')
	b.WriteString(gutter)
	b.WriteString(" |")
	style.reset(&b, style.Info)

	b.WriteByte('\n')
	b.WriteString(style.Info)
	b.WriteByte(' ')
	b.WriteString(number)
	b.WriteString(" | ")
	style.reset(&b, style.Info)
	style.writeLine(&b, line, left, right)

	b.WriteByte('\n')
	b.WriteString(style.Info)
	b.WriteByte(' ')
	b.WriteString(gutter)
	b.WriteString(" | ")
	style.reset(&b, style.Info)
	b.WriteString(strings.Repeat(" ", caret))
	b.WriteString(style.Span)
	b.WriteString(carets)
	style.reset(&b, style.Span)
	b.WriteByte('\n')
	return b.String()
}

// reset ends a role, nothing having opened it when the role is empty.
func (m DiagStyle) reset(b *strings.Builder, role string) {
	if role != "" {
		b.WriteString(m.Reset)
	}
}

// writeLine writes the source line with the markers of its cut sides
// dimmed.
func (m DiagStyle) writeLine(b *strings.Builder, line string, left, right bool) {
	if left {
		b.WriteString(m.Dimmed)
		b.WriteString(line[:markerLen])
		m.reset(b, m.Dimmed)
		line = line[markerLen:]
	}
	var marker string
	if right {
		marker, line = line[len(line)-markerLen:], line[:len(line)-markerLen]
	}
	b.WriteString(line)
	if right {
		b.WriteString(m.Dimmed)
		b.WriteString(marker)
		m.reset(b, m.Dimmed)
	}
}

// WriteTo writes the rendering to w.
func (m Diag) WriteTo(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, m.String())
	return int64(n), err
}

// markerLen is the length of the marker of a cut side, `... `.
const markerLen = 4

// sourceLine returns the source line as displayed, the caret column in it,
// the caret clamped to the last byte, and which sides were cut.
//
// When the line does not fit the room left by the gutter, the four cases
// of the reference apply: cut on the right when the caret is in the first
// half of the room, on the left when the room reaches the end of the line
// from the caret, on both sides otherwise. Each cut side loses four bytes
// to its marker, so the caret column is the same before and after.
func (m Diag) sourceLine(gutter int) (string, int, bool, bool) {
	text := m.err.Text
	caret := min(max(m.err.Column, 0), max(len(text)-1, 0))
	room := max(m.opts.Width-gutter-markerLen, 8)
	if m.opts.Width <= 0 || len(text) <= room {
		return text, caret, false, false
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
	left, right := start > 0, end < len(text)
	if left {
		line = "... " + line[markerLen:]
	}
	if right {
		line = line[:len(line)-markerLen] + " ..."
	}
	return line, caret - start, left, right
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
