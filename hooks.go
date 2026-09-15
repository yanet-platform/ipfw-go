package ipfw

// CommandHook parses an unknown command and drives the state itself.
//
// The Parser skips leading whitespace and excludes the newline and hash
// suffix. The remaining trailing whitespace is kept.
// It returns the record of the line, the number of bytes consumed and any
// error. Zero bytes and no error decline the line, a record of kind
// RecordEmpty consumes it without reporting anything, and an error is
// positioned at the bytes consumed, an ErrorKind keeping its kind.
type CommandHook func(line string, state State) (Record, int, error)

// OptionHook parses a custom option at the start of rest.
//
// The Parser supplies only the current physical line. Without `#`, its LF
// or CRLF is included when present. With `#`, input ends before the hash,
// so neither its payload nor the newline is included.
// It returns the option, the number of bytes consumed and any error,
// ErrUnknownOption declining the token.
// Exact lowercase `not` is reserved for negation and is never passed to the
// hook. A custom option whose text is `not` fails with ErrExpectedOpt.
type OptionHook func(rest string) (Opt, int, error)
