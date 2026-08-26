package ipfw

// CommandHook parses a line the grammar does not know, leading whitespace
// skipped and the newline excluded, driving the state itself.
//
// It returns the record of the line, the number of bytes consumed and any
// error. Zero bytes and no error decline the line, a record of kind
// RecordEmpty consumes it without reporting anything, and an error is
// positioned at the bytes consumed, an ErrorKind keeping its kind.
type CommandHook func(line string, state State) (Record, int, error)

// OptionHook parses a custom option at the start of rest.
//
// It returns the option, the number of bytes consumed and any error,
// ErrUnknownOption declining the token.
type OptionHook func(rest string) (Opt, int, error)
