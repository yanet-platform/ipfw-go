package ipfw

// CommandHook parses an unknown command and drives the state itself.
//
// The Parser skips leading whitespace and excludes the newline and hash
// suffix. The remaining trailing whitespace is kept.
// The returned count is a byte offset into the supplied text, valid from zero
// through its byte length. Values outside that range are clamped before use.
// With no error, zero declines the line and a positive count accepts it. A
// record of kind RecordEmpty accepts without reporting a command. With an
// error, the count only positions it, and an ErrorKind keeps its kind. Negative
// counts therefore act as zero and oversized counts as the input length.
type CommandHook func(line string, state State) (Record, int, error)

// OptionHook parses a custom option at the start of rest.
//
// The Parser supplies only the current physical line. Without `#`, its LF
// or CRLF is included when present. With `#`, input ends before the hash,
// so neither its payload nor the newline is included.
// The Parser may call a hook more than once for one occurrence while selecting
// a body grammar or distinguishing an option from a destination port. Calls
// must be side-effect-free and deterministic: equal input produces the same
// option, count and error outcome. Every result applies immediately. The parser
// neither compares repeated results nor revisits an earlier decision if they differ.
// The returned count is a byte offset into the supplied text, valid from zero
// through its byte length. Values outside that range are clamped before use.
// With no error, zero declines the token and a positive count accepts it.
// ErrUnknownOption also declines the token. Any error uses the count only as
// its position. Negative counts therefore act as zero and oversized counts as
// the input length.
type OptionHook func(rest string) (Opt, int, error)
