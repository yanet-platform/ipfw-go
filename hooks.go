package ipfw

// OptionHook parses a custom option at the start of rest.
//
// It returns the option, the number of bytes consumed and any error,
// ErrUnknownOption declining the token.
type OptionHook func(rest string) (Opt, int, error)
