package ipfw

// TargetKind classifies a source or destination token by its shape.
type TargetKind uint8

// The target kinds. The parser classifies by shape and never validates a
// network, and anything of an unknown shape is TargetCustom.
const (
	_ TargetKind = iota
	TargetAny
	TargetMe
	TargetMe6
	TargetHostname
	TargetTable
	TargetNetwork4
	TargetNetwork6
	TargetCustom
)

// Target is a source or destination of the rule body, negated by `not`.
type Target struct {
	// Neg is the `not` prefix.
	Neg bool
	// Kind is the shape the token was classified as.
	Kind TargetKind
	// Text is the network text, the hostname, the table name or the raw
	// custom token, and empty for any, me and me6.
	Text string
}
