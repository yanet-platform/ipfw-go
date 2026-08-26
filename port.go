package ipfw

// Port is a transport port, by service name or by number.
type Port struct {
	// Name is empty for a numeric port and keeps any backslash escapes.
	Name string
	// Number is the port when Name is empty.
	Number uint16
}

// IsNumber reports whether the port was given as a number.
func (m Port) IsNumber() bool {
	return m.Name == ""
}

// PortRange is an inclusive `lo-hi` range, a single port having Hi equal to Lo.
type PortRange struct {
	// Lo is the first port of the range.
	Lo Port
	// Hi is the last port of the range.
	Hi Port
}

// PortMatch is a port range of the rule body, negated by `not`.
type PortMatch struct {
	// Neg is the `not` prefix.
	Neg bool
	// Range is the port range.
	Range PortRange
}
