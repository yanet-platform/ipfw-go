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

// ParseSourcePorts parses the source port part of a rule body into state.
//
// It returns the number of bytes consumed, or on failure its offset together
// with the error, an ErrorKind unless the state returned something else.
func ParseSourcePorts(s string, state State) (int, error) {
	rest, err := parsePorts(s, state, false)
	return consumed(s, rest, err)
}

// ParseDestinationPorts is ParseSourcePorts for the destination part.
func ParseDestinationPorts(s string, state State) (int, error) {
	rest, err := parsePorts(s, state, true)
	return consumed(s, rest, err)
}

// parsePorts parses a comma list of port ranges into the source or the
// destination side of the state, a failure pointing at the port.
//
// Every range is emitted as soon as it is read, so the elements before a
// failure stay in the state while the input comes back unchanged.
func parsePorts(s string, state State, destination bool) (string, fail) {
	rest := s
	for {
		portRange, afterRange, failure := parsePortRange(rest)
		if failure.Failed() {
			return s, failure
		}
		match := PortMatch{Range: portRange}
		var err error
		if destination {
			err = state.DestinationPort(match)
		} else {
			err = state.SourcePort(match)
		}
		if failure = failFrom(err, rest); failure.Failed() {
			return s, failure
		}
		afterComma, ok := prefix(afterRange, ",")
		if !ok {
			return afterRange, fail{}
		}
		rest = afterComma
	}
}

// parsePortRange parses a port or a `lo-hi` range, a single port running
// from itself to itself, the failure pointing at the missing port.
func parsePortRange(s string) (PortRange, string, fail) {
	lo, rest, kind := parsePort(s)
	if kind != 0 {
		return PortRange{}, s, fail{Kind: kind, At: s}
	}
	afterDash, ok := prefix(rest, "-")
	if !ok {
		return PortRange{Lo: lo, Hi: lo}, rest, fail{}
	}
	hi, rest, kind := parsePort(afterDash)
	if kind != 0 {
		return PortRange{}, s, fail{Kind: kind, At: afterDash}
	}
	return PortRange{Lo: lo, Hi: hi}, rest, fail{}
}

// parsePort reads a run of letters and digits up to a dash, a number when
// every byte is a digit and the value fits sixteen bits, a name otherwise.
//
// An overflowing number is a name like any other, since custom services may
// be named by digits. An empty run is ErrExpectedPort.
func parsePort(s string) (Port, string, ErrorKind) {
	name, rest := takeWhile(s, isPortByte)
	if name == "" {
		return Port{}, s, ErrExpectedPort
	}
	if number, afterNumber, kind := parseU16(name); kind == 0 && afterNumber == "" {
		return Port{Number: number}, rest, 0
	}
	return Port{Name: name}, rest, 0
}

func isPortByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
