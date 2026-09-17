package vm

import (
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/yanet-platform/ipfw-go"
)

// The upper-layer protocol numbers the matcher knows, and the IPv6 one that
// names none.
const (
	protoICMP         = 1
	protoTCP          = 6
	protoUDP          = 17
	protoICMPv6       = 58
	protoNoNextHeader = 59
	protoSCTP         = 132
	protoUDPLite      = 136
)

// The IPv6 extension headers followed up to the upper layer, the ones
// ipfw_chk follows.
const (
	protoHopOptions     = 0
	protoRouting        = 43
	protoFragment       = 44
	protoAuthentication = 51
	protoDstOptions     = 60
)

// The header lengths: the fixed IPv4 and IPv6 headers and the IPv6 fragment
// header.
const (
	ipv4HeaderLen   = 20
	ipv6HeaderLen   = 40
	ipv6FragmentLen = 8
)

// Direction is where a packet is seen relative to routing.
type Direction uint8

// The directions: In is before routing, Out after it.
const (
	In Direction = iota
	Out
)

// Context is what a check needs beyond the packet bytes: the direction,
// the interface and the addresses of this host.
type Context struct {
	// Direction is where the packet is seen.
	Direction Direction
	// IfName is the interface the packet is received on or sent through.
	IfName string
	// LocalAddrs are the addresses of this host, what `me` and `me6` match.
	LocalAddrs []netip.Addr
}

// IPVersion is the IP version of a packet, the zero value being neither.
type IPVersion uint8

// The IP versions.
const (
	_ IPVersion = iota
	IPv4
	IPv6
)

// ipVersion tells the version from the first nibble of a packet.
func ipVersion(nibble byte) IPVersion {
	switch nibble {
	case 4:
		return IPv4
	case 6:
		return IPv6
	}
	return 0
}

// Packet is what the matcher reads from a packet: the fields of its headers.
//
// The VM decides which fields mean something for the packet, as ipfw(8)
// does, so a packet only reports what its headers hold. A transport field is
// asked for on a first fragment or a whole packet of a protocol that has it,
// and false tells that the packet does not hold the header.
type Packet interface {
	// Version is the IP version.
	Version() IPVersion
	// Protocol is the upper-layer protocol, past any IPv6 extension headers.
	Protocol() uint8
	// SourceAddr is the source address.
	SourceAddr() netip.Addr
	// DestinationAddr is the destination address.
	DestinationAddr() netip.Addr
	// IsFragment reports whether the packet is a fragment other than the
	// first one, IPv4 or IPv6.
	IsFragment() bool
	// SourcePort is the source port field of the transport header, asked for
	// only for TCP, UDP, SCTP and UDP-Lite.
	SourcePort() (uint16, bool)
	// DestinationPort is the destination port field of the transport header,
	// asked for only for TCP, UDP, SCTP and UDP-Lite.
	DestinationPort() (uint16, bool)
	// TCPFlags are the flags of the TCP header, asked for only for TCP.
	TCPFlags() (ipfw.TCPFlag, bool)
	// ICMPType is the type field of the ICMP or ICMPv6 header, asked for only
	// when Protocol names one of them.
	ICMPType() (uint8, bool)
}

// RawIPv4Packet is an IPv4 packet as bytes, read the way ipfw_chk reads it:
// its header as long as its IHL says, the transport fields at the header past
// it whatever the protocol.
//
// A field beyond the end of the bytes reads as zero or absent.
type RawIPv4Packet []byte

// NewIPv4Packet builds a packet between two IPv4 addresses, panicking on any
// other address: the builders are conveniences, not a parsing path.
func NewIPv4Packet(src, dst netip.Addr) RawIPv4Packet {
	if !src.Is4() || !dst.Is4() {
		panic("vm: NewIPv4Packet needs IPv4 addresses")
	}
	packet := make(RawIPv4Packet, 64)
	packet[0] = 4<<4 | 5
	from, to := src.As4(), dst.As4()
	copy(packet[12:16], from[:])
	copy(packet[16:20], to[:])
	return packet
}

// WithTCP returns a copy made a TCP packet with the flags and the ports.
//
// Every builder returns a copy, so that packets built from one base share no
// bytes.
func (m RawIPv4Packet) WithTCP(flags ipfw.TCPFlag, src, dst uint16) RawIPv4Packet {
	packet, at := m.withProtocol(protoTCP, 14)
	setPorts(packet[at:], src, dst)
	packet[at+13] = byte(flags)
	return packet
}

// WithUDP returns a copy made a UDP packet with the ports.
func (m RawIPv4Packet) WithUDP(src, dst uint16) RawIPv4Packet {
	packet, at := m.withProtocol(protoUDP, 8)
	setPorts(packet[at:], src, dst)
	return packet
}

// WithICMP returns a copy made an ICMP packet with the type and the code.
func (m RawIPv4Packet) WithICMP(ty, code uint8) RawIPv4Packet {
	packet, at := m.withProtocol(protoICMP, 4)
	packet[at], packet[at+1] = ty, code
	return packet
}

// WithFragmentOffset returns a copy with the thirteen-bit fragment offset,
// keeping the flag bits above it.
func (m RawIPv4Packet) WithFragmentOffset(offset uint16) RawIPv4Packet {
	packet := slices.Clone(m)
	packet[6] = packet[6]&0xe0 | byte(offset>>8)&0x1f
	packet[7] = byte(offset)
	return packet
}

// withProtocol returns a copy naming the protocol, long enough for a header
// of room bytes past the IP header, and the index of that header.
func (m RawIPv4Packet) withProtocol(protocol uint8, room int) (RawIPv4Packet, int) {
	at := m.transport()
	if at < 0 {
		panic("vm: the packet has no room for a transport header")
	}
	packet := slices.Clone(m)
	if short := at + room - len(packet); short > 0 {
		packet = append(packet, make([]byte, short)...)
	}
	packet[9] = protocol
	return packet, at
}

// Version implements Packet.
func (m RawIPv4Packet) Version() IPVersion {
	return ipVersion(byteAt(m, 0) >> 4)
}

// Protocol implements Packet.
func (m RawIPv4Packet) Protocol() uint8 {
	return byteAt(m, 9)
}

// SourceAddr implements Packet.
func (m RawIPv4Packet) SourceAddr() netip.Addr {
	return addr4At(m, 12)
}

// DestinationAddr implements Packet.
func (m RawIPv4Packet) DestinationAddr() netip.Addr {
	return addr4At(m, 16)
}

// IsFragment implements Packet.
func (m RawIPv4Packet) IsFragment() bool {
	return byteAt(m, 6)&0x1f != 0 || byteAt(m, 7) != 0
}

// SourcePort implements Packet.
func (m RawIPv4Packet) SourcePort() (uint16, bool) {
	return uint16At(m, m.transport())
}

// DestinationPort implements Packet.
func (m RawIPv4Packet) DestinationPort() (uint16, bool) {
	return uint16At(m, m.transport()+2)
}

// TCPFlags implements Packet.
func (m RawIPv4Packet) TCPFlags() (ipfw.TCPFlag, bool) {
	flags, ok := uint8At(m, m.transport()+13)
	return ipfw.TCPFlag(flags), ok
}

// ICMPType implements Packet.
func (m RawIPv4Packet) ICMPType() (uint8, bool) {
	return uint8At(m, m.transport())
}

// transport is the index of the header past the IP header, as long as its
// IHL says, far out of reach when the IHL is shorter than the fixed header.
func (m RawIPv4Packet) transport() int {
	length := int(byteAt(m, 0)&0x0f) * 4
	if length < ipv4HeaderLen {
		return -1 << 30
	}
	return length
}

// RawIPv6Packet is an IPv6 packet as bytes, read the way ipfw_chk reads it:
// the extension headers ipfw_chk follows, hop-by-hop options, routing,
// fragment, destination options and authentication, are walked up to the
// upper layer or to a non-first fragment, and the transport fields are read
// at the header past them whatever the protocol.
//
// A field beyond the end of the bytes reads as zero or absent.
type RawIPv6Packet []byte

// NewIPv6Packet builds a packet between two IPv6 addresses, naming no next
// header, panicking on any other address: the builders are conveniences, not
// a parsing path.
func NewIPv6Packet(src, dst netip.Addr) RawIPv6Packet {
	if !src.Is6() || src.Is4In6() || !dst.Is6() || dst.Is4In6() {
		panic("vm: NewIPv6Packet needs IPv6 addresses")
	}
	packet := make(RawIPv6Packet, 64)
	packet[0], packet[6] = 6<<4, protoNoNextHeader
	from, to := src.As16(), dst.As16()
	copy(packet[8:24], from[:])
	copy(packet[24:40], to[:])
	return packet
}

// WithTCP returns a copy made a TCP packet with the flags and the ports.
func (m RawIPv6Packet) WithTCP(flags ipfw.TCPFlag, src, dst uint16) RawIPv6Packet {
	packet, at := m.withProtocol(protoTCP, 14)
	setPorts(packet[at:], src, dst)
	packet[at+13] = byte(flags)
	return packet
}

// WithUDP returns a copy made a UDP packet with the ports.
func (m RawIPv6Packet) WithUDP(src, dst uint16) RawIPv6Packet {
	packet, at := m.withProtocol(protoUDP, 8)
	setPorts(packet[at:], src, dst)
	return packet
}

// WithICMP6 returns a copy made an ICMPv6 packet with the type and the code.
func (m RawIPv6Packet) WithICMP6(ty, code uint8) RawIPv6Packet {
	packet, at := m.withProtocol(protoICMPv6, 4)
	packet[at], packet[at+1] = ty, code
	return packet
}

// WithFragmentOffset returns a copy with the thirteen-bit fragment offset in
// a fragment header right after the fixed header, inserted when there is
// none.
func (m RawIPv6Packet) WithFragmentOffset(offset uint16) RawIPv6Packet {
	packet := slices.Clone(m)
	if packet[6] != protoFragment {
		header := [ipv6FragmentLen]byte{packet[6]}
		packet = slices.Insert(packet, ipv6HeaderLen, header[:]...)
		packet[6] = protoFragment
	}
	field := packet[ipv6HeaderLen+2 : ipv6HeaderLen+4]
	flags := binary.BigEndian.Uint16(field) & 7
	binary.BigEndian.PutUint16(field, offset<<3|flags)
	return packet
}

// withProtocol returns a copy naming the protocol as its upper layer, long
// enough for a header of room bytes, and the index of that header.
func (m RawIPv6Packet) withProtocol(protocol uint8, room int) (RawIPv6Packet, int) {
	layout := m.layout()
	if layout.Transport < 0 {
		panic("vm: the packet has no room for a transport header")
	}
	packet := slices.Clone(m)
	if short := layout.Transport + room - len(packet); short > 0 {
		packet = append(packet, make([]byte, short)...)
	}
	packet[layout.NextHeader] = protocol
	return packet, layout.Transport
}

// Version implements Packet.
func (m RawIPv6Packet) Version() IPVersion {
	return ipVersion(byteAt(m, 0) >> 4)
}

// Protocol implements Packet.
func (m RawIPv6Packet) Protocol() uint8 {
	if next := byteAt(m, 6); !isExtensionHeader(next) {
		return next
	}
	return m.layout().Protocol
}

// SourceAddr implements Packet.
func (m RawIPv6Packet) SourceAddr() netip.Addr {
	return addr6At(m, 8)
}

// DestinationAddr implements Packet.
func (m RawIPv6Packet) DestinationAddr() netip.Addr {
	return addr6At(m, 24)
}

// IsFragment implements Packet.
func (m RawIPv6Packet) IsFragment() bool {
	if !isExtensionHeader(byteAt(m, 6)) {
		return false
	}
	return m.layout().Fragment
}

// SourcePort implements Packet.
func (m RawIPv6Packet) SourcePort() (uint16, bool) {
	if isExtensionHeader(byteAt(m, 6)) {
		return uint16At(m, m.walkedTransport())
	}
	return uint16At(m, ipv6HeaderLen)
}

// DestinationPort implements Packet.
func (m RawIPv6Packet) DestinationPort() (uint16, bool) {
	if isExtensionHeader(byteAt(m, 6)) {
		return uint16At(m, m.walkedTransport()+2)
	}
	return uint16At(m, ipv6HeaderLen+2)
}

// TCPFlags implements Packet.
func (m RawIPv6Packet) TCPFlags() (ipfw.TCPFlag, bool) {
	at := ipv6HeaderLen
	if isExtensionHeader(byteAt(m, 6)) {
		at = m.walkedTransport()
	}
	flags, ok := uint8At(m, at+13)
	return ipfw.TCPFlag(flags), ok
}

// ICMPType implements Packet.
func (m RawIPv6Packet) ICMPType() (uint8, bool) {
	if isExtensionHeader(byteAt(m, 6)) {
		return uint8At(m, m.walkedTransport())
	}
	return uint8At(m, ipv6HeaderLen)
}

// walkedTransport is the index of the header past the extension headers, far
// out of reach when the packet holds none.
//
// The accessors call it only for a fixed header naming an extension header,
// so that nearly every packet is read with one call less.
//
//go:noinline
func (m RawIPv6Packet) walkedTransport() int {
	if at := m.layout().Transport; at >= 0 {
		return at
	}
	return -1 << 30
}

// extensionHeaders has the bit of every IPv6 extension header layout
// follows, all of them numbered below 64.
const extensionHeaders = 1<<protoHopOptions | 1<<protoRouting | 1<<protoFragment |
	1<<protoAuthentication | 1<<protoDstOptions

// isExtensionHeader reports whether the protocol is an extension header the
// walk follows.
func isExtensionHeader(protocol uint8) bool {
	return protocol < 64 && extensionHeaders>>protocol&1 != 0
}

// ipv6Layout is where the layers of an IPv6 packet lie.
type ipv6Layout struct {
	// Protocol is the upper-layer protocol, or the extension header a
	// truncated packet stops at.
	Protocol uint8
	// NextHeader is the index of the field naming Protocol.
	NextHeader int
	// Transport is the index of the header past the IP headers, negative
	// when the packet holds none.
	Transport int
	// Fragment is whether the packet is a fragment other than the first one.
	Fragment bool
}

// layout follows the extension headers up to the upper layer, as ipfw_chk
// does before it runs the rules, stopping at a non-first fragment, whose
// upper layer is the payload of another packet.
//
// A header too short to name the next one leaves no transport header. A
// header running past the end still names it, the transport header then
// reading as absent.
func (m RawIPv6Packet) layout() ipv6Layout {
	layout := ipv6Layout{Protocol: byteAt(m, 6), NextHeader: 6, Transport: ipv6HeaderLen}
	for {
		at := layout.Transport
		need := 2
		switch layout.Protocol {
		case protoHopOptions, protoRouting, protoDstOptions, protoAuthentication:
		case protoFragment:
			need = ipv6FragmentLen
		default:
			return layout
		}
		if at+need > len(m) {
			layout.Transport = -1
			return layout
		}
		length := (int(m[at+1]) + 1) * 8
		switch layout.Protocol {
		case protoAuthentication:
			length = (int(m[at+1]) + 2) * 4
		case protoFragment:
			length = ipv6FragmentLen
			layout.Fragment = binary.BigEndian.Uint16(m[at+2:at+4])>>3 != 0
		}
		layout.Protocol, layout.NextHeader, layout.Transport = m[at], at, at+length
		if layout.Fragment {
			return layout
		}
	}
}

// setPorts writes the two ports of a transport header.
func setPorts(transport []byte, src, dst uint16) {
	binary.BigEndian.PutUint16(transport[0:2], src)
	binary.BigEndian.PutUint16(transport[2:4], dst)
}

// byteAt is the byte at idx, zero beyond the end.
func byteAt(packet []byte, idx int) byte {
	if idx < len(packet) {
		return packet[idx]
	}
	return 0
}

// addr4At is the IPv4 address at idx, the zero address beyond the end.
func addr4At(packet []byte, idx int) netip.Addr {
	if idx+4 > len(packet) {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(packet[idx : idx+4]))
}

// addr6At is the IPv6 address at idx, the zero address beyond the end.
func addr6At(packet []byte, idx int) netip.Addr {
	if idx+16 > len(packet) {
		return netip.Addr{}
	}
	return netip.AddrFrom16([16]byte(packet[idx : idx+16]))
}

// uint16At is the big-endian field at idx, absent beyond the end.
func uint16At(packet []byte, idx int) (uint16, bool) {
	if idx < 0 || idx+2 > len(packet) {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[idx : idx+2]), true
}

// uint8At is the byte at idx, absent beyond the end.
func uint8At(packet []byte, idx int) (uint8, bool) {
	if idx < 0 || idx >= len(packet) {
		return 0, false
	}
	return packet[idx], true
}
