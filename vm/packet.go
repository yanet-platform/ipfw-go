package vm

import (
	"encoding/binary"
	"net/netip"

	"github.com/yanet-platform/ipfw"
)

// The transport protocol numbers the matcher knows.
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// The header lengths the raw packets assume: an IPv4 header without
// options and an IPv6 header without extension headers.
const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
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

// Packet is what the matcher reads from a packet.
type Packet interface {
	// Version is the IP version.
	Version() IPVersion
	// Protocol is the transport protocol number.
	Protocol() uint8
	// SourceAddr is the source address.
	SourceAddr() netip.Addr
	// DestinationAddr is the destination address.
	DestinationAddr() netip.Addr
	// SourcePort is the source port of a TCP or UDP packet.
	SourcePort() (uint16, bool)
	// DestinationPort is the destination port of a TCP or UDP packet.
	DestinationPort() (uint16, bool)
	// TCPFlags are the flags of a TCP packet.
	TCPFlags() (ipfw.TCPFlag, bool)
	// IsFragment reports whether the packet is a fragment other than the
	// first one.
	IsFragment() bool
	// ICMPType is the type of an ICMP packet.
	ICMPType() (uint8, bool)
	// ICMP6Type is the type of an ICMPv6 packet.
	ICMP6Type() (uint8, bool)
}

// RawIPv4Packet is an IPv4 packet as bytes, the header taken to be twenty
// bytes long whatever its IHL says.
//
// A field beyond the end of the bytes reads as zero or absent.
type RawIPv4Packet []byte

// NewIPv4Packet builds a packet between two IPv4 addresses, panicking on
// any other address: the builders are conveniences, not a parsing path.
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

// WithTCP makes the packet a TCP one.
func (m RawIPv4Packet) WithTCP(flags ipfw.TCPFlag, src, dst uint16) RawIPv4Packet {
	m[9] = protoTCP
	setPorts(m[ipv4HeaderLen:], src, dst)
	m[ipv4HeaderLen+13] |= byte(flags)
	return m
}

// WithUDP makes the packet a UDP one.
func (m RawIPv4Packet) WithUDP(src, dst uint16) RawIPv4Packet {
	m[9] = protoUDP
	setPorts(m[ipv4HeaderLen:], src, dst)
	return m
}

// WithICMP makes the packet an ICMP one.
func (m RawIPv4Packet) WithICMP(ty, code uint8) RawIPv4Packet {
	m[9] = protoICMP
	m[ipv4HeaderLen], m[ipv4HeaderLen+1] = ty, code
	return m
}

// WithFragmentOffset sets the thirteen-bit fragment offset, keeping the
// flag bits above it.
func (m RawIPv4Packet) WithFragmentOffset(offset uint16) RawIPv4Packet {
	m[6] = m[6]&0xe0 | byte(offset>>8)&0x1f
	m[7] = byte(offset)
	return m
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

// SourcePort implements Packet.
func (m RawIPv4Packet) SourcePort() (uint16, bool) {
	return portAt(m, m.transport(), ipv4HeaderLen)
}

// DestinationPort implements Packet.
func (m RawIPv4Packet) DestinationPort() (uint16, bool) {
	return portAt(m, m.transport(), ipv4HeaderLen+2)
}

// TCPFlags implements Packet.
func (m RawIPv4Packet) TCPFlags() (ipfw.TCPFlag, bool) {
	return tcpFlagsAt(m, m.transport(), ipv4HeaderLen+13)
}

// IsFragment implements Packet.
func (m RawIPv4Packet) IsFragment() bool {
	return byteAt(m, 6)&0x1f != 0 || byteAt(m, 7) != 0
}

// ICMPType implements Packet.
func (m RawIPv4Packet) ICMPType() (uint8, bool) {
	return typeAt(m, m.transport(), protoICMP, ipv4HeaderLen)
}

// ICMP6Type implements Packet.
func (m RawIPv4Packet) ICMP6Type() (uint8, bool) {
	return typeAt(m, m.transport(), protoICMPv6, ipv4HeaderLen)
}

// transport is the protocol of the header after the IP header, none for
// a non-first fragment, which carries payload there.
func (m RawIPv4Packet) transport() uint8 {
	if m.IsFragment() {
		return 0
	}
	return m.Protocol()
}

// RawIPv6Packet is an IPv6 packet as bytes, the header taken to be forty
// bytes long, extension headers not being followed.
//
// A field beyond the end of the bytes reads as zero or absent.
type RawIPv6Packet []byte

// NewIPv6Packet builds a packet between two IPv6 addresses, panicking on
// any other address: the builders are conveniences, not a parsing path.
func NewIPv6Packet(src, dst netip.Addr) RawIPv6Packet {
	if !src.Is6() || src.Is4In6() || !dst.Is6() || dst.Is4In6() {
		panic("vm: NewIPv6Packet needs IPv6 addresses")
	}
	packet := make(RawIPv6Packet, 64)
	packet[0] = 6 << 4
	from, to := src.As16(), dst.As16()
	copy(packet[8:24], from[:])
	copy(packet[24:40], to[:])
	return packet
}

// WithTCP makes the packet a TCP one.
func (m RawIPv6Packet) WithTCP(flags ipfw.TCPFlag, src, dst uint16) RawIPv6Packet {
	m[6] = protoTCP
	setPorts(m[ipv6HeaderLen:], src, dst)
	m[ipv6HeaderLen+13] |= byte(flags)
	return m
}

// WithUDP makes the packet a UDP one.
func (m RawIPv6Packet) WithUDP(src, dst uint16) RawIPv6Packet {
	m[6] = protoUDP
	setPorts(m[ipv6HeaderLen:], src, dst)
	return m
}

// WithICMP6 makes the packet an ICMPv6 one.
func (m RawIPv6Packet) WithICMP6(ty, code uint8) RawIPv6Packet {
	m[6] = protoICMPv6
	m[ipv6HeaderLen], m[ipv6HeaderLen+1] = ty, code
	return m
}

// Version implements Packet.
func (m RawIPv6Packet) Version() IPVersion {
	return ipVersion(byteAt(m, 0) >> 4)
}

// Protocol implements Packet.
func (m RawIPv6Packet) Protocol() uint8 {
	return byteAt(m, 6)
}

// SourceAddr implements Packet.
func (m RawIPv6Packet) SourceAddr() netip.Addr {
	return addr6At(m, 8)
}

// DestinationAddr implements Packet.
func (m RawIPv6Packet) DestinationAddr() netip.Addr {
	return addr6At(m, 24)
}

// SourcePort implements Packet.
func (m RawIPv6Packet) SourcePort() (uint16, bool) {
	return portAt(m, m.Protocol(), ipv6HeaderLen)
}

// DestinationPort implements Packet.
func (m RawIPv6Packet) DestinationPort() (uint16, bool) {
	return portAt(m, m.Protocol(), ipv6HeaderLen+2)
}

// TCPFlags implements Packet.
func (m RawIPv6Packet) TCPFlags() (ipfw.TCPFlag, bool) {
	return tcpFlagsAt(m, m.Protocol(), ipv6HeaderLen+13)
}

// IsFragment implements Packet.
func (m RawIPv6Packet) IsFragment() bool {
	return false
}

// ICMPType implements Packet.
func (m RawIPv6Packet) ICMPType() (uint8, bool) {
	return typeAt(m, m.Protocol(), protoICMP, ipv6HeaderLen)
}

// ICMP6Type implements Packet.
func (m RawIPv6Packet) ICMP6Type() (uint8, bool) {
	return typeAt(m, m.Protocol(), protoICMPv6, ipv6HeaderLen)
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

// portAt is the port at idx of a TCP or UDP packet.
func portAt(packet []byte, protocol uint8, idx int) (uint16, bool) {
	if protocol != protoTCP && protocol != protoUDP || idx+2 > len(packet) {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[idx : idx+2]), true
}

// tcpFlagsAt is the flag byte at idx of a TCP packet.
func tcpFlagsAt(packet []byte, protocol uint8, idx int) (ipfw.TCPFlag, bool) {
	if protocol != protoTCP || idx >= len(packet) {
		return 0, false
	}
	return ipfw.TCPFlag(packet[idx]), true
}

// typeAt is the type byte at idx of a packet of the given protocol.
func typeAt(packet []byte, protocol, wanted uint8, idx int) (uint8, bool) {
	if protocol != wanted || idx >= len(packet) {
		return 0, false
	}
	return packet[idx], true
}
