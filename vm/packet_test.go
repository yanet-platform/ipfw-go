package vm_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw"
	"github.com/yanet-platform/ipfw/vm"
)

var (
	_ vm.Packet = vm.RawIPv4Packet(nil)
	_ vm.Packet = vm.RawIPv6Packet(nil)
)

var (
	src4 = netip.MustParseAddr("192.0.2.1")
	dst4 = netip.MustParseAddr("198.51.100.7")
	src6 = netip.MustParseAddr("2001:db8::1")
	dst6 = netip.MustParseAddr("2001:db8::2")
)

// fields is everything the matcher reads from a packet, for comparison.
type fields struct {
	version                   vm.IPVersion
	protocol                  uint8
	src, dst                  netip.Addr
	srcPort, dstPort          uint16
	hasSrcPort, hasDstPort    bool
	flags                     ipfw.TCPFlag
	hasFlags                  bool
	fragment                  bool
	icmpType, icmp6Type       uint8
	hasICMPType, hasICMP6Type bool
}

// fieldsOf reads every accessor of a packet.
func fieldsOf(packet vm.Packet) fields {
	var f fields
	f.version, f.protocol = packet.Version(), packet.Protocol()
	f.src, f.dst = packet.SourceAddr(), packet.DestinationAddr()
	f.srcPort, f.hasSrcPort = packet.SourcePort()
	f.dstPort, f.hasDstPort = packet.DestinationPort()
	f.flags, f.hasFlags = packet.TCPFlags()
	f.fragment = packet.IsFragment()
	f.icmpType, f.hasICMPType = packet.ICMPType()
	f.icmp6Type, f.hasICMP6Type = packet.ICMP6Type()
	return f
}

// verifies that every builder combination is read back field by field,
// the accessors of the other transports reporting nothing.
func Test_Packet_Table(t *testing.T) {
	cases := []struct {
		name     string
		packet   vm.Packet
		expected fields
	}{
		{
			name:     "IPv4 without transport",
			packet:   vm.NewIPv4Packet(src4, dst4),
			expected: fields{version: vm.IPv4, src: src4, dst: dst4},
		},
		{
			name:   "IPv4 TCP",
			packet: vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn|ipfw.TCPAck, 40000, 22),
			expected: fields{
				version: vm.IPv4, protocol: 6, src: src4, dst: dst4,
				srcPort: 40000, dstPort: 22, hasSrcPort: true, hasDstPort: true,
				flags: ipfw.TCPSyn | ipfw.TCPAck, hasFlags: true,
			},
		},
		{
			name:   "IPv4 UDP",
			packet: vm.NewIPv4Packet(src4, dst4).WithUDP(53, 65535),
			expected: fields{
				version: vm.IPv4, protocol: 17, src: src4, dst: dst4,
				srcPort: 53, dstPort: 65535, hasSrcPort: true, hasDstPort: true,
			},
		},
		{
			name:   "IPv4 ICMP",
			packet: vm.NewIPv4Packet(src4, dst4).WithICMP(8, 0),
			expected: fields{
				version: vm.IPv4, protocol: 1, src: src4, dst: dst4,
				icmpType: 8, hasICMPType: true,
			},
		},
		{
			name:     "IPv6 without transport",
			packet:   vm.NewIPv6Packet(src6, dst6),
			expected: fields{version: vm.IPv6, src: src6, dst: dst6},
		},
		{
			name:   "IPv6 TCP",
			packet: vm.NewIPv6Packet(src6, dst6).WithTCP(ipfw.TCPRst, 1, 65535),
			expected: fields{
				version: vm.IPv6, protocol: 6, src: src6, dst: dst6,
				srcPort: 1, dstPort: 65535, hasSrcPort: true, hasDstPort: true,
				flags: ipfw.TCPRst, hasFlags: true,
			},
		},
		{
			name:   "IPv6 UDP",
			packet: vm.NewIPv6Packet(src6, dst6).WithUDP(546, 547),
			expected: fields{
				version: vm.IPv6, protocol: 17, src: src6, dst: dst6,
				srcPort: 546, dstPort: 547, hasSrcPort: true, hasDstPort: true,
			},
		},
		{
			name:   "IPv6 ICMPv6",
			packet: vm.NewIPv6Packet(src6, dst6).WithICMP6(135, 0),
			expected: fields{
				version: vm.IPv6, protocol: 58, src: src6, dst: dst6,
				icmp6Type: 135, hasICMP6Type: true,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, fieldsOf(tc.packet))
		})
	}
}

// verifies the fragment offset of IPv4 and that an IPv6 packet is never a
// fragment.
//
// Any non-zero value of the thirteen bits is a fragment and the flag bits
// above them are kept.
func Test_Packet_Fragment(t *testing.T) {
	packet := vm.NewIPv4Packet(src4, dst4)
	require.False(t, packet.IsFragment())

	packet[6] = 0x40
	packet = packet.WithFragmentOffset(0x1abc)
	require.True(t, packet.IsFragment())
	require.Equal(t, byte(0x5a), packet[6])
	require.Equal(t, byte(0xbc), packet[7])

	packet = packet.WithFragmentOffset(0)
	require.False(t, packet.IsFragment())
	require.Equal(t, byte(0x40), packet[6])
	require.Equal(t, byte(0x00), packet[7])

	require.True(t, packet.WithFragmentOffset(1).IsFragment())
	require.False(t, vm.NewIPv6Packet(src6, dst6).IsFragment())
}

// verifies that a non-first fragment reports no ports, flags or ICMP type,
// its bytes after the IP header being payload, and the first one does.
//
// The builders edit the bytes in place, so every case builds its own
// packet.
func Test_Packet_FragmentHasNoTransport(t *testing.T) {
	tcp := func(offset uint16) vm.RawIPv4Packet {
		return vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 50000, 22).WithFragmentOffset(offset)
	}
	icmp := func(offset uint16) vm.RawIPv4Packet {
		return vm.NewIPv4Packet(src4, dst4).WithICMP(8, 0).WithFragmentOffset(offset)
	}
	_, ok := tcp(100).SourcePort()
	require.False(t, ok)
	_, ok = tcp(100).DestinationPort()
	require.False(t, ok)
	_, ok = tcp(100).TCPFlags()
	require.False(t, ok)
	_, ok = icmp(100).ICMPType()
	require.False(t, ok)

	port, ok := tcp(0).SourcePort()
	require.True(t, ok)
	require.Equal(t, uint16(50000), port)
	ty, ok := icmp(0).ICMPType()
	require.True(t, ok)
	require.Equal(t, uint8(8), ty)
}

// verifies that a buffer shorter than the fields read reports zero
// values and no presence, without panicking.
func Test_Packet_ShortBuffer(t *testing.T) {
	cases := []struct {
		name     string
		packet   vm.Packet
		expected fields
	}{
		{name: "empty IPv4", packet: vm.RawIPv4Packet(nil), expected: fields{}},
		{name: "one byte of IPv4", packet: vm.RawIPv4Packet{0x45}, expected: fields{version: vm.IPv4}},
		{name: "neither version", packet: vm.RawIPv4Packet{0x50}, expected: fields{}},
		{
			name:     "IPv4 header only",
			packet:   vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 1, 2)[:20],
			expected: fields{version: vm.IPv4, protocol: 6, src: src4, dst: dst4},
		},
		{
			name:   "IPv4 TCP cut before the flags",
			packet: vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 1, 2)[:33],
			expected: fields{
				version: vm.IPv4, protocol: 6, src: src4, dst: dst4,
				srcPort: 1, dstPort: 2, hasSrcPort: true, hasDstPort: true,
			},
		},
		{name: "empty IPv6", packet: vm.RawIPv6Packet(nil), expected: fields{}},
		{name: "one byte of IPv6", packet: vm.RawIPv6Packet{0x60}, expected: fields{version: vm.IPv6}},
		{
			name:     "IPv6 header only",
			packet:   vm.NewIPv6Packet(src6, dst6).WithICMP6(128, 0)[:40],
			expected: fields{version: vm.IPv6, protocol: 58, src: src6, dst: dst6},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				require.Equal(t, tc.expected, fieldsOf(tc.packet))
			})
		})
	}
}

// verifies that the builders refuse an address of the other family.
func Test_Packet_WrongFamily(t *testing.T) {
	require.Panics(t, func() { vm.NewIPv4Packet(src6, dst4) })
	require.Panics(t, func() { vm.NewIPv4Packet(src4, dst6) })
	require.Panics(t, func() { vm.NewIPv6Packet(src4, dst6) })
	require.Panics(t, func() { vm.NewIPv6Packet(src6, dst4) })
}

// verifies that the zero context is an incoming packet on no interface
// with no local addresses.
func Test_Context_Zero(t *testing.T) {
	ctx := &vm.Context{}
	require.Equal(t, vm.In, ctx.Direction)
	require.Empty(t, ctx.IfName)
	require.Empty(t, ctx.LocalAddrs)
	require.NotEqual(t, vm.In, vm.Out)
}
