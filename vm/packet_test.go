package vm_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yanet-platform/ipfw-go"
	"github.com/yanet-platform/ipfw-go/vm"
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
	version                vm.IPVersion
	protocol               uint8
	src, dst               netip.Addr
	fragment               bool
	srcPort, dstPort       uint16
	hasSrcPort, hasDstPort bool
	flags                  ipfw.TCPFlag
	hasFlags               bool
	icmpType               uint8
	hasICMPType            bool
}

// fieldsOf reads every accessor of a packet.
func fieldsOf(packet vm.Packet) fields {
	var f fields
	f.version, f.protocol = packet.Version(), packet.Protocol()
	f.src, f.dst = packet.SourceAddr(), packet.DestinationAddr()
	f.fragment = packet.IsFragment()
	f.srcPort, f.hasSrcPort = packet.SourcePort()
	f.dstPort, f.hasDstPort = packet.DestinationPort()
	f.flags, f.hasFlags = packet.TCPFlags()
	f.icmpType, f.hasICMPType = packet.ICMPType()
	return f
}

// transport is the fields of a transport header holding the ports, the
// flags and the type byte, the type byte being the high byte of the source
// port since every field is read at the same header whatever the protocol.
func transport(version vm.IPVersion, protocol uint8, src, dst netip.Addr, sport, dport uint16) fields {
	return fields{
		version: version, protocol: protocol, src: src, dst: dst,
		srcPort: sport, dstPort: dport, hasSrcPort: true, hasDstPort: true,
		hasFlags: true, icmpType: uint8(sport >> 8), hasICMPType: true,
	}
}

// verifies that every builder combination is read back field by field, the
// transport fields read at the header after the IP header whatever the
// protocol, as the VM asks for them only where they mean something.
func Test_Packet_Table(t *testing.T) {
	tcp4 := transport(vm.IPv4, 6, src4, dst4, 40000, 22)
	tcp4.flags = ipfw.TCPSyn | ipfw.TCPAck
	tcp6 := transport(vm.IPv6, 6, src6, dst6, 1, 65535)
	tcp6.flags = ipfw.TCPRst
	icmp4 := transport(vm.IPv4, 1, src4, dst4, 8<<8, 0)
	icmp6 := transport(vm.IPv6, 58, src6, dst6, 135<<8, 0)
	cases := []struct {
		name     string
		packet   vm.Packet
		expected fields
	}{
		{
			name:     "IPv4 without transport",
			packet:   vm.NewIPv4Packet(src4, dst4),
			expected: transport(vm.IPv4, 0, src4, dst4, 0, 0),
		},
		{
			name:     "IPv4 TCP",
			packet:   vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn|ipfw.TCPAck, 40000, 22),
			expected: tcp4,
		},
		{
			name:     "IPv4 UDP",
			packet:   vm.NewIPv4Packet(src4, dst4).WithUDP(53, 65535),
			expected: transport(vm.IPv4, 17, src4, dst4, 53, 65535),
		},
		{
			name:     "IPv4 ICMP",
			packet:   vm.NewIPv4Packet(src4, dst4).WithICMP(8, 0),
			expected: icmp4,
		},
		{
			name:     "IPv6 without transport",
			packet:   vm.NewIPv6Packet(src6, dst6),
			expected: transport(vm.IPv6, 59, src6, dst6, 0, 0),
		},
		{
			name:     "IPv6 TCP",
			packet:   vm.NewIPv6Packet(src6, dst6).WithTCP(ipfw.TCPRst, 1, 65535),
			expected: tcp6,
		},
		{
			name:     "IPv6 UDP",
			packet:   vm.NewIPv6Packet(src6, dst6).WithUDP(546, 547),
			expected: transport(vm.IPv6, 17, src6, dst6, 546, 547),
		},
		{
			name:     "IPv6 ICMPv6",
			packet:   vm.NewIPv6Packet(src6, dst6).WithICMP6(135, 0),
			expected: icmp6,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, fieldsOf(tc.packet))
		})
	}
}

// verifies that the transport header of IPv4 starts where the IHL says, past
// any IP options, and that an IHL shorter than the fixed header leaves no
// transport header at all.
func Test_Packet_IPv4HeaderLength(t *testing.T) {
	packet := vm.NewIPv4Packet(src4, dst4)
	packet[0] = 4<<4 | 6
	packet = packet.WithTCP(ipfw.TCPSyn, 40000, 22)
	require.Equal(t, uint16(40000), binary.BigEndian.Uint16(packet[24:26]))
	expected := transport(vm.IPv4, 6, src4, dst4, 40000, 22)
	expected.flags = ipfw.TCPSyn
	require.Equal(t, expected, fieldsOf(packet))

	packet[0] = 4<<4 | 4
	require.Equal(t, fields{version: vm.IPv4, protocol: 6, src: src4, dst: dst4}, fieldsOf(packet))
}

// ipv6 is an IPv6 packet whose fixed header names next and whose extension
// headers and upper layer follow as given.
func ipv6(next uint8, rest ...[]byte) vm.RawIPv6Packet {
	packet := vm.NewIPv6Packet(src6, dst6)[:40]
	packet[6] = next
	for _, part := range rest {
		packet = append(packet, part...)
	}
	return packet
}

// verifies that the extension headers of IPv6 are followed up to the upper
// layer as ipfw_chk follows them, that a non-first fragment stops there with
// the protocol its fragment header names, that ESP and no next header stop
// the walk, and that a truncated chain leaves no transport header.
func Test_Packet_IPv6ExtensionHeaders(t *testing.T) {
	tcp := []byte{0x9c, 0x40, 0x00, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, byte(ipfw.TCPSyn)}
	// Every upper layer is fourteen bytes long, so that each field is there.
	udp := []byte{0x00, 0x35, 0x00, 0x35, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}
	icmp := []byte{128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	tcpFields := transport(vm.IPv6, 6, src6, dst6, 40000, 22)
	tcpFields.flags = ipfw.TCPSyn
	cases := []struct {
		name     string
		packet   vm.RawIPv6Packet
		expected fields
	}{
		{
			name:     "hop-by-hop options",
			packet:   ipv6(0, []byte{6, 0, 0, 0, 0, 0, 0, 0}, tcp),
			expected: tcpFields,
		},
		{
			name:     "routing header of sixteen bytes",
			packet:   ipv6(43, []byte{17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, udp),
			expected: transport(vm.IPv6, 17, src6, dst6, 53, 53),
		},
		{
			name:     "destination options before ICMPv6",
			packet:   ipv6(60, []byte{58, 0, 0, 0, 0, 0, 0, 0}, icmp),
			expected: transport(vm.IPv6, 58, src6, dst6, 128<<8, 0),
		},
		{
			name:     "authentication header of twelve bytes",
			packet:   ipv6(51, []byte{6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, tcp),
			expected: tcpFields,
		},
		{
			name: "chain of every header",
			packet: ipv6(0,
				[]byte{60, 0, 0, 0, 0, 0, 0, 0},
				[]byte{43, 0, 0, 0, 0, 0, 0, 0},
				[]byte{44, 0, 0, 0, 0, 0, 0, 0},
				[]byte{51, 0, 0, 0, 0, 0, 0, 0},
				[]byte{6, 0, 0, 0, 0, 0, 0, 0},
				tcp),
			expected: tcpFields,
		},
		{
			name:     "first fragment",
			packet:   ipv6(44, []byte{6, 0, 0x00, 0x01, 0, 0, 0, 1}, tcp),
			expected: tcpFields,
		},
		{
			name:   "non-first fragment",
			packet: ipv6(44, []byte{6, 0, 0x03, 0x20, 0, 0, 0, 1}, tcp),
			expected: func() fields {
				f := tcpFields
				f.fragment = true
				return f
			}(),
		},
		{
			name:     "encapsulating security payload",
			packet:   ipv6(50, []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}),
			expected: transport(vm.IPv6, 50, src6, dst6, 0, 1),
		},
		{
			name:     "no next header",
			packet:   ipv6(59),
			expected: fields{version: vm.IPv6, protocol: 59, src: src6, dst: dst6},
		},
		{
			name:     "hop-by-hop options cut short",
			packet:   ipv6(0, []byte{6}),
			expected: fields{version: vm.IPv6, protocol: 0, src: src6, dst: dst6},
		},
		{
			name:     "hop-by-hop length past the end",
			packet:   ipv6(0, []byte{6, 4, 0, 0, 0, 0, 0, 0}, tcp),
			expected: fields{version: vm.IPv6, protocol: 6, src: src6, dst: dst6},
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

// verifies the fragment offset of both versions: the thirteen bits of the
// IPv4 header with the flag bits above them kept, and an IPv6 fragment header
// inserted once and then updated.
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

	whole := vm.NewIPv6Packet(src6, dst6).WithTCP(ipfw.TCPSyn, 40000, 22)
	require.False(t, whole.IsFragment())
	fragment := whole.WithFragmentOffset(100)
	require.True(t, fragment.IsFragment())
	require.Equal(t, uint8(6), fragment.Protocol())
	require.Len(t, fragment, len(whole)+8)
	first := fragment.WithFragmentOffset(0)
	require.False(t, first.IsFragment())
	require.Len(t, first, len(fragment))
	port, ok := first.DestinationPort()
	require.True(t, ok)
	require.Equal(t, uint16(22), port)
}

// verifies that a builder returns a copy, so that packets built from one
// base share no bytes, and that WithTCP sets the flags rather than adding
// them.
func Test_Packet_BuildersCopy(t *testing.T) {
	base := vm.NewIPv4Packet(src4, dst4)
	tcp := base.WithTCP(ipfw.TCPSyn, 40000, 22)
	udp := base.WithUDP(53, 53)
	require.Equal(t, uint8(0), base.Protocol())
	require.Equal(t, uint8(6), tcp.Protocol())
	require.Equal(t, uint8(17), udp.Protocol())

	flags, ok := tcp.WithTCP(ipfw.TCPAck, 40000, 22).TCPFlags()
	require.True(t, ok)
	require.Equal(t, ipfw.TCPAck, flags)
	flags, _ = tcp.TCPFlags()
	require.Equal(t, ipfw.TCPSyn, flags)
}

// verifies that a buffer shorter than the fields read reports zero values
// and no presence, without panicking.
func Test_Packet_ShortBuffer(t *testing.T) {
	cutBeforeFlags := transport(vm.IPv4, 6, src4, dst4, 1, 2)
	cutBeforeFlags.hasFlags = false
	cases := []struct {
		name     string
		packet   vm.Packet
		expected fields
	}{
		{name: "empty IPv4", packet: vm.RawIPv4Packet(nil), expected: fields{}},
		{name: "empty IPv6", packet: vm.RawIPv6Packet(nil), expected: fields{}},
		{name: "one byte of IPv4", packet: vm.RawIPv4Packet{0x45}, expected: fields{version: vm.IPv4}},
		{name: "one byte of IPv6", packet: vm.RawIPv6Packet{0x60}, expected: fields{version: vm.IPv6}},
		{name: "neither version", packet: vm.RawIPv4Packet{0x50}, expected: fields{}},
		{
			name:     "IPv4 header only",
			packet:   vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 1, 2)[:20],
			expected: fields{version: vm.IPv4, protocol: 6, src: src4, dst: dst4},
		},
		{
			name:     "IPv4 TCP cut before the flags",
			packet:   vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 1, 2)[:33],
			expected: cutBeforeFlags,
		},
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

// verifies that no bytes make a raw packet of either version panic, and that a transport field
// is present only when its bytes are.
func Fuzz_Packet(f *testing.F) {
	f.Add([]byte(vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 40000, 22)))
	f.Add([]byte(vm.NewIPv6Packet(src6, dst6).WithUDP(53, 53).WithFragmentOffset(100)))
	f.Add([]byte(ipv6(0, []byte{43, 0, 0, 0, 0, 0, 0, 0}, []byte{51, 0, 0, 0, 0, 0, 0, 0})))
	f.Add([]byte{0x46, 0, 0, 0, 0, 0, 0, 0, 0, 6})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, packet := range []vm.Packet{vm.RawIPv4Packet(data), vm.RawIPv6Packet(data)} {
			got := fieldsOf(packet)
			if got.hasFlags {
				require.True(t, got.hasSrcPort && got.hasDstPort && got.hasICMPType)
			}
			if got.hasSrcPort {
				require.True(t, got.hasICMPType)
			}
		}
	})
}

func Benchmark_Packet_Fields(b *testing.B) {
	cases := []struct {
		name   string
		packet vm.Packet
	}{
		{name: "IPv4", packet: vm.NewIPv4Packet(src4, dst4).WithTCP(ipfw.TCPSyn, 40000, 22)},
		{name: "IPv6", packet: vm.NewIPv6Packet(src6, dst6).WithTCP(ipfw.TCPSyn, 40000, 22)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				fieldsOf(tc.packet)
			}
		})
	}
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
