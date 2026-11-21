package sing_tun

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

func buildIPv4TCPSYN(ttl uint8, srcIP, dstIP [4]byte, srcPort, dstPort uint16, opts []byte) []byte {
	tcpLen := 20 + len(opts)
	pkt := make([]byte, 20+tcpLen)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[8] = ttl
	pkt[9] = protoTCP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = byte((tcpLen / 4) << 4)
	pkt[33] = 0x02 // pure SYN
	copy(pkt[40:], opts)
	return pkt
}

func buildIPv4UDPPacket(ttl uint8, srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[8] = ttl
	pkt[9] = protoUDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

func buildIPv6TCPSYN(hopLimit uint8, srcIP, dstIP [16]byte, srcPort, dstPort uint16, opts []byte) []byte {
	tcpLen := 20 + len(opts)
	pkt := make([]byte, 40+tcpLen)
	pkt[0] = 0x60
	pkt[6] = protoTCP
	pkt[7] = hopLimit
	copy(pkt[8:24], srcIP[:])
	copy(pkt[24:40], dstIP[:])
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	pkt[52] = byte((tcpLen / 4) << 4)
	pkt[53] = 0x02 // pure SYN
	copy(pkt[60:], opts)
	return pkt
}

func TestTTLTrackerDistinguishesWindowsAppleAndLinux(t *testing.T) {
	tracker := newTTLTracker()

	winIP := [4]byte{192, 168, 1, 10}
	appleIP := [4]byte{192, 168, 1, 20}
	linuxIP := [4]byte{192, 168, 1, 30}
	dstIP := [4]byte{1, 1, 1, 1}

	winOpts := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		1,       // NOP
		3, 3, 8, // WS 8
		1, 1, // NOP, NOP
		4, 2, // SACK_PERM
	}
	appleOpts := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		1,       // NOP
		3, 3, 6, // WS 6
		1, 1, // NOP, NOP
		8, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, // TS
		4, 2, // SACK_PERM
		0, 0, // EOL, EOL
	}
	linuxOpts := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		4, 2, // SACK_PERM
		8, 10, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, // TS
		1,       // NOP
		3, 3, 7, // WS 7
	}

	// Windows host: TTL 128 TCP + TTL 127 UDP
	tracker.observePacket(buildIPv4TCPSYN(128, winIP, dstIP, 50001, 443, winOpts))
	tracker.observePacket(buildIPv4UDPPacket(127, winIP, dstIP, 50002, 443))

	// Apple macOS/iOS host: TTL 64 TCP SYN with XNU options, followed by TTL 64 UDP
	tracker.observePacket(buildIPv4TCPSYN(64, appleIP, dstIP, 60001, 443, appleOpts))
	tracker.observePacket(buildIPv4UDPPacket(64, appleIP, dstIP, 60002, 443))

	// Linux/Android host: TTL 64 TCP SYN with Linux options, followed by TTL 64 UDP
	tracker.observePacket(buildIPv4TCPSYN(64, linuxIP, dstIP, 61001, 443, linuxOpts))
	tracker.observePacket(buildIPv4UDPPacket(64, linuxIP, dstIP, 61002, 443))

	// IPv6 Apple macOS/iOS host (84 bytes total: 40B IPv6 + 44B TCP)
	appleV6 := [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20}
	dstV6 := [16]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	tracker.observePacket(buildIPv6TCPSYN(64, appleV6, dstV6, 62001, 443, appleOpts))

	check := func(name string, meta *C.Metadata, want uint8) {
		t.Helper()
		tracker.Addition()(meta)
		if meta.InitialTTL != want {
			t.Fatalf("%s: got InitialTTL=%d, want %d", name, meta.InitialTTL, want)
		}
	}

	check("Windows TCP", &C.Metadata{
		NetWork: C.TCP, SrcIP: netip.AddrFrom4(winIP), SrcPort: 50001, DstIP: netip.AddrFrom4(dstIP), DstPort: 443,
	}, dialer.WindowsInitialTTL)

	check("Windows UDP", &C.Metadata{
		NetWork: C.UDP, SrcIP: netip.AddrFrom4(winIP), SrcPort: 50002, DstIP: netip.AddrFrom4(dstIP), DstPort: 443,
	}, dialer.WindowsInitialTTL)

	check("Apple IPv4 TCP", &C.Metadata{
		NetWork: C.TCP, SrcIP: netip.AddrFrom4(appleIP), SrcPort: 60001, DstIP: netip.AddrFrom4(dstIP), DstPort: 443,
	}, dialer.AppleRelayTTL)

	check("Apple IPv4 UDP inherits host profile", &C.Metadata{
		NetWork: C.UDP, SrcIP: netip.AddrFrom4(appleIP), SrcPort: 60002, DstIP: netip.AddrFrom4(dstIP), DstPort: 443,
	}, dialer.AppleRelayTTL)

	check("Apple IPv6 TCP", &C.Metadata{
		NetWork: C.TCP, SrcIP: netip.AddrFrom16(appleV6), SrcPort: 62001, DstIP: netip.AddrFrom16(dstV6), DstPort: 443,
	}, dialer.AppleRelayTTL)

	check("Linux/Android TCP", &C.Metadata{
		NetWork: C.TCP, SrcIP: netip.AddrFrom4(linuxIP), SrcPort: 61001, DstIP: netip.AddrFrom4(dstIP), DstPort: 443,
	}, dialer.LinuxRelayTTL)

	check("Linux/Android UDP inherits host profile", &C.Metadata{
		NetWork: C.UDP, SrcIP: netip.AddrFrom4(linuxIP), SrcPort: 61002, DstIP: netip.AddrFrom4(dstIP), DstPort: 443,
	}, dialer.LinuxRelayTTL)
}
