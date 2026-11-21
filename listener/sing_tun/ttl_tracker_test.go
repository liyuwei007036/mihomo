package sing_tun

import (
	"encoding/binary"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func buildIPv4Packet(ttl, proto uint8, srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 24)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[8] = ttl
	pkt[9] = proto
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}

func TestTTLTrackerDistinguishesWindowsAndNonWindows(t *testing.T) {
	tracker := newTTLTracker()

	winIP := [4]byte{192, 168, 1, 10}
	macIP := [4]byte{192, 168, 1, 20}
	dstIP := [4]byte{1, 1, 1, 1}

	// Windows host with initial TTL 128 (or 127 after 1 LAN hop)
	tracker.observePacket(buildIPv4Packet(128, protoTCP, winIP, dstIP, 50001, 443))
	tracker.observePacket(buildIPv4Packet(127, protoUDP, winIP, dstIP, 50002, 443))
	// macOS/iOS/Android/Linux host with initial TTL 64
	tracker.observePacket(buildIPv4Packet(64, protoTCP, macIP, dstIP, 60001, 443))

	winMeta := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.AddrFrom4(winIP),
		SrcPort: 50001,
		DstIP:   netip.AddrFrom4(dstIP),
		DstPort: 443,
	}
	tracker.Addition()(winMeta)
	if !winMeta.IsWindows {
		t.Fatalf("expected Windows TCP flow (TTL 128) to set IsWindows=true")
	}

	winUDPMeta := &C.Metadata{
		NetWork: C.UDP,
		SrcIP:   netip.AddrFrom4(winIP),
		SrcPort: 50002,
		DstIP:   netip.AddrFrom4(dstIP),
		DstPort: 443,
	}
	tracker.Addition()(winUDPMeta)
	if !winUDPMeta.IsWindows {
		t.Fatalf("expected Windows UDP flow (TTL 127) to set IsWindows=true")
	}

	macMeta := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.AddrFrom4(macIP),
		SrcPort: 60001,
		DstIP:   netip.AddrFrom4(dstIP),
		DstPort: 443,
	}
	tracker.Addition()(macMeta)
	if macMeta.IsWindows {
		t.Fatalf("expected non-Windows TCP flow (TTL 64) to keep IsWindows=false")
	}
}
