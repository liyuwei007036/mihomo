package sing_tun

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	tun "github.com/metacubex/sing-tun"
)

const (
	ttlTrackerEntryTTL  = 30 * time.Second
	ttlTrackerMaxFlows  = 8192
	ttlTrackerMaxHosts  = 1024
	windowsTTLMin       = 65
	windowsTTLMax       = 128
	linuxRelayTTLMin    = 129
	linuxRelayTTLMax    = 192
	appleRelayTTLMin    = 193
	ipv4MinHeaderLength = 20
	ipv6HeaderLength    = 40
	protoTCP            = 6
	protoUDP            = 17
)

type ttlFlowKey struct {
	proto   uint8
	srcIP   netip.Addr
	srcPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

type ttlRecord struct {
	relayTTL uint8
	seenAt   time.Time
}

// ttlTracker records the originating OS class from raw L3/L4 headers arriving
// on the TUN interface before the stack (system / mixed / gvisor) terminates
// them in the kernel:
//   - Windows hosts emit initial TTL 128 (65..128) -> relayTTL = 128
//   - Apple macOS/iOS hosts emit TTL 64 + XNU TCP SYN options [2,1,3,1,1,8]
//     (or upstream relayed TTL >= 129) -> relayTTL = 255
//   - Linux/Android hosts emit TTL 64 + Linux TCP options -> relayTTL = 0
type ttlTracker struct {
	mu          sync.RWMutex
	flows       map[ttlFlowKey]ttlRecord
	hosts       map[netip.Addr]ttlRecord
	lastCleanup time.Time
}

func newTTLTracker() *ttlTracker {
	return &ttlTracker{
		flows:       make(map[ttlFlowKey]ttlRecord, 256),
		hosts:       make(map[netip.Addr]ttlRecord, 64),
		lastCleanup: time.Now(),
	}
}

// isAppleTCPSYNOptions reports whether a TCP header carries the characteristic
// Apple XNU (macOS / iOS / iPadOS) SYN option prefix:
// MSS(2), NOP(1), WS(3), NOP(1), NOP(1), TS(8) [, SACK_PERM(4), EOL(0), EOL(0)].
func isAppleTCPSYNOptions(tcpHeader []byte) bool {
	if len(tcpHeader) < 20 {
		return false
	}
	dataOffset := int(tcpHeader[12]>>4) * 4
	if dataOffset <= 20 {
		return false
	}
	if dataOffset > len(tcpHeader) {
		dataOffset = len(tcpHeader)
	}
	opts := tcpHeader[20:dataOffset]
	want := [6]byte{2, 1, 3, 1, 1, 8}
	matched := 0
	for i := 0; i < len(opts) && matched < len(want); {
		kind := opts[i]
		if kind == 0 || kind != want[matched] {
			return false
		}
		matched++
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			return false
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return false
		}
		i += optLen
	}
	return matched == len(want)
}

func classifyPacketRelayTTL(ttl uint8, proto uint8, l4 []byte) uint8 {
	if ttl >= windowsTTLMin && ttl <= windowsTTLMax {
		return dialer.WindowsInitialTTL
	}
	if ttl >= appleRelayTTLMin {
		return dialer.AppleRelayTTL
	}
	if ttl >= linuxRelayTTLMin && ttl <= linuxRelayTTLMax {
		return dialer.LinuxRelayTTL
	}
	if proto == protoTCP {
		if isAppleTCPSYNOptions(l4) {
			return dialer.AppleRelayTTL
		}
		return dialer.LinuxRelayTTL
	}
	return 0
}

func (t *ttlTracker) observePacket(packet []byte) {
	if len(packet) < ipv4MinHeaderLength {
		return
	}
	version := packet[0] >> 4
	var (
		ttl      uint8
		proto    uint8
		srcIP    netip.Addr
		dstIP    netip.Addr
		l4Offset int
	)
	switch version {
	case 4:
		ihl := int(packet[0]&0x0f) * 4
		if ihl < ipv4MinHeaderLength || len(packet) < ihl {
			return
		}
		ttl = packet[8]
		proto = packet[9]
		srcIP = netip.AddrFrom4([4]byte(packet[12:16]))
		dstIP = netip.AddrFrom4([4]byte(packet[16:20]))
		l4Offset = ihl
	case 6:
		if len(packet) < ipv6HeaderLength {
			return
		}
		proto = packet[6]
		ttl = packet[7]
		srcIP = netip.AddrFrom16([16]byte(packet[8:24])).Unmap()
		dstIP = netip.AddrFrom16([16]byte(packet[24:40])).Unmap()
		l4Offset = ipv6HeaderLength
	default:
		return
	}
	if proto != protoTCP && proto != protoUDP {
		return
	}
	// Performance fast-path: for TCP, only pure SYN packets (SYN=1, ACK=0) open
	// new connections; skip 99.99% of established data/ACK packets with zero locks.
	if proto == protoTCP && len(packet) >= l4Offset+14 {
		if (packet[l4Offset+13] & 0x12) != 0x02 {
			return
		}
	}
	relayTTL := classifyPacketRelayTTL(ttl, proto, packet[l4Offset:])
	now := time.Now()

	var (
		hasFlow bool
		key     ttlFlowKey
	)
	if len(packet) >= l4Offset+4 {
		key = ttlFlowKey{
			proto:   proto,
			srcIP:   srcIP,
			srcPort: binary.BigEndian.Uint16(packet[l4Offset : l4Offset+2]),
			dstIP:   dstIP,
			dstPort: binary.BigEndian.Uint16(packet[l4Offset+2 : l4Offset+4]),
		}
		hasFlow = true
	}

	// Fast path: inherit host-level Apple/Linux classification for UDP packets
	// from an already-classified host (UDP carries TTL=64 with no TCP options),
	// and skip acquiring the write lock when flow/host state is already fresh.
	t.mu.RLock()
	if proto == protoUDP && relayTTL == 0 {
		if hrec, ok := t.hosts[srcIP]; ok && (hrec.relayTTL == dialer.AppleRelayTTL || hrec.relayTTL == dialer.LinuxRelayTTL) && now.Sub(hrec.seenAt) <= ttlTrackerEntryTTL {
			relayTTL = hrec.relayTTL
		}
	}
	if hasFlow {
		if rec, ok := t.flows[key]; ok && rec.relayTTL == relayTTL && now.Sub(rec.seenAt) < 5*time.Second {
			if hrec, hok := t.hosts[srcIP]; hok && hrec.relayTTL == relayTTL && now.Sub(hrec.seenAt) < 5*time.Second {
				t.mu.RUnlock()
				return
			}
		}
	} else if rec, ok := t.hosts[srcIP]; ok && rec.relayTTL == relayTTL && now.Sub(rec.seenAt) < 5*time.Second {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()

	t.mu.Lock()
	if proto == protoUDP && relayTTL == 0 {
		if hrec, ok := t.hosts[srcIP]; ok && (hrec.relayTTL == dialer.AppleRelayTTL || hrec.relayTTL == dialer.LinuxRelayTTL) && now.Sub(hrec.seenAt) <= ttlTrackerEntryTTL {
			relayTTL = hrec.relayTTL
		}
	}
	if hasFlow {
		t.flows[key] = ttlRecord{relayTTL: relayTTL, seenAt: now}
	}
	t.hosts[srcIP] = ttlRecord{relayTTL: relayTTL, seenAt: now}
	if len(t.flows) > ttlTrackerMaxFlows || len(t.hosts) > ttlTrackerMaxHosts || now.Sub(t.lastCleanup) > ttlTrackerEntryTTL {
		t.cleanupLocked(now)
	}
	t.mu.Unlock()
}

func (t *ttlTracker) observeReadBuffer(raw []byte) {
	if len(raw) <= tun.PacketOffset {
		return
	}
	t.observePacket(raw[tun.PacketOffset:])
}

func (t *ttlTracker) cleanupLocked(now time.Time) {
	t.lastCleanup = now
	for _, maxAge := range []time.Duration{ttlTrackerEntryTTL, 5 * time.Second, time.Second} {
		for k, rec := range t.flows {
			if now.Sub(rec.seenAt) > maxAge {
				delete(t.flows, k)
			}
		}
		if len(t.flows) <= ttlTrackerMaxFlows*3/4 {
			break
		}
	}
	if len(t.flows) > ttlTrackerMaxFlows {
		drop := len(t.flows) - ttlTrackerMaxFlows*3/4
		for k := range t.flows {
			delete(t.flows, k)
			drop--
			if drop <= 0 {
				break
			}
		}
	}
	for k, rec := range t.hosts {
		if now.Sub(rec.seenAt) > ttlTrackerEntryTTL {
			delete(t.hosts, k)
		}
	}
	if len(t.hosts) > ttlTrackerMaxHosts {
		drop := len(t.hosts) - ttlTrackerMaxHosts*3/4
		for k := range t.hosts {
			delete(t.hosts, k)
			drop--
			if drop <= 0 {
				break
			}
		}
	}
}

func (t *ttlTracker) relayTTL(metadata *C.Metadata) uint8 {
	if runtime.GOOS == "windows" {
		return dialer.WindowsInitialTTL
	}
	if runtime.GOOS == "darwin" {
		return dialer.AppleRelayTTL
	}
	if metadata == nil {
		return 0
	}
	if metadata.DSCP == 1 {
		return dialer.WindowsInitialTTL
	}
	srcIP := metadata.SrcIP.Unmap()
	if !srcIP.IsValid() {
		return 0
	}
	var proto uint8
	switch metadata.NetWork {
	case C.TCP:
		proto = protoTCP
	case C.UDP:
		proto = protoUDP
	}
	now := time.Now()
	t.mu.RLock()
	defer t.mu.RUnlock()

	if proto != 0 && metadata.DstIP.IsValid() {
		key := ttlFlowKey{
			proto:   proto,
			srcIP:   srcIP,
			srcPort: metadata.SrcPort,
			dstIP:   metadata.DstIP.Unmap(),
			dstPort: metadata.DstPort,
		}
		if rec, ok := t.flows[key]; ok && now.Sub(rec.seenAt) <= ttlTrackerEntryTTL {
			return rec.relayTTL
		}
	}
	if rec, ok := t.hosts[srcIP]; ok && now.Sub(rec.seenAt) <= ttlTrackerEntryTTL {
		return rec.relayTTL
	}
	return 0
}

func (t *ttlTracker) Addition() inbound.Addition {
	return func(metadata *C.Metadata) {
		if ttl := t.relayTTL(metadata); ttl > 0 {
			metadata.InitialTTL = ttl
		}
	}
}

type ttlTrackingTun struct {
	tun.Tun
	tracker *ttlTracker
}

func (w *ttlTrackingTun) Read(p []byte) (int, error) {
	n, err := w.Tun.Read(p)
	if n > 0 {
		w.tracker.observeReadBuffer(p[:n])
	}
	return n, err
}

type ttlTrackingLinuxTun struct {
	tun.LinuxTUN
	tracker *ttlTracker
}

func (w *ttlTrackingLinuxTun) Read(p []byte) (int, error) {
	n, err := w.LinuxTUN.Read(p)
	if n > 0 {
		w.tracker.observeReadBuffer(p[:n])
	}
	return n, err
}

func (w *ttlTrackingLinuxTun) BatchRead(buffers [][]byte, offset int, readN []int) (int, error) {
	n, err := w.LinuxTUN.BatchRead(buffers, offset, readN)
	for i := 0; i < n; i++ {
		if readN[i] > 0 && offset+readN[i] <= len(buffers[i]) {
			w.tracker.observePacket(buffers[i][offset : offset+readN[i]])
		}
	}
	return n, err
}
