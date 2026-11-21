package sing_tun

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	tun "github.com/metacubex/sing-tun"
)

const (
	ttlTrackerEntryTTL  = 30 * time.Second
	ttlTrackerMaxFlows  = 8192
	ttlTrackerMaxHosts  = 1024
	windowsTTLMin       = 65
	windowsTTLMax       = 128
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
	isWindows bool
	seenAt    time.Time
}

// ttlTracker records the raw IPv4 TTL / IPv6 Hop Limit of packets arriving on
// the TUN interface before the stack (system / mixed / gvisor) rewrites or
// terminates them in the kernel. LAN Windows hosts emit initial TTL 128
// (65..128 after optional intermediate hops), whereas Linux/macOS/iOS/Android
// emit initial TTL <= 64.
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

func isWindowsInitialTTL(ttl uint8) bool {
	return ttl >= windowsTTLMin && ttl <= windowsTTLMax
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
	isWin := isWindowsInitialTTL(ttl)
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

	// Fast path: skip acquiring the write lock for already-tracked flows seen
	// within the last 5 seconds with the same OS classification.
	t.mu.RLock()
	if hasFlow {
		if rec, ok := t.flows[key]; ok && rec.isWindows == isWin && now.Sub(rec.seenAt) < 5*time.Second {
			t.mu.RUnlock()
			return
		}
	} else if rec, ok := t.hosts[srcIP]; ok && rec.isWindows == isWin && now.Sub(rec.seenAt) < 5*time.Second {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()

	t.mu.Lock()
	if hasFlow {
		t.flows[key] = ttlRecord{isWindows: isWin, seenAt: now}
	}
	t.hosts[srcIP] = ttlRecord{isWindows: isWin, seenAt: now}
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

func (t *ttlTracker) isWindows(metadata *C.Metadata) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	if metadata == nil {
		return false
	}
	if metadata.DSCP == 1 {
		return true
	}
	srcIP := metadata.SrcIP.Unmap()
	if !srcIP.IsValid() {
		return false
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
			return rec.isWindows
		}
	}
	if rec, ok := t.hosts[srcIP]; ok && now.Sub(rec.seenAt) <= ttlTrackerEntryTTL {
		return rec.isWindows
	}
	return false
}

func (t *ttlTracker) Addition() inbound.Addition {
	return func(metadata *C.Metadata) {
		if t.isWindows(metadata) {
			metadata.IsWindows = true
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
