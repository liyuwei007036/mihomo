//go:build with_gvisor

package sing_tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	tun "github.com/metacubex/sing-tun"
)

// ttlTrackingGVisorEndpoint intercepts packets delivered from gVisor's fdbased
// link endpoint so gVisor stack mode also records raw IPv4 TTL / IPv6 Hop Limit.
type ttlTrackingGVisorEndpoint struct {
	stack.LinkEndpoint
	tracker *ttlTracker
}

type ttlTrackingNetworkDispatcher struct {
	stack.NetworkDispatcher
	tracker *ttlTracker
}

func (d *ttlTrackingNetworkDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if pkt != nil {
		var hdrBuf [64]byte
		copied := 0
		for _, slice := range pkt.AsSlices() {
			if copied >= len(hdrBuf) {
				break
			}
			copied += copy(hdrBuf[copied:], slice)
		}
		if copied >= ipv4MinHeaderLength {
			d.tracker.observePacket(hdrBuf[:copied])
		}
	}
	d.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (e *ttlTrackingGVisorEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		e.LinkEndpoint.Attach(nil)
		return
	}
	e.LinkEndpoint.Attach(&ttlTrackingNetworkDispatcher{
		NetworkDispatcher: dispatcher,
		tracker:           e.tracker,
	})
}

// ttlTrackingLinuxGVisorTun implements BOTH tun.LinuxTUN and tun.GVisorTun so
// sing-tun's system, mixed, and gvisor stacks all succeed their interface assertions.
type ttlTrackingLinuxGVisorTun struct {
	tun.LinuxTUN
	gTun    tun.GVisorTun
	tracker *ttlTracker
}

func (w *ttlTrackingLinuxGVisorTun) Read(p []byte) (int, error) {
	n, err := w.LinuxTUN.Read(p)
	if n > 0 {
		w.tracker.observeReadBuffer(p[:n])
	}
	return n, err
}

func (w *ttlTrackingLinuxGVisorTun) BatchRead(buffers [][]byte, offset int, readN []int) (int, error) {
	n, err := w.LinuxTUN.BatchRead(buffers, offset, readN)
	for i := 0; i < n; i++ {
		if readN[i] > 0 && offset+readN[i] <= len(buffers[i]) {
			w.tracker.observePacket(buffers[i][offset : offset+readN[i]])
		}
	}
	return n, err
}

func (w *ttlTrackingLinuxGVisorTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	return w.gTun.WritePacket(pkt)
}

func (w *ttlTrackingLinuxGVisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep, nicOpts, err := w.gTun.NewEndpoint()
	if err != nil {
		return nil, nicOpts, err
	}
	return &ttlTrackingGVisorEndpoint{LinkEndpoint: ep, tracker: w.tracker}, nicOpts, nil
}

// ttlTrackingGVisorTun handles non-Linux platforms (e.g. macOS/Windows) that
// implement tun.GVisorTun without tun.LinuxTUN.
type ttlTrackingGVisorTun struct {
	tun.GVisorTun
	tracker *ttlTracker
}

func (w *ttlTrackingGVisorTun) Read(p []byte) (int, error) {
	n, err := w.GVisorTun.Read(p)
	if n > 0 {
		w.tracker.observeReadBuffer(p[:n])
	}
	return n, err
}

func (w *ttlTrackingGVisorTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep, nicOpts, err := w.GVisorTun.NewEndpoint()
	if err != nil {
		return nil, nicOpts, err
	}
	return &ttlTrackingGVisorEndpoint{LinkEndpoint: ep, tracker: w.tracker}, nicOpts, nil
}

func wrapTunWithTTLTracker(tunIf tun.Tun, tracker *ttlTracker) tun.Tun {
	if tunIf == nil || tracker == nil {
		return tunIf
	}
	linuxTun, isLinux := tunIf.(tun.LinuxTUN)
	gTun, isGVisor := tunIf.(tun.GVisorTun)
	switch {
	case isLinux && isGVisor:
		return &ttlTrackingLinuxGVisorTun{LinuxTUN: linuxTun, gTun: gTun, tracker: tracker}
	case isLinux:
		return &ttlTrackingLinuxTun{LinuxTUN: linuxTun, tracker: tracker}
	case isGVisor:
		return &ttlTrackingGVisorTun{GVisorTun: gTun, tracker: tracker}
	default:
		return &ttlTrackingTun{Tun: tunIf, tracker: tracker}
	}
}
