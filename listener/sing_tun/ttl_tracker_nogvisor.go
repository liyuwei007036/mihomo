//go:build !with_gvisor

package sing_tun

import tun "github.com/metacubex/sing-tun"

func wrapTunWithTTLTracker(tunIf tun.Tun, tracker *ttlTracker) tun.Tun {
	if tunIf == nil || tracker == nil {
		return tunIf
	}
	if linuxTun, ok := tunIf.(tun.LinuxTUN); ok {
		return &ttlTrackingLinuxTun{LinuxTUN: linuxTun, tracker: tracker}
	}
	return &ttlTrackingTun{Tun: tunIf, tracker: tracker}
}
