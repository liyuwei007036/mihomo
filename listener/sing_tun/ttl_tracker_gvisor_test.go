//go:build with_gvisor

package sing_tun

import (
	"testing"

	tun "github.com/metacubex/sing-tun"
)

func TestTTLTrackingLinuxGVisorTunPreservesBothInterfaces(t *testing.T) {
	var wrapped any = &ttlTrackingLinuxGVisorTun{}
	if _, ok := wrapped.(tun.LinuxTUN); !ok {
		t.Fatalf("ttlTrackingLinuxGVisorTun must implement tun.LinuxTUN")
	}
	if _, ok := wrapped.(tun.GVisorTun); !ok {
		t.Fatalf("ttlTrackingLinuxGVisorTun must implement tun.GVisorTun (required by mixed and gvisor stacks)")
	}
}
