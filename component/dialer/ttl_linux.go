//go:build linux

package dialer

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindTTLToDialer(ttl int, dialer *net.Dialer) {
	if ttl <= 0 || ttl > 255 {
		return
	}
	addControlToDialer(dialer, bindTTLToControl(ttl))
}

func bindTTLToListenConfig(ttl int, lc *net.ListenConfig) {
	if ttl <= 0 || ttl > 255 {
		return
	}
	addControlToListenConfig(lc, bindTTLToControl(ttl))
}

func bindTTLToControl(ttl int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return setRawConnInitialTTL(c, network, ttl)
	}
}

func setRawConnInitialTTL(c syscall.RawConn, network string, ttl int) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		// On Linux, dual-stack AF_INET6 sockets (e.g. ListenPacket("udp", ":0"))
		// use IP_TTL for IPv4-mapped destinations and IPV6_UNICAST_HOPS for IPv6
		// destinations. Apply both where supported and ignore ENOPROTOOPT when
		// at least one succeeds.
		switch network {
		case "tcp4", "udp4":
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
		case "tcp6", "udp6":
			err6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
			err4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
			if err6 != nil && err4 != nil {
				sockErr = err6
			}
		default:
			err4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
			err6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
			if err4 != nil && err6 != nil {
				sockErr = err4
			}
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
