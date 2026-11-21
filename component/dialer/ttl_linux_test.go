//go:build linux

package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func getSocketIPv4TTL(t *testing.T, sc syscall.Conn) int {
	t.Helper()
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var ttl int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		ttl, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("GetsockoptInt(IP_TTL): %v", sockErr)
	}
	return ttl
}

func TestDialContextInitialTTL(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Default context keeps Linux default TTL (64).
	cDefault, err := DialContext(context.Background(), "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("default DialContext: %v", err)
	}
	defer cDefault.Close()
	if got := getSocketIPv4TTL(t, cDefault.(syscall.Conn)); got != 64 {
		t.Fatalf("default TCP TTL = %d, want 64", got)
	}

	// Windows context sets initial TTL to 128.
	ctxWin := WithInitialTTL(context.Background(), WindowsInitialTTL)
	cWin, err := DialContext(ctxWin, "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("win DialContext: %v", err)
	}
	defer cWin.Close()
	if got := getSocketIPv4TTL(t, cWin.(syscall.Conn)); got != 128 {
		t.Fatalf("win TCP TTL = %d, want 128", got)
	}
}

func TestListenPacketInitialTTL(t *testing.T) {
	ctxWin := WithInitialTTL(context.Background(), WindowsInitialTTL)
	pc, err := ListenPacket(ctxWin, "udp", ":0", netip.MustParseAddrPort("127.0.0.1:443"))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	if got := getSocketIPv4TTL(t, pc.(syscall.Conn)); got != 128 {
		t.Fatalf("win UDP IPv4 TTL = %d, want 128", got)
	}
}
