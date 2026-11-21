package outbound

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	M "github.com/metacubex/sing/common/metadata"
	singN "github.com/metacubex/sing/common/network"
)

func isWindowsTTLContext(ctx context.Context) bool {
	return dialer.InitialTTLFromContext(ctx) == dialer.WindowsInitialTTL
}

// ttlProxyDialer wraps a C.Dialer so every outbound socket dialed through it
// carries the configured initial IP TTL / Hop Limit in ctx.
type ttlProxyDialer struct {
	inner C.Dialer
	ttl   int
}

func wrapDialerWithTTL(d C.Dialer, ttl int) C.Dialer {
	if d == nil || ttl <= 0 {
		return d
	}
	return ttlProxyDialer{inner: d, ttl: ttl}
}

func (d ttlProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.inner.DialContext(dialer.WithInitialTTL(ctx, d.ttl), network, address)
}

func (d ttlProxyDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return d.inner.ListenPacket(dialer.WithInitialTTL(ctx, d.ttl), network, address, rAddrPort)
}

// ttlSingDialer wraps a sing network.Dialer so multiplexed transports (AnyTLS,
// SingMux) establish companion outer connections with the requested initial TTL.
type ttlSingDialer struct {
	inner singN.Dialer
	ttl   int
}

func wrapSingDialerWithTTL(d singN.Dialer, ttl int) singN.Dialer {
	if d == nil || ttl <= 0 {
		return d
	}
	return ttlSingDialer{inner: d, ttl: ttl}
}

func (d ttlSingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.inner.DialContext(dialer.WithInitialTTL(ctx, d.ttl), network, destination)
}

func (d ttlSingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.inner.ListenPacket(dialer.WithInitialTTL(ctx, d.ttl), destination)
}
