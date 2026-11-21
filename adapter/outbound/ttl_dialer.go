package outbound

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	M "github.com/metacubex/sing/common/metadata"
	singN "github.com/metacubex/sing/common/network"
)

// ttlClientPool lazily creates and caches companion multiplexed clients keyed
// by non-zero initial TTL (e.g., 128 for Windows, 255 for Apple macOS/iOS) so
// multiplexed transports never mix OS fingerprints on the same outer socket.
type ttlClientPool[T any] struct {
	mu      sync.Mutex
	clients map[int]T
	factory func(ttl int) (T, error)
}

func (p *ttlClientPool[T]) init(factory func(ttl int) (T, error)) {
	p.factory = factory
}

func (p *ttlClientPool[T]) get(ctx context.Context, fallback T) (T, error) {
	ttl := dialer.InitialTTLFromContext(ctx)
	if ttl <= 0 || p.factory == nil {
		return fallback, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients == nil {
		p.clients = make(map[int]T, 2)
	}
	if c, ok := p.clients[ttl]; ok {
		return c, nil
	}
	c, err := p.factory(ttl)
	if err != nil {
		var zero T
		return zero, err
	}
	p.clients[ttl] = c
	return c, nil
}

func (p *ttlClientPool[T]) getNoErr(ctx context.Context, fallback T) T {
	c, err := p.get(ctx, fallback)
	if err != nil {
		return fallback
	}
	return c
}

func (p *ttlClientPool[T]) takeAll() []T {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.clients) == 0 {
		return nil
	}
	out := make([]T, 0, len(p.clients))
	for _, c := range p.clients {
		out = append(out, c)
	}
	p.clients = nil
	return out
}

func (p *ttlClientPool[T]) forEach(fn func(T)) {
	p.mu.Lock()
	snapshot := make([]T, 0, len(p.clients))
	for _, c := range p.clients {
		snapshot = append(snapshot, c)
	}
	p.mu.Unlock()
	for _, c := range snapshot {
		fn(c)
	}
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
