package dialer

import "context"

// WindowsInitialTTL is the default IPv4 TTL / IPv6 Hop Limit used by Windows
// TCP/IP stacks, preserved across proxy relays when the originating host is Windows.
const WindowsInitialTTL = 128

type initialTTLKey struct{}

// WithInitialTTL returns a context carrying the desired initial IP TTL / Hop Limit
// for outbound sockets dialed using that context.
func WithInitialTTL(ctx context.Context, ttl int) context.Context {
	if ttl <= 0 || ttl > 255 {
		return ctx
	}
	return context.WithValue(ctx, initialTTLKey{}, ttl)
}

// InitialTTLFromContext extracts the desired initial IP TTL / Hop Limit from ctx,
// returning 0 when none was requested.
func InitialTTLFromContext(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	ttl, _ := ctx.Value(initialTTLKey{}).(int)
	if ttl <= 0 || ttl > 255 {
		return 0
	}
	return ttl
}
