package dialer

import "context"

// WindowsInitialTTL is the default IPv4 TTL / IPv6 Hop Limit used by Windows
// TCP/IP stacks, preserved across proxy relays when the originating host is Windows.
const WindowsInitialTTL = 128

// LinuxRelayTTL is the distinct IPv4 TTL / IPv6 Hop Limit used on proxy hops to
// signal an explicitly classified Linux / Android client downstream (avoiding
// ambiguity with direct UDP TTL<=64 fallback).
const LinuxRelayTTL = 192

// AppleRelayTTL is the distinct IPv4 TTL / IPv6 Hop Limit used on proxy hops to
// signal an originating Apple (macOS / iOS / iPadOS) client to downstream relays.
const AppleRelayTTL = 255

type initialTTLKey struct{}

// WithInitialTTL returns a context carrying the desired initial IP TTL / Hop Limit
// for outbound sockets dialed using that context.
func WithInitialTTL(ctx context.Context, ttl int) context.Context {
	if ttl <= 0 || ttl > 255 {
		return ctx
	}
	return context.WithValue(ctx, initialTTLKey{}, ttl)
}

// WithoutRelayTTL strips proxy-hop-only relay TTL values (> 128, i.e., Linux
// 192 and Apple 255) so DIRECT outbounds never emit non-standard TTLs to public
// destinations while still preserving Windows TTL 128.
func WithoutRelayTTL(ctx context.Context) context.Context {
	if InitialTTLFromContext(ctx) > WindowsInitialTTL {
		return context.WithValue(ctx, initialTTLKey{}, 0)
	}
	return ctx
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
