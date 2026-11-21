//go:build !linux

package dialer

import "net"

func bindTTLToDialer(int, *net.Dialer) {}

func bindTTLToListenConfig(int, *net.ListenConfig) {}
