// +build !linux

package netlink

import (
	"net"
)

// Scope is an enum representing a route scope.
type Scope uint8

type Route struct {
	LinkIndex int
	Scope     Scope
	Dst       *net.IPNet
	Src       net.IP
	Gw        net.IP
}
