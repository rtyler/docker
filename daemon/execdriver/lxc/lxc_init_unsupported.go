// +build !linux

package lxc

/* Redefining because init.go is not compiled on "not linux" platforms */
type InitArgs struct {
}

func finalizeNamespace(args *InitArgs) error {
	panic("Not supported on this platform")
}
