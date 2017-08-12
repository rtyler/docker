// +build freebsd

package reexec

import (
	"os/exec"
)

// Self returns the path to the current process's binary.
// Uses os.Args[0].
func Self() string {
	return naiveSelf()
}

func Command(args ...string) *exec.Cmd {
	return &exec.Cmd{
		Path: Self(),
		Args: args,
		//SysProcAttr: &syscall.SysProcAttr{
		//	Pdeathsig: syscall.SIGTERM,
		//},
	}
}
