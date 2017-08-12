// +build freebsd

package execdrivers

import (
	"fmt"
	"path"

	"github.com/docker/docker/daemon/execdriver"
	"github.com/docker/docker/daemon/execdriver/jail"
	"github.com/docker/docker/pkg/sysinfo"
)

func NewDriver(name string, options []string, root, libPath, initPath string, sysInfo *sysinfo.SysInfo) (execdriver.Driver, error) {
	switch name {
	case "jail":
		return jail.NewDriver(path.Join(root, "execdriver", "jail"), initPath)
	}
	return nil, fmt.Errorf("unknown exec driver %s", name)
}
