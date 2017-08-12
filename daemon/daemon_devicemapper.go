// +build !exclude_graphdriver_devicemapper,linux, +build !freebsd

package daemon

import (
	_ "github.com/docker/docker/daemon/graphdriver/devmapper"
)
