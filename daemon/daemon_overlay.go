// +build !exclude_graphdriver_overlay,linux, +build !freebsd

package daemon

import (
	_ "github.com/docker/docker/daemon/graphdriver/overlay"
)
