// +build freebsd

package daemon

import (
	"github.com/docker/docker/api/types"
	"github.com/opencontainers/runc/libcontainer"
)

func convertStatsToAPITypes(ls *libcontainer.Stats) *types.Stats {
	s := &types.Stats{}
    return s
}
