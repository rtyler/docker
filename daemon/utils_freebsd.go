// +build freebsd

package daemon

import (
	"github.com/docker/docker/runconfig"
)

func selinuxSetDisabled() {
}

func selinuxFreeLxcContexts(label string) {
}

func selinuxEnabled() bool {
	return false
}

func mergeLxcConfIntoOptions(hostConfig *runconfig.HostConfig) ([]string, error) {
	if hostConfig == nil {
		return nil, nil
	}

	out := []string{}

	return out, nil
}
