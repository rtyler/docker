// +build !linux

package nl

import (
	"syscall"
)

const (
	// Family type definitions
	FAMILY_ALL = syscall.AF_UNSPEC
	FAMILY_V4  = syscall.AF_INET
	FAMILY_V6  = syscall.AF_INET6
)

