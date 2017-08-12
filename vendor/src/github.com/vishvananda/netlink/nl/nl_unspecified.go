// +build !linux

package nl

import (
    "syscall"
    "encoding/binary"
)

const (
	// Family type definitions
	FAMILY_ALL = syscall.AF_UNSPEC
	FAMILY_V4  = syscall.AF_INET
	FAMILY_V6  = syscall.AF_INET6
)

var SupportedNlFamilies = []int{}

func NativeEndian() binary.ByteOrder {
	return nil
}
