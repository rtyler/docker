package sysinfo

func New(quiet bool) *SysInfo {
	sysInfo := &SysInfo{}
	/* These structs cannot be nil otherwise gnarly nil dereferences will
	 * happen further "up" in the code (daemon.go)
	 */
	sysInfo.cgroupMemInfo = &cgroupMemInfo{}
	sysInfo.cgroupCpuInfo = &cgroupCpuInfo{}
	return sysInfo
}
