//go:build freebsd

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cadvisor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	//"runtime"
	"time"
	"unsafe"

	"github.com/google/cadvisor/events"
	cadvisorapi "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

type cadvisorClient struct {
	imageFsInfoProvider ImageFsInfoProvider
	rootPath            string
}

var _ Interface = new(cadvisorClient)

var startTime time.Time

func init() {
	startTime = time.Now()
}

// New creates a new cAdvisor Interface for freebsd systems.
func New(_ klog.Logger, imageFsInfoProvider ImageFsInfoProvider, rootPath string, cgroupRoots []string, usingLegacyStats, localStorageCapacityIsolation bool) (Interface, error) {
	return &cadvisorClient{
		imageFsInfoProvider: imageFsInfoProvider,
		rootPath:            rootPath,
	}, nil
}

func (cc *cadvisorClient) Start() error {
	return nil
}

func (cu *cadvisorClient) DockerContainer(name string, req *cadvisorapi.ContainerInfoRequest) (cadvisorapi.ContainerInfo, error) {
	return cadvisorapi.ContainerInfo{}, nil
}

func (cc *cadvisorClient) ContainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (*cadvisorapi.ContainerInfo, error) {
	return &cadvisorapi.ContainerInfo{}, nil
}

func (cc *cadvisorClient) ContainerInfoV2(name string, options cadvisorapiv2.RequestOptions) (map[string]cadvisorapiv2.ContainerInfo, error) {
	infos := make(map[string]cadvisorapiv2.ContainerInfo)
	rootContainerInfo, err := createRootContainerInfo()
	if err != nil {
		return nil, err
	}

	infos["/"] = *rootContainerInfo

	return infos, nil
}

func (cc *cadvisorClient) VersionInfo() (*cadvisorapi.VersionInfo, error) {
	return &cadvisorapi.VersionInfo{}, nil
}

func (cc *cadvisorClient) SubcontainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (map[string]*cadvisorapi.ContainerInfo, error) {
	return map[string]*cadvisorapi.ContainerInfo{}, nil
}

func (cc *cadvisorClient) MachineInfo() (*cadvisorapi.MachineInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	memTotal, _, err := getMemInfo()
	if err != nil {
		return nil, err
	}

	cores, err := unix.SysctlUint32("kern.smp.cpus")
	if err != nil {
		return nil, err
	}

	physCores, err := unix.SysctlUint32("kern.smp.cores")
	if err != nil {
		return nil, err
	}

	return &cadvisorapi.MachineInfo{
		NumCores:         int(cores),
		NumPhysicalCores: int(physCores),
		NumSockets:       1,
		MemoryCapacity:   uint64(memTotal),
		MachineID:        hostname,
	}, nil
}

func (cc *cadvisorClient) ImagesFsInfo(context.Context) (cadvisorapiv2.FsInfo, error) {
	// TODO: don't hardcode the path here
	return cc.GetDirFsInfo("/var/db/containers")
}

func (cu *cadvisorClient) ContainerFsInfo(context.Context) (cadvisorapiv2.FsInfo, error) {
	return cadvisorapiv2.FsInfo{}, nil
}

func (cc *cadvisorClient) RootFsInfo() (cadvisorapiv2.FsInfo, error) {
	return cc.GetDirFsInfo(cc.rootPath)
}

func (cc *cadvisorClient) WatchEvents(request *events.Request) (*events.EventChannel, error) {
	return &events.EventChannel{}, nil
}

func toString(bs []byte) string {
	return string(bs[:bytes.IndexByte(bs, 0)])
}

func (cu *cadvisorClient) GetDirFsInfo(path string) (cadvisorapiv2.FsInfo, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return cadvisorapiv2.FsInfo{}, err
	}

	return cadvisorapiv2.FsInfo{
		Device:     toString(stat.Mntfromname[:]),
		Mountpoint: toString(stat.Mntonname[:]),
		Capacity:   stat.Blocks * stat.Bsize,
		Available:  uint64(stat.Bavail) * stat.Bsize,
		Usage:      (stat.Blocks - uint64(stat.Bavail)) * stat.Bsize,
		Inodes:     nil,
		InodesFree: nil,
	}, nil
}

func (cu *cadvisorClient) GetRequestedContainersInfo(containerName string, options cadvisorapiv2.RequestOptions) (map[string]*cadvisorapi.ContainerInfo, error) {
	return nil, nil
}

// vmtotal mirrors struct vmtotal from <sys/vmmeter.h> (stable layout since FreeBSD 12).
// Defined in Go so the kubelet can be built with CGO_ENABLED=0 and cross-compiled.
type vmtotal struct {
	VM, AVM, RM, ARM, VMShr, AVMShr, RMShr, ARMShr, Free uint64
	RQ, DW, PW, SL, SW                                   int16
	_                                                    [3]uint16
}

func getMemInfo() (int64, int64, error) {
	data, err := unix.SysctlRaw("vm.vmtotal")
	if err != nil {
		return -1, -1, fmt.Errorf("can't get kernel info: %w", err)
	}
	if len(data) != int(unsafe.Sizeof(vmtotal{})) {
		return -1, -1, fmt.Errorf("unexpected vmtotal size %d", len(data))
	}
	total := (*vmtotal)(unsafe.Pointer(&data[0]))

	physmem, err := unix.SysctlUint64("hw.physmem")
	if err != nil {
		return -1, -1, fmt.Errorf("can't get hw.physmem value: %w", err)
	}
	pagesize := int64(unix.Getpagesize())
	return int64(physmem), pagesize * int64(total.Free), nil
}

// nodeMemory returns the node's memory working set and usage. racct's
// memoryuse for jail 0 only sums process RSS: it leaves out the ZFS ARC, tmpfs
// (emptyDir medium Memory, projected service account tokens), and other wired
// kernel memory, so the kubelet saw memory as nearly free until the host ran
// out, and memory eviction never triggered. Like Linux (usage minus inactive
// file pages), count what the kernel can reclaim quickly as available: free
// pages, inactive pages and the part of the ARC above its minimum size. But
// FreeBSD's inactive queue also holds tmpfs pages, which can't be reclaimed
// without swap: filling a tmpfs on a 12 GB node made "available" rise to 5 GB
// while 330 MB were free. So inactive pages only count as reclaimable beyond
// what tmpfs holds (conservative: tmpfs pages still active are subtracted too).
func nodeMemory(physmem uint64) (workingSet, usage uint64, err error) {
	pagesize := uint64(unix.Getpagesize())
	var free, inactive uint32
	if free, err = unix.SysctlUint32("vm.stats.vm.v_free_count"); err != nil {
		return 0, 0, err
	}
	if inactive, err = unix.SysctlUint32("vm.stats.vm.v_inactive_count"); err != nil {
		return 0, 0, err
	}
	// No ZFS loaded: no ARC.
	arcSize, _ := unix.SysctlUint64("kstat.zfs.misc.arcstats.size")
	arcMin, _ := unix.SysctlUint64("kstat.zfs.misc.arcstats.c_min")
	tmpfs, err := tmpfsUsed()
	if err != nil {
		return 0, 0, err
	}
	workingSet, usage = nodeWorkingSet(physmem, uint64(free)*pagesize, uint64(inactive)*pagesize, tmpfs, arcSize, arcMin)
	return workingSet, usage, nil
}

// tmpfsUsed returns the bytes in use on all tmpfs mounts.
func tmpfsUsed() (uint64, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return 0, err
	}
	// Mounts can appear between the two calls: leave room.
	buf := make([]unix.Statfs_t, n+16)
	if n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT); err != nil {
		return 0, err
	}
	var used uint64
	for _, fs := range buf[:n] {
		if unix.ByteSliceToString(fs.Fstypename[:]) != "tmpfs" {
			continue
		}
		// MNT_NOWAIT returns the statistics cached at mount time, which
		// tmpfs never refreshes (df: "stats possibly stale"): statfs each
		// tmpfs mount for current numbers (tmpfs never blocks).
		var st unix.Statfs_t
		if err := unix.Statfs(unix.ByteSliceToString(fs.Mntonname[:]), &st); err != nil {
			continue // unmounted meanwhile
		}
		if st.Blocks > uint64(st.Bfree) {
			used += (st.Blocks - uint64(st.Bfree)) * st.Bsize
		}
	}
	return used, nil
}

// nodeWorkingSet: usage is everything not free; the working set additionally
// excludes inactive pages not taken by tmpfs, and the reclaimable part of the ARC.
func nodeWorkingSet(physmem, free, inactive, tmpfs, arcSize, arcMin uint64) (workingSet, usage uint64) {
	sub := func(a, b uint64) uint64 {
		if b > a {
			return 0
		}
		return a - b
	}
	usage = sub(physmem, free)
	workingSet = sub(sub(usage, sub(inactive, tmpfs)), sub(arcSize, arcMin))
	return workingSet, usage
}

func createRootContainerInfo() (*cadvisorapiv2.ContainerInfo, error) {
	// Jail id zero represents the host.
	entries, err := getRacct("jail:0")
	if err != nil {
		return nil, err
	}
	cpu, err := getCPUTime()

	physmem, err := unix.SysctlUint64("hw.physmem")
	if err != nil {
		return nil, fmt.Errorf("can't get hw.physmem value: %w", err)
	}

	stats := &cadvisorapiv2.ContainerStats{Timestamp: time.Now()}
	userTime := cpu.user + cpu.nice
	sysTime := cpu.sys + cpu.intr
	stats.Cpu = &cadvisorapi.CpuStats{
		Usage: cadvisorapi.CpuUsage{
			Total:  uint64((userTime + sysTime) * 1000000000),
			User:   uint64(userTime * 1000000000),
			System: uint64(sysTime * 1000000000),
		},
	}
	if val, ok := entries["pcpu"]; ok {
		stats.CpuInst = &cadvisorapiv2.CpuInstStats{
			Usage: cadvisorapiv2.CpuInstUsage{
				Total: (val / 100.0) * 1000000000,
			},
		}
	}
	if ws, usage, err := nodeMemory(physmem); err == nil {
		stats.Memory = &cadvisorapi.MemoryStats{
			WorkingSet: ws,
			Usage:      usage,
		}
	} else if val, ok := entries["memoryuse"]; ok {
		klog.ErrorS(err, "Can't read node memory counters, falling back to process RSS (racct memoryuse)")
		stats.Memory = &cadvisorapi.MemoryStats{
			WorkingSet: val,
		}
	}
	// TODO: network stats?

	rootInfo := cadvisorapiv2.ContainerInfo{
		Spec: cadvisorapiv2.ContainerSpec{
			CreationTime: startTime,
			HasCpu:       true,
			HasMemory:    true,
			HasNetwork:   false,
			Memory: cadvisorapiv2.MemorySpec{
				Limit: physmem,
			},
		},
		Stats: []*cadvisorapiv2.ContainerStats{stats},
	}

	return &rootInfo, nil
}

// TODO: factor this out and add the prometheus copyright

type clockinfo struct {
	hz     int32 // clock frequency
	tick   int32 // micro-seconds per hz tick
	spare  int32
	stathz int32 // statistics clock frequency
	profhz int32 // profiling clock frequency
}

type cputime struct {
	user float64
	nice float64
	sys  float64
	intr float64
	idle float64
}

func getCPUTime() (*cputime, error) {
	const states = 5

	clockb, err := unix.SysctlRaw("kern.clockrate")
	if err != nil {
		return nil, err
	}
	clock := *(*clockinfo)(unsafe.Pointer(&clockb[0]))
	cpb, err := unix.SysctlRaw("kern.cp_time")
	if err != nil {
		return nil, err
	}

	var cpufreq float64
	if clock.stathz > 0 {
		cpufreq = float64(clock.stathz)
	} else {
		cpufreq = float64(clock.hz)
	}
	var times []float64
	for len(cpb) >= int(unsafe.Sizeof(int(0))) {
		t := *(*int)(unsafe.Pointer(&cpb[0]))
		times = append(times, float64(t)/cpufreq)
		cpb = cpb[unsafe.Sizeof(int(0)):]
	}

	cpu := &cputime{
		user: times[0],
		nice: times[0],
		sys:  times[0],
		intr: times[0],
		idle: times[0],
	}

	return cpu, nil
}

func getRacct(filter string) (map[string]uint64, error) {
	bp, err := syscall.ByteSliceFromString(filter)
	if err != nil {
		return nil, err
	}
	// rctl_get_racct returns ERANGE when the buffer is too small; grow and retry.
	var buf []byte
	for size := 1024; ; size *= 2 {
		buf = make([]byte, size)
		_, _, errno := syscall.Syscall6(syscall.SYS_RCTL_GET_RACCT,
			uintptr(unsafe.Pointer(&bp[0])),
			uintptr(len(bp)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)), 0, 0)
		if errno == syscall.ERANGE && size < 1<<20 {
			continue
		}
		if errno != 0 {
			return nil, fmt.Errorf("error calling rctl_get_racct with filter %s: %w", filter, errno)
		}
		break
	}
	if n := bytes.IndexByte(buf, 0); n >= 0 {
		buf = buf[:n]
	}
	res := make(map[string]uint64)
	for _, entry := range strings.Split(string(buf), ",") {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		val, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			klog.Warningf("unexpected rctl entry, ignoring: %s", entry)
			continue
		}
		res[key] = val
	}
	return res, nil
}

func IsPsiEnabled(_ klog.Logger) bool {
	return false
}
