//go:build freebsd

/*
Copyright 2026 The Kubernetes Authors.

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

package pidlimit

import (
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	statsapi "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// Stats provides basic information about max and current process count.
// FreeBSD limits processes, not threads: the limit is the smaller of
// kern.maxproc and kern.pid_max, and the count is the number of processes.
func Stats() (*statsapi.RlimitStats, error) {
	rlimit := &statsapi.RlimitStats{}

	taskMax := int64(-1)
	for _, name := range []string{"kern.maxproc", "kern.pid_max"} {
		if limit, err := unix.SysctlUint32(name); err == nil {
			if taskMax == -1 || taskMax > int64(limit) {
				taskMax = int64(limit)
			}
		}
	}
	if taskMax >= 0 {
		rlimit.MaxPID = &taskMax
	}

	if procs, err := processCount(); err == nil {
		rlimit.NumOfRunningProcesses = &procs
	}

	rlimit.Time = v1.NewTime(time.Now())

	return rlimit, nil
}

// processCount counts the processes in kern.proc.proc, an array of struct
// kinfo_proc whose first field, ki_structsize, is the element size.
func processCount() (int64, error) {
	buf, err := unix.SysctlRaw("kern.proc.proc")
	if err != nil {
		return 0, err
	}
	if len(buf) < 4 {
		return 0, nil
	}
	size := int(binary.NativeEndian.Uint32(buf))
	if size <= 0 || len(buf)%size != 0 {
		return 0, fmt.Errorf("kern.proc.proc: %d bytes with ki_structsize %d", len(buf), size)
	}
	return int64(len(buf) / size), nil
}
