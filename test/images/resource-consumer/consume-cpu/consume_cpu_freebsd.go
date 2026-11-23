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

package main

import (
	"flag"
	"time"

	"golang.org/x/sys/unix"
)

// On FreeBSD the systemstat package the generic version uses only has stubs
// (its process and uptime samples are zero), so the generic loop never saw
// any CPU use and spun at full speed whatever was asked. Measure this
// process's CPU time with getrusage(2), as the Windows version does with
// GetProcessTimes.

// cpuTimeNow returns the user and system CPU time this process has used.
func cpuTimeNow() time.Duration {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func main() {
	flag.Parse()
	duration := time.Duration(*durationSec) * time.Second
	start := time.Now()
	firstCPU := cpuTimeNow()
	for time.Since(start) < duration {
		elapsed := time.Since(start)
		var currentMillicores int64
		if elapsed > 0 {
			currentMillicores = int64(1000 * (cpuTimeNow() - firstCPU) / elapsed)
		}
		if currentMillicores < int64(*millicores) {
			doSomething()
		} else {
			time.Sleep(sleep)
		}
	}
}
