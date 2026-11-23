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

package pf

import (
	"bytes"
	"sync"
	"time"

	utilexec "k8s.io/utils/exec"
)

// pfctlMu serializes the pfctl commands of this process that change pf.
// Loading rules takes a ticket for pf's address pool buffer, and pf has one
// such buffer for the whole system (DIOCBEGINADDRS): a second load started
// meanwhile invalidates the first one's ticket, which then fails with
// "DIOCADDADDR: Device busy" (or DIOCADDRULE). A dual-stack kube-proxy runs
// one proxier per IP family, and they sync at the same time.
var pfctlMu sync.Mutex

// pfctlBusyRetries is how often runPfctl retries a command that failed
// because another process (the families of this kube-proxy are serialized
// above, but bsd-netpol and the CNI portmap plugin also load rules) was
// loading rules at the same moment.
const pfctlBusyRetries = 5

// sleep is replaced in tests.
var sleep = time.Sleep

// runPfctl runs a pfctl command that changes pf, with stdin as its input
// (nil for none): one at a time in this process, and retried while pf
// reports the device busy.
func runPfctl(execer utilexec.Interface, stdin []byte, args ...string) ([]byte, error) {
	pfctlMu.Lock()
	defer pfctlMu.Unlock()
	for attempt := 0; ; attempt++ {
		cmd := execer.Command("pfctl", args...)
		if stdin != nil {
			cmd.SetStdin(bytes.NewReader(stdin))
		}
		out, err := cmd.CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("Device busy")) || attempt == pfctlBusyRetries {
			return out, err
		}
		sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
	}
}
