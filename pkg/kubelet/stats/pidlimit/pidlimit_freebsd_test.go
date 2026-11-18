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
	"os/exec"
	"testing"
)

func TestStats(t *testing.T) {
	s, err := Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxPID == nil || *s.MaxPID <= 0 {
		t.Errorf("MaxPID = %v", s.MaxPID)
	}
	if s.NumOfRunningProcesses == nil || *s.NumOfRunningProcesses <= 1 {
		t.Fatalf("NumOfRunningProcesses = %v", s.NumOfRunningProcesses)
	}
	// Starting processes raises the count.
	var cmds []*exec.Cmd
	for i := 0; i < 5; i++ {
		c := exec.Command("sleep", "5")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	s2, _ := Stats()
	if *s2.NumOfRunningProcesses < *s.NumOfRunningProcesses+5 {
		t.Errorf("count went from %d to %d with 5 more processes", *s.NumOfRunningProcesses, *s2.NumOfRunningProcesses)
	}
	for _, c := range cmds {
		c.Process.Kill()
		c.Wait()
	}
	t.Logf("MaxPID %d, processes %d", *s.MaxPID, *s.NumOfRunningProcesses)
}
