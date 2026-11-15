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

package cadvisor

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const mb = 1 << 20

func TestNodeWorkingSet(t *testing.T) {
	for _, tc := range []struct {
		name                                        string
		physmem, free, inactive, tmpfs, arc, arcMin uint64
		wantWS, wantUsage                           uint64
	}{
		// measured on a 12 GB dev VM: racct memoryuse said 790 MB
		{"idle node", 12255 * mb, 10013 * mb, 449 * mb, 0, 842 * mb, 382 * mb, 1333 * mb, 2242 * mb},
		{"ARC below its minimum is not reclaimable", 8192 * mb, 1024 * mb, 0, 0, 256 * mb, 512 * mb, 7168 * mb, 7168 * mb},
		{"no ZFS", 4096 * mb, 1024 * mb, 1024 * mb, 0, 0, 0, 2048 * mb, 3072 * mb},
		{"never negative", 1024 * mb, 512 * mb, 900 * mb, 0, 0, 0, 0, 512 * mb},
		// measured: a 6.6 GB tmpfs fill, pages moving to the inactive queue
		// (free 326 MB); counting them as reclaimable claimed ~5 GB available
		{"tmpfs in inactive is not reclaimable", 12255 * mb, 326 * mb, 4760 * mb, 6656 * mb, 1100 * mb, 382 * mb, 11211 * mb, 11929 * mb},
		{"inactive beyond tmpfs is reclaimable", 12255 * mb, 326 * mb, 4760 * mb, 1024 * mb, 1100 * mb, 382 * mb, 7475 * mb, 11929 * mb},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws, usage := nodeWorkingSet(tc.physmem, tc.free, tc.inactive, tc.tmpfs, tc.arc, tc.arcMin)
			if ws != tc.wantWS || usage != tc.wantUsage {
				t.Errorf("workingSet/usage = %d/%d MB, want %d/%d MB", ws/mb, usage/mb, tc.wantWS/mb, tc.wantUsage/mb)
			}
		})
	}
}

// On a live system the working set must cover at least the wired memory
// (the ARC minimum and other wired kernel memory), which process RSS doesn't.
func TestNodeMemoryLive(t *testing.T) {
	physmem, err := unix.SysctlUint64("hw.physmem")
	if err != nil {
		t.Skip(err)
	}
	ws, usage, err := nodeMemory(physmem)
	if err != nil {
		t.Fatal(err)
	}
	if ws == 0 || ws > usage || usage > physmem {
		t.Errorf("implausible: workingSet %d, usage %d, physmem %d", ws, usage, physmem)
	}
	t.Logf("workingSet %d MB, usage %d MB, physmem %d MB", ws/mb, usage/mb, physmem/mb)
}

// tmpfsUsed must see current tmpfs usage, not what getfsstat cached at mount
// time. Needs root (mounts a tmpfs).
func TestTmpfsUsedLive(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	if out, err := exec.Command("mount", "-t", "tmpfs", "tmpfs", dir).CombinedOutput(); err != nil {
		t.Skipf("can't mount tmpfs: %v: %s", err, out)
	}
	defer exec.Command("umount", dir).Run()
	before, err := tmpfsUsed()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), make([]byte, 64*mb), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := tmpfsUsed()
	if err != nil {
		t.Fatal(err)
	}
	if after < before+60*mb {
		t.Errorf("tmpfs usage %d MB -> %d MB after writing 64 MB", before/mb, after/mb)
	}
}
