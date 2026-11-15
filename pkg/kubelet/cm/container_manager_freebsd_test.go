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

package cm

import (
	"math"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

// In-place resize compares the pod-level config the runtime last applied with
// the desired one, and dereferences every value.
func TestFreeBSDPodContainerManagerPodCgroupConfig(t *testing.T) {
	pcm := &podContainerManagerFreeBSD{}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-1")}}
	get := func() (int64, int64, uint64) {
		t.Helper()
		mem, err := pcm.GetPodCgroupConfig(pod, v1.ResourceMemory)
		if err != nil || mem.Memory == nil {
			t.Fatalf("memory config: %+v, %v", mem, err)
		}
		cpu, err := pcm.GetPodCgroupConfig(pod, v1.ResourceCPU)
		if err != nil || cpu.CPUQuota == nil || cpu.CPUPeriod == nil || cpu.CPUShares == nil {
			t.Fatalf("cpu config: %+v, %v", cpu, err)
		}
		return *mem.Memory, *cpu.CPUQuota, *cpu.CPUShares
	}
	ptr := func(v int64) *int64 { return &v }
	uptr := func(v uint64) *uint64 { return &v }

	// unknown (e.g. after a kubelet restart): unlimited, so the kubelet
	// sends the pod's limits again
	if mem, quota, shares := get(); mem != math.MaxInt64 || quota != -1 || shares != MinShares {
		t.Errorf("unknown pod: %d/%d/%d", mem, quota, shares)
	}
	// recorded at sandbox creation
	RecordPodLevelConfig(pod.UID, &ResourceConfig{Memory: ptr(256 << 20), CPUQuota: ptr(50000), CPUPeriod: uptr(100000), CPUShares: uptr(512)})
	if mem, quota, shares := get(); mem != 256<<20 || quota != 50000 || shares != 512 {
		t.Errorf("recorded: %d/%d/%d", mem, quota, shares)
	}
	// a memory-only update keeps the CPU values
	if err := pcm.SetPodCgroupConfig(klog.Background(), pod, &ResourceConfig{Memory: ptr(512 << 20)}); err != nil {
		t.Fatal(err)
	}
	if mem, quota, shares := get(); mem != 512<<20 || quota != 50000 || shares != 512 {
		t.Errorf("after memory update: %d/%d/%d", mem, quota, shares)
	}
	RecordPodLevelConfig(pod.UID, nil)
	if mem, _, _ := get(); mem != math.MaxInt64 {
		t.Errorf("after forget: %d", mem)
	}
}
