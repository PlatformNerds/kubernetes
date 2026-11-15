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
	"k8s.io/apimachinery/pkg/api/resource"
)

// In-place resize dereferences the pod-level config, so it must always be
// fully populated, and it must equal what the allocated pod implies (so the
// kubelet only resizes containers).
func TestFreeBSDPodContainerManagerGetPodCgroupConfig(t *testing.T) {
	pcm := &podContainerManagerFreeBSD{}
	res := func(cpu, mem string) v1.ResourceList {
		rl := v1.ResourceList{}
		if cpu != "" {
			rl[v1.ResourceCPU] = resource.MustParse(cpu)
		}
		if mem != "" {
			rl[v1.ResourceMemory] = resource.MustParse(mem)
		}
		return rl
	}
	pod := func(req, lim v1.ResourceList) *v1.Pod {
		return &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{Name: "c", Resources: v1.ResourceRequirements{Requests: req, Limits: lim}}}}}
	}
	for _, tc := range []struct {
		name               string
		pod                *v1.Pod
		wantMem, wantQuota int64
		wantShares         uint64
	}{
		{"limited", pod(res("100m", "64Mi"), res("200m", "128Mi")), 128 << 20, 20000, 102},
		{"no limits", pod(res("250m", ""), nil), math.MaxInt64, -1, 256},
		{"best effort", pod(nil, nil), math.MaxInt64, -1, MinShares},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem, err := pcm.GetPodCgroupConfig(tc.pod, v1.ResourceMemory)
			if err != nil || mem == nil || mem.Memory == nil {
				t.Fatalf("memory config: %+v, %v", mem, err)
			}
			if *mem.Memory != tc.wantMem {
				t.Errorf("memory = %d, want %d", *mem.Memory, tc.wantMem)
			}
			cpu, err := pcm.GetPodCgroupConfig(tc.pod, v1.ResourceCPU)
			if err != nil || cpu == nil || cpu.CPUQuota == nil || cpu.CPUShares == nil || cpu.CPUPeriod == nil {
				t.Fatalf("cpu config: %+v, %v", cpu, err)
			}
			if *cpu.CPUQuota != tc.wantQuota || *cpu.CPUShares != tc.wantShares {
				t.Errorf("cpu quota/shares = %d/%d, want %d/%d", *cpu.CPUQuota, *cpu.CPUShares, tc.wantQuota, tc.wantShares)
			}
		})
	}
}
