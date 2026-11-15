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

package kuberuntime

import (
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestGenerateFreeBSDContainerResources(t *testing.T) {
	q := resource.MustParse
	for _, tc := range []struct {
		name     string
		cfsQuota bool
		res      v1.ResourceRequirements
		want     *runtimeapi.LinuxContainerResources
	}{
		{name: "none", cfsQuota: true, want: &runtimeapi.LinuxContainerResources{}},
		{
			name: "limits and requests", cfsQuota: true,
			res: v1.ResourceRequirements{
				Limits:   v1.ResourceList{v1.ResourceMemory: q("64Mi"), v1.ResourceCPU: q("200m")},
				Requests: v1.ResourceList{v1.ResourceCPU: q("100m")},
			},
			want: &runtimeapi.LinuxContainerResources{MemoryLimitInBytes: 64 << 20, CpuShares: 102, CpuPeriod: 100000, CpuQuota: 20000},
		},
		{
			name: "cfs quota disabled drops cpu limit only", cfsQuota: false,
			res: v1.ResourceRequirements{Limits: v1.ResourceList{v1.ResourceMemory: q("1Gi"), v1.ResourceCPU: q("2")}},
			// no request set: requests are defaulted from limits by the API server, not here
			want: &runtimeapi.LinuxContainerResources{MemoryLimitInBytes: 1 << 30},
		},
		{
			name: "tiny cpu limit clamps quota", cfsQuota: true,
			res:  v1.ResourceRequirements{Limits: v1.ResourceList{v1.ResourceCPU: q("1m")}},
			want: &runtimeapi.LinuxContainerResources{CpuPeriod: 100000, CpuQuota: 1000},
		},
		{
			name: "tiny request clamps shares", cfsQuota: true,
			res:  v1.ResourceRequirements{Requests: v1.ResourceList{v1.ResourceCPU: q("1m")}},
			want: &runtimeapi.LinuxContainerResources{CpuShares: 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &kubeGenericRuntimeManager{cpuCFSQuota: tc.cfsQuota, cpuCFSQuotaPeriod: metav1.Duration{Duration: 100 * time.Millisecond}}
			got := m.generateFreeBSDContainerResources(&v1.Container{Resources: tc.res})
			if got.MemoryLimitInBytes != tc.want.MemoryLimitInBytes || got.CpuShares != tc.want.CpuShares ||
				got.CpuPeriod != tc.want.CpuPeriod || got.CpuQuota != tc.want.CpuQuota {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// In-place resize: the resources the kubelet sends (generateContainerResources)
// come back from the runtime's ContainerStatus and must convert to the same
// requests/limits (toKubeContainerResources), or the resize never completes.
func TestFreeBSDContainerResourcesRoundTrip(t *testing.T) {
	m := &kubeGenericRuntimeManager{cpuCFSQuota: true, cpuCFSQuotaPeriod: metav1.Duration{Duration: 100 * time.Millisecond}}
	for _, tc := range []struct {
		name                string
		requests, limits    v1.ResourceList
		wantCPUReq          string
		wantCPULim, wantMem string
	}{
		{"limits and requests",
			v1.ResourceList{v1.ResourceCPU: resource.MustParse("100m"), v1.ResourceMemory: resource.MustParse("64Mi")},
			v1.ResourceList{v1.ResourceCPU: resource.MustParse("200m"), v1.ResourceMemory: resource.MustParse("128Mi")},
			"100m", "200m", "128Mi"},
		{"resized up",
			v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
			v1.ResourceList{v1.ResourceCPU: resource.MustParse("1500m"), v1.ResourceMemory: resource.MustParse("1Gi")},
			"500m", "1500m", "1Gi"},
		{"requests only", v1.ResourceList{v1.ResourceCPU: resource.MustParse("250m")}, nil, "250m", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &v1.Container{Resources: v1.ResourceRequirements{Requests: tc.requests, Limits: tc.limits}}
			sent := m.generateContainerResources(t.Context(), &v1.Pod{}, c)
			if sent.GetLinux() == nil {
				t.Fatalf("no Linux resources sent")
			}
			got := toKubeContainerResources(sent)
			if got == nil {
				t.Fatalf("no resources converted back")
			}
			check := func(what string, q *resource.Quantity, want string) {
				t.Helper()
				if want == "" {
					if q != nil {
						t.Errorf("%s = %s, want none", what, q.String())
					}
					return
				}
				if q == nil || q.Cmp(resource.MustParse(want)) != 0 {
					t.Errorf("%s = %v, want %s", what, q, want)
				}
			}
			check("cpu request", got.CPURequest, tc.wantCPUReq)
			check("cpu limit", got.CPULimit, tc.wantCPULim)
			check("memory limit", got.MemoryLimit, tc.wantMem)
		})
	}
	if toKubeContainerResources(nil) != nil || toKubeContainerResources(&runtimeapi.ContainerResources{}) != nil {
		t.Errorf("nil/empty status should convert to nil")
	}
}
