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
	"context"
	"time"

	v1 "k8s.io/api/core/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	"k8s.io/kubernetes/pkg/kubelet/cm"
)

// applySandboxResources sends the pod-level limits with the sandbox. FreeBSD
// has no pod cgroup for the kubelet to configure: the runtime puts these
// limits on the pod jail (the parent of the container jails) as rctl rules,
// which then limit the pod as a whole. They are computed exactly like the
// Linux pod cgroup's (cm.ResourceConfigForPod): a memory limit only if every
// container declares one, likewise the CPU quota, pod overhead included
// (so Overhead isn't sent separately), and pod-level resources honoured.
func (m *kubeGenericRuntimeManager) applySandboxResources(ctx context.Context, pod *v1.Pod, config *runtimeapi.PodSandboxConfig) error {
	if config.Linux == nil {
		return nil
	}
	period := uint64(m.cpuCFSQuotaPeriod.Duration / time.Microsecond)
	rc := cm.ResourceConfigForPod(pod, m.cpuCFSQuota, period, false, kubeletconfig.NoneMemoryReservationPolicy)
	config.Linux.Resources = convertResourceConfigToLinuxContainerResources(rc)
	// What the pod jail starts with, for in-place resize (GetPodCgroupConfig).
	cm.RecordPodLevelConfig(pod.UID, rc)
	return nil
}
