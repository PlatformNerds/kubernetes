//go:build freebsd

/*
Copyright 2018 The Kubernetes Authors.

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

	"k8s.io/api/core/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

// applyPlatformSpecificContainerConfig applies platform specific configurations to runtimeapi.ContainerConfig.
func (m *kubeGenericRuntimeManager) applyPlatformSpecificContainerConfig(ctx context.Context, config *runtimeapi.ContainerConfig, container *v1.Container, pod *v1.Pod, uid *int64, username string, nsTarget *kubecontainer.ContainerID) error {
	// Add a security context to support privileged containers
	sc, err := m.determineEffectiveSecurityContext(ctx, pod, container, uid, username)
	if err != nil {
		return err
	}
	config.Linux = &runtimeapi.LinuxContainerConfig{
		SecurityContext: sc,
		Resources:       m.generateFreeBSDContainerResources(container),
	}
	return nil
}

// FreeBSD has no cgroups and CRI has no FreeBSD resource message, so resource
// limits travel in the CRI LinuxContainerResources message: CRI-O turns it
// into OCI linux.resources and the OCI runtime (ocijail) turns that into
// rctl(8) rules on the container's jail:
//
//	limits.memory -> memory_limit_in_bytes -> swapuse:deny + memoryuse:deny
//	limits.cpu    -> cpu_quota/cpu_period  -> pcpu:deny (percent of one CPU)
//	requests.cpu  -> cpu_shares            -> no FreeBSD equivalent (ignored)
const (
	freebsdQuotaPeriod    = 100000 // usec, same default as CFS
	freebsdMinQuotaPeriod = 1000
	freebsdMinShares      = 2
	freebsdMaxShares      = 262144
	freebsdSharesPerCPU   = 1024
)

func (m *kubeGenericRuntimeManager) generateFreeBSDContainerResources(container *v1.Container) *runtimeapi.LinuxContainerResources {
	res := &runtimeapi.LinuxContainerResources{}

	if mem := container.Resources.Limits.Memory(); !mem.IsZero() {
		res.MemoryLimitInBytes = mem.Value()
	}

	if req := container.Resources.Requests.Cpu(); !req.IsZero() {
		res.CpuShares = freebsdMilliCPUToShares(req.MilliValue())
	}

	if lim := container.Resources.Limits.Cpu(); !lim.IsZero() && m.cpuCFSQuota {
		period := int64(freebsdQuotaPeriod)
		if p := m.cpuCFSQuotaPeriod.Duration.Microseconds(); p > 0 {
			period = p
		}
		res.CpuPeriod = period
		res.CpuQuota = freebsdMilliCPUToQuota(lim.MilliValue(), period)
	}
	return res
}

func freebsdMilliCPUToShares(milliCPU int64) int64 {
	shares := milliCPU * freebsdSharesPerCPU / 1000
	if shares < freebsdMinShares {
		return freebsdMinShares
	}
	if shares > freebsdMaxShares {
		return freebsdMaxShares
	}
	return shares
}

func freebsdMilliCPUToQuota(milliCPU, period int64) int64 {
	quota := milliCPU * period / 1000
	if quota < freebsdMinQuotaPeriod {
		quota = freebsdMinQuotaPeriod
	}
	return quota
}

// generateContainerResources generates platform specific container resources config for runtime
func (m *kubeGenericRuntimeManager) generateContainerResources(_ context.Context, pod *v1.Pod, container *v1.Container) *runtimeapi.ContainerResources {
	return nil
}

// generateUpdatePodSandboxResourcesRequest generates platform specific podsandox resources config for runtime
func (m *kubeGenericRuntimeManager) generateUpdatePodSandboxResourcesRequest(sandboxID string, pod *v1.Pod, podResources *cm.ResourceConfig) *runtimeapi.UpdatePodSandboxResourcesRequest {
	return nil
}

func toKubeContainerResources(statusResources *runtimeapi.ContainerResources) *kubecontainer.ContainerResources {
	return nil
}

func toKubeContainerUser(statusUser *runtimeapi.ContainerUser) *kubecontainer.ContainerUser {
	return nil
}

func (m *kubeGenericRuntimeManager) GetContainerSwapBehavior(pod *v1.Pod, container *v1.Container) types.SwapBehavior {
	return types.NoSwap
}

// initSwapControllerAvailabilityCheck returns a function that always returns false on unsupported platforms
func initSwapControllerAvailabilityCheck(ctx context.Context) func() bool {
	return func() bool { return false }
}
