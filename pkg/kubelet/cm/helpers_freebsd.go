//go:build freebsd

/*
Copyright 2016 The Kubernetes Authors.

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

// FreeBSD has no cgroups, but the kubelet's pod resource arithmetic (CFS-style
// shares and quota, ResourceConfigForPod) is still what the CRI carries to the
// runtime: CRI-O passes it on as OCI linux.resources and ocijail turns that
// into rctl(8) rules. These are the platform-independent parts of
// helpers_linux.go; the cgroupfs-specific functions are stubs, as on other
// non-Linux platforms.

import (
	"math"
	"strconv"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	resourcehelper "k8s.io/component-helpers/resource"
	"k8s.io/klog/v2"
	v1helper "k8s.io/kubernetes/pkg/apis/core/v1/helper"
	v1qos "k8s.io/kubernetes/pkg/apis/core/v1/helper/qos"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
)

// Unified (cgroup v2) keys ResourceConfigForPod sets under MemoryQoS, which
// the kubelet never enables on FreeBSD.
const (
	Cgroup2MemoryMin string = "memory.min"
	Cgroup2MemoryLow string = "memory.low"
)

const (
	// These limits are defined in the kernel:
	// https://github.com/torvalds/linux/blob/0bddd227f3dc55975e2b8dfa7fc6f959b062a2c7/kernel/sched/sched.h#L427-L428
	MinShares = 2
	MaxShares = 262144

	SharesPerCPU  = 1024
	MilliCPUToCPU = 1000

	// 100000 microseconds is equivalent to 100ms
	QuotaPeriod = 100000
	// 1000 microseconds is equivalent to 1ms
	// defined here:
	// https://github.com/torvalds/linux/blob/cac03ac368fabff0122853de2422d4e17a32de08/kernel/sched/core.c#L10546
	MinQuotaPeriod = 1000

	// From the inverse of the conversion in MilliCPUToQuota:
	// MinQuotaPeriod * MilliCPUToCPU / QuotaPeriod
	MinMilliCPULimit = 10
)

// MilliCPUToQuota converts milliCPU to CFS quota and period values.
// Input parameters and resulting value is number of microseconds.
func MilliCPUToQuota(milliCPU int64, period int64) (quota int64) {
	// CFS quota is measured in two values:
	//  - cfs_period_us=100ms (the amount of time to measure usage across given by period)
	//  - cfs_quota=20ms (the amount of cpu time allowed to be used across a period)
	// so in the above example, you are limited to 20% of a single CPU
	// for multi-cpu environments, you just scale equivalent amounts
	// see https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt for details

	if milliCPU == 0 {
		return
	}

	if !utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUCFSQuotaPeriod) {
		period = QuotaPeriod
	}

	// we then convert your milliCPU to a value normalized over a period
	quota = (milliCPU * period) / MilliCPUToCPU

	// quota needs to be a minimum of 1ms.
	if quota < MinQuotaPeriod {
		quota = MinQuotaPeriod
	}
	return
}

// MilliCPUToShares converts the milliCPU to CFS shares.
func MilliCPUToShares(milliCPU int64) uint64 {
	if milliCPU == 0 {
		// Docker converts zero milliCPU to unset, which maps to kernel default
		// for unset: 1024. Return 2 here to really match kernel default for
		// zero milliCPU.
		return MinShares
	}
	// Conceptually (milliCPU / milliCPUToCPU) * sharesPerCPU, but factored to improve rounding.
	shares := (milliCPU * SharesPerCPU) / MilliCPUToCPU
	if shares < MinShares {
		return MinShares
	}
	if shares > MaxShares {
		return MaxShares
	}
	return uint64(shares)
}

// HugePageLimits converts the API representation to a map
// from huge page size (in bytes) to huge page limit (in bytes).
func HugePageLimits(resourceList v1.ResourceList) map[int64]int64 {
	hugePageLimits := map[int64]int64{}
	for k, v := range resourceList {
		if v1helper.IsHugePageResourceName(k) {
			pageSize, _ := v1helper.HugePageSizeFromResourceName(k)
			if value, exists := hugePageLimits[pageSize.Value()]; exists {
				hugePageLimits[pageSize.Value()] = value + v.Value()
			} else {
				hugePageLimits[pageSize.Value()] = v.Value()
			}
		}
	}
	return hugePageLimits
}

// ResourceConfigForPod takes the input pod and outputs the cgroup resource config.
func ResourceConfigForPod(allocatedPod *v1.Pod, enforceCPULimits bool, cpuPeriod uint64, enforceMemoryQoS bool, memoryReservationPolicy kubeletconfig.MemoryReservationPolicy) *ResourceConfig {
	podLevelResourcesEnabled := utilfeature.DefaultFeatureGate.Enabled(kubefeatures.PodLevelResources)
	// sum requests and limits.
	reqs := resourcehelper.PodRequests(allocatedPod, resourcehelper.PodResourcesOptions{
		// SkipPodLevelResources is set to false when PodLevelResources feature is enabled.
		SkipPodLevelResources: !podLevelResourcesEnabled,
		UseStatusResources:    false,
	})
	// track if limits were applied for each resource.
	memoryLimitsDeclared := true
	cpuLimitsDeclared := true

	limits := resourcehelper.PodLimits(allocatedPod, resourcehelper.PodResourcesOptions{
		// SkipPodLevelResources is set to false when PodLevelResources feature is enabled.
		SkipPodLevelResources: !podLevelResourcesEnabled,
		ContainerFn: func(res v1.ResourceList, containerType resourcehelper.ContainerType) {
			if res.Cpu().IsZero() {
				cpuLimitsDeclared = false
			}
			if res.Memory().IsZero() {
				memoryLimitsDeclared = false
			}
		},
	})

	if podLevelResourcesEnabled && resourcehelper.IsPodLevelResourcesSet(allocatedPod) {
		if !allocatedPod.Spec.Resources.Limits.Cpu().IsZero() {
			cpuLimitsDeclared = true
		}

		if !allocatedPod.Spec.Resources.Limits.Memory().IsZero() {
			memoryLimitsDeclared = true
		}
	}
	// map hugepage pagesize (bytes) to limits (bytes)
	hugePageLimits := HugePageLimits(reqs)

	cpuRequests := int64(0)
	cpuLimits := int64(0)
	memoryLimits := int64(0)
	if request, found := reqs[v1.ResourceCPU]; found {
		cpuRequests = request.MilliValue()
	}
	if limit, found := limits[v1.ResourceCPU]; found {
		cpuLimits = limit.MilliValue()
	}
	if limit, found := limits[v1.ResourceMemory]; found {
		memoryLimits = limit.Value()
	}

	// convert to CFS values
	cpuShares := MilliCPUToShares(cpuRequests)
	cpuQuota := MilliCPUToQuota(cpuLimits, int64(cpuPeriod))

	// quota is not capped when cfs quota is disabled
	if !enforceCPULimits {
		cpuQuota = int64(-1)
	}

	// determine the qos class
	qosClass := v1qos.GetPodQOS(allocatedPod)

	// build the result
	result := &ResourceConfig{}
	if qosClass == v1.PodQOSGuaranteed {
		result.CPUShares = &cpuShares
		result.CPUQuota = &cpuQuota
		result.CPUPeriod = &cpuPeriod
		result.Memory = &memoryLimits
	} else if qosClass == v1.PodQOSBurstable {
		result.CPUShares = &cpuShares
		if cpuLimitsDeclared {
			result.CPUQuota = &cpuQuota
			result.CPUPeriod = &cpuPeriod
		}
		if memoryLimitsDeclared {
			result.Memory = &memoryLimits
		}
	} else {
		shares := uint64(MinShares)
		result.CPUShares = &shares
	}
	result.HugePageLimit = hugePageLimits

	if enforceMemoryQoS && memoryReservationPolicy == kubeletconfig.TieredReservationMemoryReservationPolicy {
		memoryRequest := int64(0)
		if request, found := reqs[v1.ResourceMemory]; found {
			memoryRequest = request.Value()
		}
		if memoryRequest > 0 {
			// Guaranteed pods get memory.min (hard protection, kernel never reclaims).
			// Burstable pods get memory.low (soft protection, kernel prefers not to reclaim).
			cgroupKey := Cgroup2MemoryLow
			if qosClass == v1.PodQOSGuaranteed {
				cgroupKey = Cgroup2MemoryMin
			}
			result.Unified = map[string]string{
				cgroupKey: strconv.FormatInt(memoryRequest, 10),
			}
		}
	}

	return result
}

// GetCgroupSubsystems returns information about the mounted cgroup subsystems
func GetCgroupSubsystems() (*CgroupSubsystems, error) {
	return nil, nil
}

func getCgroupProcs(dir string) ([]int, error) {
	return nil, nil
}

// GetPodCgroupNameSuffix returns the last element of the pod CgroupName identifier
func GetPodCgroupNameSuffix(podUID types.UID) string {
	return ""
}

// NodeAllocatableRoot returns the literal cgroup path for the node allocatable cgroup
func NodeAllocatableRoot(cgroupRoot string, cgroupsPerQOS bool, cgroupDriver string) string {
	return ""
}

// GetKubeletContainer returns the cgroup the kubelet will use
func GetKubeletContainer(logger klog.Logger, kubeletCgroups string) (string, error) {
	return "", nil
}

func CPURequestsFromConfig(podConfig *ResourceConfig) *resource.Quantity {
	var cpuRequest *resource.Quantity
	if podConfig != nil && *podConfig.CPUShares > 0 {
		milliCPU := SharesToMilliCPU(int64(*podConfig.CPUShares))
		if milliCPU > 0 {
			cpuRequest = resource.NewMilliQuantity(milliCPU, resource.DecimalSI)
		}
	}

	return cpuRequest
}

func CPULimitsFromConfig(podConfig *ResourceConfig) *resource.Quantity {
	var cpuLimit *resource.Quantity

	if podConfig != nil && *podConfig.CPUPeriod > 0 {
		milliCPU := QuotaToMilliCPU(*podConfig.CPUQuota, int64(*podConfig.CPUPeriod))
		if milliCPU > 0 {
			cpuLimit = resource.NewMilliQuantity(milliCPU, resource.DecimalSI)
		}
	}

	return cpuLimit
}

func MemoryLimitsFromConfig(podConfig *ResourceConfig) *resource.Quantity {
	var memLimit *resource.Quantity

	if podConfig != nil && *podConfig.Memory > int64(0) {
		memLimit = resource.NewQuantity(*podConfig.Memory, resource.BinarySI)
	}
	return memLimit
}

// SharesToMilliCPU converts CpuShares (cpu.shares) to milli-CPU value
func SharesToMilliCPU(shares int64) int64 {
	milliCPU := int64(0)
	if shares >= int64(MinShares) {
		milliCPU = int64(math.Ceil(float64(shares*MilliCPUToCPU) / float64(SharesPerCPU)))
	}
	return milliCPU
}

// QuotaToMilliCPU converts cpu.cfs_quota_us and cpu.cfs_period_us to milli-CPU value
func QuotaToMilliCPU(quota int64, period int64) int64 {
	if quota == -1 {
		return int64(0)
	}
	return (quota * MilliCPUToCPU) / period
}
