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

package lifecycle

import (
	"sync"

	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-helpers/resource"
	"k8s.io/kubernetes/pkg/features"
)

// rctlJailHierarchy reports whether rctl rules on a jail are enforced on its
// child jails (kern.features.rctl_jail_hierarchy). Pod-level limits are rctl
// rules on the pod jail, the parent of the container jails; without this the
// runtime doesn't apply them, so pods asking for them aren't admitted.
var rctlJailHierarchy = sync.OnceValue(func() bool {
	v, err := unix.SysctlUint32("kern.features.rctl_jail_hierarchy")
	return err == nil && v == 1
})

func isPodLevelResourcesSupported(pod *v1.Pod) PodAdmitResult {
	return podLevelResourcesAdmit(pod, utilfeature.DefaultFeatureGate.Enabled(features.PodLevelResources), rctlJailHierarchy())
}

func podLevelResourcesAdmit(pod *v1.Pod, gateEnabled, kernelSupport bool) PodAdmitResult {
	if !resource.IsPodLevelResourcesSet(pod) {
		return PodAdmitResult{Admit: true}
	}
	if !gateEnabled {
		return PodAdmitResult{
			Admit:   false,
			Reason:  PodLevelResourcesNotAdmittedReason,
			Message: "PodLevelResources feature gate is disabled",
		}
	}
	if !kernelSupport {
		return PodAdmitResult{
			Admit:   false,
			Reason:  PodLevelResourcesNotAdmittedReason,
			Message: "pod-level resources need a kernel that enforces jail rctl rules on child jails (kern.features.rctl_jail_hierarchy)",
		}
	}
	return PodAdmitResult{Admit: true}
}
