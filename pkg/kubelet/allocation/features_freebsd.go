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

package allocation

import (
	v1 "k8s.io/api/core/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/kubernetes/pkg/features"
)

// IsInPlacePodVerticalScalingAllowed: container resources are rctl rules on
// the container's jail, which the runtime (CRI-O + ocijail `update`) can
// change in place.
func IsInPlacePodVerticalScalingAllowed(pod *v1.Pod) (allowed bool, msg, reason string) {
	if !utilfeature.DefaultFeatureGate.Enabled(features.InPlacePodVerticalScaling) {
		return false, "InPlacePodVerticalScaling is disabled", "feature_gate_off"
	}
	return true, "", ""
}

// IsInPlacePodLevelResourcesVerticalScalingAllowed: pod-level resources are not
// enforced on FreeBSD yet (no pod cgroup; rctl on the pod's parent jail would be
// the equivalent), so they can't be resized either.
func IsInPlacePodLevelResourcesVerticalScalingAllowed(pod *v1.Pod) (allowed bool, msg, reason string) {
	return false, "In-place pod-level resources resize is not supported on FreeBSD", "unsupported_platform"
}
