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
	"testing"

	v1 "k8s.io/api/core/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
)

func TestFreeBSDPodLevelResourcesAdmit(t *testing.T) {
	plain := &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{Name: "c"}}}}
	podLevel := &v1.Pod{Spec: v1.PodSpec{
		Resources:  &v1.ResourceRequirements{Limits: v1.ResourceList{v1.ResourceMemory: apiresource.MustParse("200Mi")}},
		Containers: []v1.Container{{Name: "c"}},
	}}
	for _, tc := range []struct {
		name         string
		pod          *v1.Pod
		gate, kernel bool
		want         bool
	}{
		{"no pod-level resources, old kernel", plain, true, false, true},
		{"pod-level resources, kernel support", podLevel, true, true, true},
		{"pod-level resources, old kernel", podLevel, true, false, false},
		{"pod-level resources, gate off", podLevel, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := podLevelResourcesAdmit(tc.pod, tc.gate, tc.kernel); got.Admit != tc.want {
				t.Errorf("admit = %v (%s), want %v", got.Admit, got.Message, tc.want)
			}
		})
	}
}
