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

package mount

import (
	"reflect"
	"testing"
)

func TestNullfsMountRefs(t *testing.T) {
	mps := []MountPoint{
		{Device: "zroot/ROOT/default", Path: "/", Type: "zfs"},
		{Device: "/var/tmp/lpv", Path: "/var/db/kubelet/pods/a/volumes/kubernetes.io~local-volume/pv", Type: "nullfs"},
		{Device: "/var/tmp/lpv", Path: "/var/db/kubelet/pods/b/volumes/kubernetes.io~local-volume/pv", Type: "nullfs"},
		{Device: "/var/tmp/other", Path: "/var/db/kubelet/pods/c/volumes/kubernetes.io~local-volume/pv2", Type: "nullfs"},
		{Device: "tmpfs", Path: "/var/tmp/lpv", Type: "tmpfs"},
	}
	tests := []struct {
		path string
		want []string
	}{
		// A pod's mount point: the other pod's mount of the same source.
		{"/var/db/kubelet/pods/a/volumes/kubernetes.io~local-volume/pv",
			[]string{"/var/db/kubelet/pods/b/volumes/kubernetes.io~local-volume/pv"}},
		// The source directory: every nullfs mount of it.
		{"/var/tmp/lpv/", []string{
			"/var/db/kubelet/pods/a/volumes/kubernetes.io~local-volume/pv",
			"/var/db/kubelet/pods/b/volumes/kubernetes.io~local-volume/pv"}},
		{"/var/tmp/unused", []string{}},
	}
	for _, tc := range tests {
		if got := nullfsMountRefs(tc.path, mps); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("nullfsMountRefs(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestWithNFSRetryCount(t *testing.T) {
	for _, tc := range []struct {
		fstype  string
		options []string
		want    []string
	}{
		{"nfs", nil, []string{"retrycnt=3"}},
		{"nfs", []string{"vers=4.1"}, []string{"vers=4.1", "retrycnt=3"}},
		{"nfs", []string{"retrycnt=0"}, []string{"retrycnt=0"}},
		{"nullfs", []string{"ro"}, []string{"ro"}},
		{"tmpfs", nil, nil},
	} {
		if got := withNFSRetryCount(tc.fstype, tc.options); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("withNFSRetryCount(%q, %v) = %v, want %v", tc.fstype, tc.options, got, tc.want)
		}
	}
}
