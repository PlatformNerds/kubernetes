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
	"os"
	"path/filepath"
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
		// A pod's mount point: its source, a mount point itself (the
		// kubelet's global mount of a disk), and the other pod's mount of
		// the same source.
		{"/var/db/kubelet/pods/a/volumes/kubernetes.io~local-volume/pv",
			[]string{"/var/tmp/lpv", "/var/db/kubelet/pods/b/volumes/kubernetes.io~local-volume/pv"}},
		// A pod's mount of a plain directory: no source mount point.
		{"/var/db/kubelet/pods/c/volumes/kubernetes.io~local-volume/pv2", []string{}},
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

func TestIsMountPointFromMountTable(t *testing.T) {
	m := New("")
	if isMnt, err := m.IsMountPoint("/"); err != nil || !isMnt {
		t.Errorf("IsMountPoint(/) = %v, %v; want true", isMnt, err)
	}
	dir := t.TempDir()
	if isMnt, err := m.IsMountPoint(dir); err != nil || isMnt {
		t.Errorf("IsMountPoint(%s) = %v, %v; want false", dir, isMnt, err)
	}
	missing := filepath.Join(dir, "missing")
	if _, err := m.IsMountPoint(missing); !os.IsNotExist(err) {
		t.Errorf("IsMountPoint(%s) error = %v; want not exist", missing, err)
	}
	if notMnt, err := m.IsLikelyNotMountPoint(missing); !notMnt || !os.IsNotExist(err) {
		t.Errorf("IsLikelyNotMountPoint(%s) = %v, %v; want true, not exist", missing, notMnt, err)
	}
	if notMnt, err := m.IsLikelyNotMountPoint("/"); notMnt || err != nil {
		t.Errorf("IsLikelyNotMountPoint(/) = %v, %v; want false", notMnt, err)
	}
	if fstype, ok := mountTypeWithoutStat("/"); !ok || fstype == "" {
		t.Errorf("mountTypeWithoutStat(/) = %q, %v", fstype, ok)
	}
	if exists, err := PathExists("/"); err != nil || !exists {
		t.Errorf("PathExists(/) = %v, %v", exists, err)
	}
}
