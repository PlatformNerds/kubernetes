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

package volumepathhandler

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

// FreeBSD has no block devices and no loop devices (md(4) disks are character
// devices), so a file is never attached as one: AttachFileDevice fails, and so
// does mapping a block-mode volume. Tearing one down must still work, or a pod
// whose block volume failed to map can never finish terminating.

// AttachFileDevice takes a path to a regular file and makes it available as an
// attached block device.
func (v VolumePathHandler) AttachFileDevice(path string) (string, error) {
	return "", fmt.Errorf("AttachFileDevice: FreeBSD has no loop (block) devices to attach %s to", path)
}

// DetachFileDevice takes a path to the attached block device and
// detach it from block device.
//
// Nothing can have been attached, so there is nothing to detach: as on Linux
// when no loop device holds the file, skip it.
func (v VolumePathHandler) DetachFileDevice(path string) error {
	klog.V(4).Infof("DetachFileDevice: no loop device on FreeBSD, nothing to detach for %q", path)
	return nil
}

// GetLoopDevice returns the full path to the loop device associated with the given path.
func (v VolumePathHandler) GetLoopDevice(path string) (string, error) {
	return "", errors.New(ErrDeviceNotFound)
}

// FindGlobalMapPathUUIDFromPod finds {pod uuid} bind mount under globalMapPath
// corresponding to map path symlink, and then return global map path with pod uuid.
func (v VolumePathHandler) FindGlobalMapPathUUIDFromPod(pluginDir, mapPath string, podUID types.UID) (string, error) {
	return "", fmt.Errorf("FindGlobalMapPathUUIDFromPod not supported on FreeBSD")
}
