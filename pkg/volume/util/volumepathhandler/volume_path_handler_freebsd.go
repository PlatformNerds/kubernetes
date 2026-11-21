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
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
)

// Block volumes on FreeBSD. Disks (md(4), da(4), nvd(4), ...) are character
// devices in devfs; FreeBSD has no block devices. Linux keeps, per pod, a
// bind mount of the device below the volume's global map path, and counts
// those to know when the device is no longer used. nullfs can't mount a
// device node, so on FreeBSD these are symbolic links to the device, like
// the per-pod links Linux already uses, and the references are the links
// that lead to a device.
//
// Linux also attaches a loop device to the global map path, as a lock that
// keeps the device from being removed while it is mapped. FreeBSD's md(4)
// can't stack on a device, and an open device is busy anyway: there is no
// lock to take.
const deviceBindMounts = false

// isDeviceSymlink reports whether path is a symbolic link to a device.
func isDeviceSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to Lstat file %s: %v", path, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}
	target, err := os.Stat(path)
	if err != nil {
		// A dangling link (the device is gone) still refers to it.
		return true, nil
	}
	return target.Mode()&os.ModeDevice != 0, nil
}

// AttachFileDevice: see above. A device needs no attaching; a regular file
// can't be attached (md(4) could, but nothing on FreeBSD asks for it).
func (v VolumePathHandler) AttachFileDevice(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("AttachFileDevice: %v", err)
	}
	if fi.Mode()&os.ModeDevice == 0 {
		return "", fmt.Errorf("AttachFileDevice: %s is not a device, and FreeBSD has no loop devices", path)
	}
	klog.V(4).Infof("AttachFileDevice: %s is a device, nothing to attach on FreeBSD", path)
	return "", nil
}

// DetachFileDevice: nothing was attached.
func (v VolumePathHandler) DetachFileDevice(path string) error {
	klog.V(4).Infof("DetachFileDevice: no loop device on FreeBSD, nothing to detach for %q", path)
	return nil
}

// GetLoopDevice returns the full path to the loop device associated with the given path.
func (v VolumePathHandler) GetLoopDevice(path string) (string, error) {
	return "", errors.New(ErrDeviceNotFound)
}

// FindGlobalMapPathUUIDFromPod finds the {pod uuid} link below pluginDir that
// leads to the same device as the pod's link mapPath, and returns it.
func (v VolumePathHandler) FindGlobalMapPathUUIDFromPod(pluginDir, mapPath string, podUID types.UID) (string, error) {
	podDev, err := filepath.EvalSymlinks(mapPath)
	if err != nil {
		return "", fmt.Errorf("FindGlobalMapPathUUIDFromPod: %v", err)
	}
	var globalMapPathUUID string
	err = filepath.Walk(pluginDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 && fi.Name() == string(podUID) {
			if dev, err := filepath.EvalSymlinks(path); err == nil && dev == podDev {
				globalMapPathUUID = path
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("FindGlobalMapPathUUIDFromPod failed: %v", err)
	}
	klog.V(5).Infof("FindGlobalMapPathFromPod: globalMapPathUUID %s", globalMapPathUUID)
	return globalMapPathUUID, nil
}
