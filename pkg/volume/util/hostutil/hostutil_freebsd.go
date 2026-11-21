//go:build freebsd

/*
Copyright 2017 The Kubernetes Authors.

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

package hostutil

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"k8s.io/mount-utils"
	utilpath "k8s.io/utils/path"
)

// HostUtil implements HostUtils for Windows platforms.
type HostUtil struct{}

// NewHostUtil returns a struct that implements HostUtils on Windows platforms
func NewHostUtil() *HostUtil {
	return &HostUtil{}
}

// GetDeviceNameFromMount given a mnt point, find the device
func (hu *HostUtil) GetDeviceNameFromMount(mounter mount.Interface, mountPath, pluginMountDir string) (string, error) {
	return getDeviceNameFromMount(mounter, mountPath, pluginMountDir)
}

// getDeviceNameFromMount find the device(drive) name in which
// the mount path reference should match the given plugin mount directory. In case no mount path reference
// matches, returns the volume name taken from its given mountPath
func getDeviceNameFromMount(mounter mount.Interface, mountPath, pluginMountDir string) (string, error) {
	refs, err := mounter.GetMountRefs(mountPath)
	if err != nil {
		klog.V(4).Infof("GetMountRefs failed for mount path %q: %v", mountPath, err)
		return "", err
	}
	if len(refs) == 0 {
		return "", fmt.Errorf("directory %s is not mounted", mountPath)
	}
	basemountPath := pluginMountDir
	for _, ref := range refs {
		if strings.Contains(ref, basemountPath) {
			volumeID, err := filepath.Rel(basemountPath, ref)
			if err != nil {
				klog.Errorf("Failed to get volume id from mount %s - %v", mountPath, err)
				return "", err
			}
			return volumeID, nil
		}
	}

	return path.Base(mountPath), nil
}

// DeviceOpened determines if the device is in use elsewhere
func (hu *HostUtil) DeviceOpened(pathname string) (bool, error) {
	return false, nil
}

// PathIsDevice determines if a path is a block device (see GetFileType).
func (hu *HostUtil) PathIsDevice(pathname string) (bool, error) {
	t, err := hu.GetFileType(pathname)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return t == FileTypeBlockDev, nil
}

// MakeRShared checks that given path is on a mount with 'rshared' mount
// propagation. Empty implementation here.
func (hu *HostUtil) MakeRShared(path string) error {
	return nil
}

// GetFileType checks for sockets/block/character devices.
//
// FreeBSD has no block devices: disks are character devices in devfs. What
// Linux calls a block device is a disk, so a character device that is a
// GEOM provider (a disk, a partition, a label, an md(4) or a ZFS volume) is
// a BlockDevice here, and HostPathType BlockDevice, local block volumes and
// block-mode volumes work with them.
func (hu *(HostUtil)) GetFileType(pathname string) (FileType, error) {
	t, err := getFileType(pathname)
	if err != nil || t != FileTypeCharDev {
		return t, err
	}
	if isGEOMProvider(pathname) {
		return FileTypeBlockDev, nil
	}
	return t, nil
}

// isGEOMProvider reports whether pathname is a GEOM provider's device in a
// devfs. It reads the GEOM configuration; it doesn't open the device.
func isGEOMProvider(pathname string) bool {
	resolved, err := filepath.EvalSymlinks(pathname)
	if err != nil {
		return false
	}
	var st unix.Statfs_t
	if err := unix.Statfs(resolved, &st); err != nil || unix.ByteSliceToString(st.Fstypename[:]) != "devfs" {
		return false
	}
	name, err := filepath.Rel(unix.ByteSliceToString(st.Mntonname[:]), resolved)
	if err != nil {
		return false
	}
	conf, err := unix.Sysctl("kern.geom.conftxt")
	if err != nil {
		return false
	}
	return geomProviderListed(conf, name)
}

// geomProviderListed reports whether kern.geom.conftxt lists a provider
// called name ("<depth> <class> <name> <mediasize> ...").
func geomProviderListed(conftxt, name string) bool {
	for _, line := range strings.Split(conftxt, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == name {
			return true
		}
	}
	return false
}

// PathExists checks whether the path exists
func (hu *HostUtil) PathExists(pathname string) (bool, error) {
	return utilpath.Exists(utilpath.CheckFollowSymlink, pathname)
}

// EvalHostSymlinks returns the path name after evaluating symlinks
func (hu *HostUtil) EvalHostSymlinks(pathname string) (string, error) {
	return filepath.EvalSymlinks(pathname)
}

// GetOwner returns the integer ID for the user and group of the given path
// Note that on windows, it always returns 0. We actually don't set Group on
// windows platform, see SetVolumeOwnership implementation.
func (hu *HostUtil) GetOwner(pathname string) (int64, int64, error) {
	return -1, -1, nil
}

// GetSELinuxSupport returns a boolean indicating support for SELinux.
// Windows does not support SELinux.
func (hu *HostUtil) GetSELinuxSupport(pathname string) (bool, error) {
	return false, nil
}

// GetMode returns permissions of the path.
func (hu *HostUtil) GetMode(pathname string) (os.FileMode, error) {
	info, err := os.Stat(pathname)
	if err != nil {
		return 0, err
	}
	return info.Mode(), nil
}

// GetSELinuxMountContext returns value of -o context=XYZ mount option on
// given mount point.
func (hu *HostUtil) GetSELinuxMountContext(pathname string) (string, error) {
	return "", nil
}
