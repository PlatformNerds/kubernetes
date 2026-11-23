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
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	utilexec "k8s.io/utils/exec"
)

// Growing file systems on FreeBSD. UFS grows while mounted (growfs(8)).
// ext2/3/4 are grown with resize2fs from e2fsprogs, but FreeBSD has no
// online ext resize: resize2fs only works while the file system is not
// mounted, so an online expansion of an ext volume fails with resize2fs's
// error.

// ResizeFs Provides support for resizing file systems
type ResizeFs struct {
	exec utilexec.Interface
}

// NewResizeFs returns new instance of resizer
func NewResizeFs(exec utilexec.Interface) *ResizeFs {
	return &ResizeFs{exec: exec}
}

func (resizefs *ResizeFs) diskFormat(devicePath string) (string, error) {
	m := &SafeFormatAndMount{Exec: resizefs.exec}
	return m.GetDiskFormat(devicePath)
}

// Resize perform resize of file system
func (resizefs *ResizeFs) Resize(devicePath string, deviceMountPath string) (bool, error) {
	format, err := resizefs.diskFormat(devicePath)
	if err != nil {
		return false, fmt.Errorf("ResizeFS.Resize - error checking format for device %s: %v", devicePath, err)
	}
	// If disk has no format, there is no need to resize the disk because
	// the formatter by default will use the whole disk anyways.
	if format == "" {
		return false, nil
	}

	klog.V(3).Infof("ResizeFS.Resize - Expanding mounted volume %s", devicePath)
	switch format {
	case "ufs":
		return resizefs.run(devicePath, "growfs", "-y", devicePath)
	case "ext2", "ext3", "ext4":
		return resizefs.run(devicePath, "resize2fs", devicePath)
	}
	return false, fmt.Errorf("ResizeFS.Resize - resize of format %s is not supported for device %s mounted at %s", format, devicePath, deviceMountPath)
}

func (resizefs *ResizeFs) run(devicePath, cmd string, args ...string) (bool, error) {
	output, err := resizefs.exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("resize of device %s failed: %v. %s output: %s", devicePath, err, cmd, string(output))
	}
	klog.V(2).Infof("Device %s resized successfully", devicePath)
	return true, nil
}

// NeedResize check whether mounted volume needs resize
func (resizefs *ResizeFs) NeedResize(devicePath string, deviceMountPath string) (bool, error) {
	// Do nothing if the file system is mounted read-only.
	if deviceMountPath != "" {
		var st unix.Statfs_t
		if err := unix.Statfs(deviceMountPath, &st); err == nil && st.Flags&unix.MNT_RDONLY != 0 {
			klog.V(3).Infof("ResizeFs.needResize - no resize possible since filesystem %s is readonly", devicePath)
			return false, nil
		}
	}

	format, err := resizefs.diskFormat(devicePath)
	if err != nil {
		return false, fmt.Errorf("ResizeFS.Resize - error checking format for device %s: %v", devicePath, err)
	}
	if format == "" {
		return false, nil
	}

	switch format {
	case "ext2", "ext3", "ext4":
		// As on Linux, let resize2fs do the check.
		return true, nil
	case "ufs":
		deviceSize, err := resizefs.getDeviceSize(devicePath)
		if err != nil {
			return false, err
		}
		blockSize, fsSize, err := resizefs.getUFSSize(devicePath)
		klog.V(5).Infof("UFS size: filesystem size=%d, block size=%d, err=%v", fsSize, blockSize, err)
		if err != nil {
			return false, err
		}
		if deviceSize <= fsSize+blockSize {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("could not parse fs info of given filesystem format: %s. Supported fs types are: ufs, ext2, ext3, ext4", format)
	}
}

// getDeviceSize returns the media size in bytes from diskinfo(8), whose
// third field is the media size.
func (resizefs *ResizeFs) getDeviceSize(devicePath string) (uint64, error) {
	output, err := resizefs.exec.Command("diskinfo", devicePath).CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err != nil {
		return 0, fmt.Errorf("failed to read size of device %s: %s: %s", devicePath, err, outStr)
	}
	fields := strings.Fields(outStr)
	if len(fields) < 3 {
		return 0, fmt.Errorf("failed to parse size of device %s: %q", devicePath, outStr)
	}
	size, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse size of device %s %s: %s", devicePath, outStr, err)
	}
	return size, nil
}

// getUFSSize returns the block size and the size in bytes of the UFS file
// system on devicePath, from the superblock dumpfs(8) prints.
func (resizefs *ResizeFs) getUFSSize(devicePath string) (uint64, uint64, error) {
	output, err := resizefs.exec.Command("dumpfs", devicePath).CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read size of filesystem on %s: %s: %s", devicePath, err, string(output))
	}
	return parseDumpfsSize(string(output))
}

// parseDumpfsSize reads "bsize", "fsize" and the file system "size" (in
// fragments) from dumpfs output. These are key/value pairs on the header
// lines, e.g. "ncg 4 size 16384 blocks 15751".
func parseDumpfsSize(out string) (uint64, uint64, error) {
	vals := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "cs[") || strings.HasPrefix(line, "cg ") {
			break // per-cylinder-group details follow the superblock
		}
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "bsize", "fsize", "size":
				if _, seen := vals[f[i]]; seen {
					continue
				}
				if v, err := strconv.ParseUint(f[i+1], 10, 64); err == nil {
					vals[f[i]] = v
				}
			}
		}
	}
	bsize, fsize, size := vals["bsize"], vals["fsize"], vals["size"]
	if bsize == 0 || fsize == 0 || size == 0 {
		return 0, 0, fmt.Errorf("could not find bsize/fsize/size in dumpfs output")
	}
	return bsize, size * fsize, nil
}
