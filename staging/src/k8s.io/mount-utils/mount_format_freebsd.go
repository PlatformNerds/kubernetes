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
	"strings"
	"time"

	"k8s.io/klog/v2"
	utilexec "k8s.io/utils/exec"
)

// Formatting disks on FreeBSD. The commands are the Linux ones where FreeBSD
// has them (blkid, mkfs.ext4 and e2fsck come with e2fsprogs), so a volume
// formatted on one OS mounts on the other. ext2/3/4 are mounted with FreeBSD's
// ext2fs, which handles all three; UFS is formatted with newfs.

const (
	fsckErrorsCorrected   = 1
	fsckErrorsUncorrected = 4
)

// freeBSDFSType maps a volume's fsType to the type mount(8) knows.
func freeBSDFSType(fstype string) string {
	switch fstype {
	case "ext2", "ext3", "ext4":
		return "ext2fs"
	}
	return fstype
}

func isExtFS(fstype string) bool {
	return fstype == "ext2" || fstype == "ext3" || fstype == "ext4"
}

// formatAndMountSensitive formats source if it has no file system (as Linux
// does; the default is ext4), checks it if it has one, and mounts it.
func (mounter *SafeFormatAndMount) formatAndMountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string, formatOptions []string) error {
	readOnly := false
	for _, o := range append(append([]string(nil), options...), sensitiveOptions...) {
		if o == "ro" {
			readOnly = true
		}
	}
	mountErrorValue := UnknownMountError

	existingFormat, err := mounter.GetDiskFormat(source)
	if err != nil {
		return NewMountError(GetDiskFormatFailed, "failed to get disk format of disk %s: %v", source, err)
	}
	if fstype == "" {
		fstype = "ext4"
	}

	if existingFormat == "" {
		if readOnly {
			return NewMountError(UnformattedReadOnly, "cannot mount unformatted disk %s as we are manipulating it in read-only mode", source)
		}
		cmd, args := formatCommand(fstype, source)
		args = append(formatOptions, args...)
		klog.Infof("Disk %q appears to be unformatted, attempting to format as type: %q with options: %v", source, fstype, args)
		output, err := mounter.format(cmd, args)
		if err != nil {
			sensitiveOptionsLog := sanitizedOptionsForLogging(options, sensitiveOptions)
			detailedErr := fmt.Sprintf("format of disk %q failed: type:(%q) target:(%q) options:(%q) errcode:(%v) output:(%v) ", source, fstype, target, sensitiveOptionsLog, err, string(output))
			klog.Error(detailedErr)
			return NewMountError(FormatFailed, "%s", detailedErr)
		}
		klog.Infof("Disk successfully formatted (%s): %s - %s %s", cmd, fstype, source, target)
	} else {
		if fstype != existingFormat {
			mountErrorValue = FilesystemMismatch
			klog.Warningf("Configured to mount disk %s as %s but current format is %s, things might break", source, fstype, existingFormat)
		}
		if !readOnly {
			if err := mounter.checkAndRepairFilesystem(source, existingFormat); err != nil {
				return err
			}
		}
	}

	klog.V(4).Infof("Attempting to mount disk %s in %s format at %s", source, fstype, target)
	if err := mounter.MountSensitive(source, target, fstype, options, sensitiveOptions); err != nil {
		return NewMountError(mountErrorValue, "%s", err.Error())
	}
	return nil
}

// formatCommand returns the command that makes a file system of fstype.
func formatCommand(fstype, source string) (string, []string) {
	switch {
	case isExtFS(fstype):
		return "mkfs." + fstype, []string{"-F", "-m0", source}
	case fstype == "ufs":
		return "newfs", []string{"-U", source}
	}
	return "mkfs." + fstype, []string{source}
}

func (mounter *SafeFormatAndMount) format(cmd string, args []string) ([]byte, error) {
	if mounter.formatSem != nil {
		done := make(chan struct{})
		defer close(done)
		mounter.formatSem <- struct{}{}
		go func() {
			defer func() { <-mounter.formatSem }()
			timeout := time.NewTimer(mounter.formatTimeout)
			defer timeout.Stop()
			select {
			case <-done:
			case <-timeout.C:
			}
		}()
	}
	return mounter.Exec.Command(cmd, args...).CombinedOutput()
}

// checkAndRepairFilesystem runs the file system's own checker in preen mode
// (FreeBSD's fsck(8) picks the checker from /etc/fstab, not from the disk).
func (mounter *SafeFormatAndMount) checkAndRepairFilesystem(source, fstype string) error {
	var cmd string
	switch {
	case isExtFS(fstype):
		cmd = "e2fsck"
	case fstype == "ufs":
		cmd = "fsck_ufs"
	default:
		return nil
	}
	klog.V(4).Infof("Checking for issues with %s on disk: %s", cmd, source)
	out, err := mounter.Exec.Command(cmd, "-p", source).CombinedOutput()
	if err != nil {
		ee, isExitError := err.(utilexec.ExitError)
		switch {
		case err == utilexec.ErrExecutableNotFound:
			klog.Warningf("%q not found on system; continuing mount without checking the file system.", cmd)
		case isExitError && ee.ExitStatus() == fsckErrorsCorrected:
			klog.Infof("Device %s has errors which were corrected by %s.", source, cmd)
		case isExitError && ee.ExitStatus() == fsckErrorsUncorrected:
			return NewMountError(HasFilesystemErrors, "%q found errors on device %s but could not correct them: %s", cmd, source, string(out))
		case isExitError && ee.ExitStatus() > fsckErrorsUncorrected:
			klog.Infof("%q error %s", cmd, string(out))
		default:
			klog.Warningf("%s on device %s failed with error %v, output: %v", cmd, source, err, string(out))
		}
	}
	return nil
}

// GetDiskFormat uses blkid (e2fsprogs) to see if the given disk is
// unformatted. It returns "" for an unformatted disk.
func (mounter *SafeFormatAndMount) GetDiskFormat(disk string) (string, error) {
	args := []string{"-p", "-s", "TYPE", "-s", "PTTYPE", "-o", "export", disk}
	dataOut, err := mounter.Exec.Command("blkid", args...).CombinedOutput()
	output := string(dataOut)
	if err != nil {
		if exit, ok := err.(utilexec.ExitError); ok && exit.ExitStatus() == 2 {
			return "", nil
		}
		klog.Errorf("Could not determine if disk %q is formatted (%v)", disk, err)
		return "", err
	}
	var fstype, pttype string
	for _, l := range strings.Split(output, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "TYPE":
			fstype = v
		case "PTTYPE":
			pttype = v
		}
	}
	if pttype != "" {
		return "unknown data, probably partitions", nil
	}
	return fstype, nil
}

func (mounter *SafeFormatAndMount) diskLooksUnformatted(disk string) (bool, error) {
	format, err := mounter.GetDiskFormat(disk)
	return format == "", err
}
