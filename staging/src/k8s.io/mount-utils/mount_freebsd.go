//go:build freebsd

/*
Copyright 2014 The Kubernetes Authors.

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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// Mounter implements mount.Interface for unsupported platforms
type Mounter struct {
	mounterPath string
}

func isBindMount(options []string) bool {
	for _, option := range options {
		if option == "bind" {
			return true
		}
	}
	return false
}

// New returns a mount.Interface for the current system.
// It provides options to override the default mounter behavior.
// mounterPath allows using an alternative to `/bin/mount` for mounting.
func New(mounterPath string) Interface {
	return &Mounter{
		mounterPath: mounterPath,
	}
}

func (mounter *Mounter) Mount(source string, target string, fstype string, options []string) error {
	return mounter.MountSensitive(source, target, fstype, options, nil /* sensitiveOptions */)
}

func (mounter *Mounter) MountSensitiveWithoutSystemd(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return mounter.MountSensitive(source, target, fstype, options, sensitiveOptions /* sensitiveOptions */)
}

func (mounter *Mounter) MountSensitiveWithoutSystemdWithMountFlags(source string, target string, fstype string, options []string, sensitiveOptions []string, mountFlags []string) error {
	return mounter.MountSensitive(source, target, fstype, options, sensitiveOptions /* sensitiveOptions */)
}

func (mounter *Mounter) MountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	if socket := mountProxySocket(); socket != "" {
		return mountThroughProxy(socket, source, target, fstype, append(append([]string(nil), options...), sensitiveOptions...))
	}
	if isBindMount(options) {
		fstype = "nullfs"
	}
	mountCmd := defaultMountCommand
	if mounter.mounterPath != "" {
		mountCmd = mounter.mounterPath
	}
	return mounter.doMount(mountCmd, source, target, fstype, options, sensitiveOptions, nil /* mountFlags */)
}

// Unmount unmounts target with umount(8).
func (mounter *Mounter) Unmount(target string) error {
	if socket := mountProxySocket(); socket != "" {
		return unmountThroughProxy(socket, target)
	}
	klog.V(4).Infof("Unmounting %s", target)
	command := exec.Command("umount", "-f", target)
	output, err := command.CombinedOutput()
	if err != nil {
		return checkUmountError(target, command, output, err)
	}
	return nil
}

// List returns the mounted file systems, from getfsstat(2).
func (mounter *Mounter) List() ([]MountPoint, error) {
	if socket := mountProxySocket(); socket != "" {
		return listThroughProxy(socket)
	}
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	mounts := make([]unix.Statfs_t, count)
	count, err = unix.Getfsstat(mounts, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}

	res := make([]MountPoint, 0, count)
	for _, entry := range mounts {
		res = append(res, MountPoint{
			Device: unix.ByteSliceToString(entry.Mntfromname[:]),
			Path:   unix.ByteSliceToString(entry.Mntonname[:]),
			Type:   unix.ByteSliceToString(entry.Fstypename[:]),
		})
	}

	return res, nil
}

// IsLikelyNotMountPoint reports true with the error when file can't be
// checked, a missing path included, as Linux does: callers such as the CSI
// plugin's isDirMounted accept os.IsNotExist and use the boolean, and false
// there meant "mounted", so the volume directory was never removed.
func (mounter *Mounter) IsLikelyNotMountPoint(file string) (bool, error) {
	isMountPoint, err := mounter.IsMountPoint(file)
	if err != nil {
		return true, err
	}
	return !isMountPoint, nil
}

// CanSafelySkipMountPointCheck always returns false on unsupported platforms
func (mounter *Mounter) CanSafelySkipMountPointCheck() bool {
	return false
}

// IsMountPoint determines if a directory is a mountpoint, from the mount table
// (getfsstat(2) without MNT_WAIT) rather than statfs(2) on the path: for an NFS
// mount whose server is gone, statfs(2) and stat(2) on the mount point block
// for good, and the kubelet could never tear the volume down. Only the parent
// directory's symbolic links are resolved; the last component is the mount
// point itself.
func (mounter *Mounter) IsMountPoint(file string) (bool, error) {
	path, err := mountPointPath(file)
	if err != nil {
		return false, err
	}
	mps, err := mounter.List()
	if err != nil {
		return false, err
	}
	for _, mp := range mps {
		if mp.Path == path {
			return true, nil
		}
	}
	// Not a mount point, so lstat(2) can't block on one; report a missing
	// path like Linux does.
	if _, err := os.Lstat(path); err != nil {
		return false, err
	}
	return false, nil
}

// mountPointPath returns file as an absolute path with the symbolic links of
// its parent directory resolved, without looking at file itself.
func mountPointPath(file string) (string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	if abs == "/" {
		return abs, nil
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// mountTypeWithoutStat returns the file system type mounted at path, if path is
// a mount point, from the mount table only (see IsMountPoint).
func mountTypeWithoutStat(path string) (string, bool) {
	p, err := mountPointPath(path)
	if err != nil {
		return "", false
	}
	mps, err := (&Mounter{}).List()
	if err != nil {
		return "", false
	}
	for _, mp := range mps {
		if mp.Path == p {
			return mp.Type, true
		}
	}
	return "", false
}

// UnmountWithForce unmounts target. An NFS mount that isn't off after
// umountTimeout - its server is gone, and umount(8) blocks looking the path up
// - is dismounted with "umount -N", which cancels the outstanding RPCs without
// a lookup of the path (also releasing the blocked umount). Other file systems
// are unmounted as by Unmount.
func (mounter *Mounter) UnmountWithForce(target string, umountTimeout time.Duration) error {
	if fstype, _ := mountTypeWithoutStat(target); fstype != "nfs" {
		return mounter.Unmount(target)
	}
	klog.V(4).Infof("Unmounting %s", target)
	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	command := exec.Command("umount", target)
	go func() {
		output, err := command.CombinedOutput()
		done <- result{output, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return checkUmountError(target, command, r.output, r.err)
		}
		return nil
	case <-time.After(umountTimeout):
	}
	klog.V(2).Infof("Timed out waiting for unmount of %s, dismounting it with umount -N", target)
	force := exec.Command("umount", "-N", target)
	if output, err := force.CombinedOutput(); err != nil {
		return checkUmountError(target, force, output, err)
	}
	return nil
}

// GetMountRefs finds the other mount points of the directory pathname is, or
// is mounted from. FreeBSD's bind mounts are nullfs mounts, whose source
// (f_mntfromname) is the directory they show, so the references are the nullfs
// mounts that share pathname's source. Like Linux, pathname itself is left out.
// The local volume plugin uses this to see whether another pod already uses a
// volume before it applies fsGroup.
func (mounter *Mounter) GetMountRefs(pathname string) ([]string, error) {
	pathExists, pathErr := PathExists(pathname)
	if !pathExists {
		return []string{}, nil
	} else if IsCorruptedMnt(pathErr) {
		klog.Warningf("GetMountRefs found corrupted mount at %s, treating as unmounted path", pathname)
		return []string{}, nil
	} else if pathErr != nil {
		return nil, fmt.Errorf("error checking path %s: %v", pathname, pathErr)
	}
	realpath, err := filepath.EvalSymlinks(pathname)
	if err != nil {
		return nil, err
	}
	mps, err := mounter.List()
	if err != nil {
		return nil, err
	}
	return nullfsMountRefs(realpath, mps), nil
}

// nullfsMountRefs returns the nullfs mount points showing the same directory
// as path, other than path: path's own source if path is a nullfs mount point,
// otherwise path itself.
func nullfsMountRefs(path string, mps []MountPoint) []string {
	path = filepath.Clean(path)
	source := path
	for _, mp := range mps {
		if mp.Type == "nullfs" && filepath.Clean(mp.Path) == path {
			source = filepath.Clean(mp.Device)
		}
	}
	refs := []string{}
	for _, mp := range mps {
		p := filepath.Clean(mp.Path)
		if mp.Type == "nullfs" && filepath.Clean(mp.Device) == source && p != path {
			refs = append(refs, p)
		}
	}
	return refs
}

// SafeFormatAndMount has no IsMountPoint of its own (as on Linux): the embedded
// Interface's applies. A stub here that always failed used to shadow it.

// doMount runs the mount command. sensitiveOptions is an extension of options
// except they will not be logged (because they may contain sensitive material)
// systemdMountRequired is an extension of option to decide whether uses systemd
// mount.
func (mounter *Mounter) doMount(mountCmd string, source string, target string, fstype string, options []string, sensitiveOptions []string, mountFlags []string) error {
	options = withNFSRetryCount(fstype, options)
	fstype = freeBSDFSType(fstype)
	mountArgs, mountArgsLogStr := MakeMountArgsSensitiveWithMountFlags(source, target, fstype, options, sensitiveOptions, mountFlags)

	// Logging with sensitive mount options removed.
	klog.V(4).Infof("Mounting cmd (%s) with arguments (%s)", mountCmd, mountArgsLogStr)
	command := exec.Command(mountCmd, mountArgs...)
	output, err := command.CombinedOutput()
	if err != nil {
		klog.Errorf("Mount failed: %v\nMounting command: %s\nMounting arguments: %s\nOutput: %s\n", err, mountCmd, mountArgsLogStr, string(output))
		return fmt.Errorf("mount failed: %v\nMounting command: %s\nMounting arguments: %s\nOutput: %s",
			err, mountCmd, mountArgsLogStr, string(output))
	}
	return err
}

// nfsRetryCount bounds how often mount_nfs(8) tries an NFS server that doesn't
// answer. mount_nfs retries forever by default, a minute apart, so the mount
// would never return: the volume's operation stays pending, and its pod can
// neither start nor be torn down. Linux's mount.nfs gives up after two minutes
// in the foreground; three attempts a minute apart take as long.
const nfsRetryCount = "retrycnt=3"

// withNFSRetryCount adds nfsRetryCount to the options of an NFS mount that
// doesn't set a retry count itself.
func withNFSRetryCount(fstype string, options []string) []string {
	if fstype != "nfs" {
		return options
	}
	for _, o := range options {
		if strings.HasPrefix(o, "retrycnt=") {
			return options
		}
	}
	return append(append([]string(nil), options...), nfsRetryCount)
}

// MakeMountArgsSensitive makes the arguments to the mount(8) command.
// sensitiveOptions is an extension of options except they will not be logged (because they may contain sensitive material)
func MakeMountArgsSensitive(source, target, fstype string, options []string, sensitiveOptions []string) (mountArgs []string, mountArgsLogStr string) {
	return MakeMountArgsSensitiveWithMountFlags(source, target, fstype, options, sensitiveOptions, nil /* mountFlags */)
}

// MakeMountArgsSensitiveWithMountFlags makes the arguments to the mount(8) command.
// sensitiveOptions is an extension of options except they will not be logged (because they may contain sensitive material)
// mountFlags are additional mount flags that are not related with the fstype
// and mount options
func MakeMountArgsSensitiveWithMountFlags(source, target, fstype string, options []string, sensitiveOptions []string, mountFlags []string) (mountArgs []string, mountArgsLogStr string) {
	// Build mount command as follows:
	//   mount [$mountFlags] [-t $fstype] [-o $options] [$source] $target
	mountArgs = []string{}
	mountArgsLogStr = ""

	mountArgs = append(mountArgs, mountFlags...)
	mountArgsLogStr += strings.Join(mountFlags, " ")

	if len(fstype) > 0 {
		mountArgs = append(mountArgs, "-t", fstype)
		mountArgsLogStr += strings.Join(mountArgs, " ")
	}
	if len(options) > 0 || len(sensitiveOptions) > 0 {
		combinedOptions := []string{}
		combinedOptions = append(combinedOptions, options...)
		combinedOptions = append(combinedOptions, sensitiveOptions...)
		mountArgs = append(mountArgs, "-o", strings.Join(combinedOptions, ","))
		// exclude sensitiveOptions from log string
		mountArgsLogStr += " -o " + sanitizedOptionsForLogging(options, sensitiveOptions)
	}
	if len(source) > 0 {
		mountArgs = append(mountArgs, source)
		mountArgsLogStr += " " + source
	}
	mountArgs = append(mountArgs, target)
	mountArgsLogStr += " " + target

	return mountArgs, mountArgsLogStr
}

func checkUmountError(target string, command *exec.Cmd, output []byte, err error) error {
	return fmt.Errorf("unmount failed: %v\nUnmounting arguments: %s\nOutput: %s", err, target, string(output))
}
