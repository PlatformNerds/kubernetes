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

package mounttest

import (
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// xvfsconf mirrors struct xvfsconf (sys/mount.h), the elements of the
// vfs.conflist sysctl.
type xvfsconf struct {
	vfsops   uintptr
	name     [16]byte // MFSNAMELEN
	typenum  int32
	refcount int32
	flags    int32
	next     uintptr
}

// statfsTypeName returns the name of the filesystem holding buf's path, like
// Linux, whose statfs reports the type of the filesystem behind a bind
// mount. A volume is nullfs-mounted into the jail, and f_fstypename names
// that layer ("nullfs"), but f_type is the number of the filesystem below it
// (tmpfs for an emptyDir with medium Memory). FreeBSD assigns those numbers
// at boot: look the name up in vfs.conflist.
func statfsTypeName(buf *syscall.Statfs_t) string {
	if name := vfsName(int32(buf.Type)); name != "" {
		return name
	}
	n := make([]byte, 0, len(buf.Fstypename))
	for _, c := range buf.Fstypename {
		if c == 0 {
			break
		}
		n = append(n, byte(c))
	}
	if len(n) == 0 {
		return formatFsType(int64(buf.Type))
	}
	return string(n)
}

// vfsName returns the name of filesystem type number typenum, or "".
func vfsName(typenum int32) string {
	conf, err := unix.SysctlRaw("vfs.conflist")
	if err != nil {
		return ""
	}
	size := int(unsafe.Sizeof(xvfsconf{}))
	for off := 0; off+size <= len(conf); off += size {
		vfc := (*xvfsconf)(unsafe.Pointer(&conf[off]))
		if vfc.typenum == typenum {
			n := 0
			for n < len(vfc.name) && vfc.name[n] != 0 {
				n++
			}
			return string(vfc.name[:n])
		}
	}
	return ""
}

// formatFsType returns a string representation of the filesystem type number.
func formatFsType(fsType int64) string {
	return strconv.FormatInt(fsType, 10)
}
