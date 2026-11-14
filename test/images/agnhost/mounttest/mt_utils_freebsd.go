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
)

// statfsTypeName returns the filesystem type name of buf. FreeBSD assigns
// filesystem type numbers (f_type) dynamically at boot, so report
// f_fstypename instead, e.g. "tmpfs" for an emptyDir with medium Memory.
func statfsTypeName(buf *syscall.Statfs_t) string {
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

// formatFsType returns a string representation of the filesystem type number.
func formatFsType(fsType int64) string {
	return strconv.FormatInt(fsType, 10)
}
