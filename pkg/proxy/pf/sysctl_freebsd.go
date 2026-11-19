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

package pf

import "golang.org/x/sys/unix"

// pfSCTPRdrPorts reports whether pf may change SCTP destination ports on rdr
// (net.pf.sctp_rdr_ports; kernels without it never do).
func pfSCTPRdrPorts() (bool, error) {
	v, err := unix.SysctlUint32("net.pf.sctp_rdr_ports")
	return err == nil && v != 0, err
}
