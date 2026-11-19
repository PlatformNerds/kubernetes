//go:build !freebsd

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

package main

import "net"

// newSniffer returns where to read the TCP segments sent to ip: on Linux,
// the raw ip:tcp socket itself, which gets a copy of every TCP packet.
func newSniffer(conn *net.IPConn, ip net.IP) (packetReader, error) {
	return conn, nil
}
