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

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD never hands TCP to raw sockets (rip_input only sees protocols the
// kernel doesn't handle), so read the segments sent to ip from bpf(4) on the
// interface that has ip, the way tcpdump does. The pod needs CAP_NET_RAW,
// which CRI-O on FreeBSD maps to the bpf device. Writes still go through the
// raw socket.
func newSniffer(conn *net.IPConn, ip net.IP) (packetReader, error) {
	ifname, err := interfaceWith(ip)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/dev/bpf", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/bpf: %w", err)
	}
	blen := 1 << 16
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, blen); err != nil {
		return nil, fmt.Errorf("BIOCSBLEN: %w", err)
	}
	var ifr [unix.IFNAMSIZ + 16]byte
	copy(ifr[:], ifname)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.BIOCSETIF, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return nil, fmt.Errorf("BIOCSETIF %s: %w", ifname, e)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return nil, fmt.Errorf("BIOCIMMEDIATE: %w", err)
	}
	const bpfDirectionIn = 0 // BPF_D_IN: only what the interface receives
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSDIRECTION, bpfDirectionIn); err != nil {
		return nil, fmt.Errorf("BIOCSDIRECTION: %w", err)
	}
	return &bpfReader{fd: fd, ip: ip.To4(), buf: make([]byte, blen)}, nil
}

func interfaceWith(ip net.IP) (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifs {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface has %v", ip)
}

type bpfReader struct {
	fd       int
	ip       net.IP
	buf      []byte
	off, end int
}

// ReadFrom returns the next TCP segment sent to r.ip, like a raw ip:tcp
// socket read: the TCP header and payload, and the sender's address.
func (r *bpfReader) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		if r.off >= r.end {
			n, err := unix.Read(r.fd, r.buf)
			if err != nil {
				return 0, nil, err
			}
			r.off, r.end = 0, n
		}
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&r.buf[r.off]))
		pkt := r.buf[r.off+int(hdr.Hdrlen) : r.off+int(hdr.Hdrlen)+int(hdr.Caplen)]
		r.off += bpfWordAlign(int(hdr.Hdrlen) + int(hdr.Caplen))

		// Ethernet (epair, vtnet), then IPv4 carrying TCP to us.
		if len(pkt) < 14+20 || binary.BigEndian.Uint16(pkt[12:14]) != 0x0800 {
			continue
		}
		iph := pkt[14:]
		ihl := int(iph[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(iph[2:4]))
		if iph[0]>>4 != 4 || iph[9] != unix.IPPROTO_TCP || ihl < 20 || total > len(iph) || total < ihl ||
			!net.IP(iph[16:20]).Equal(r.ip) {
			continue
		}
		n := copy(b, iph[ihl:total])
		return n, &net.IPAddr{IP: net.IP(append([]byte(nil), iph[12:16]...))}, nil
	}
}

func bpfWordAlign(n int) int {
	const align = int(unsafe.Sizeof(int64(0))) // BPF_ALIGNMENT: sizeof(long)
	return (n + align - 1) &^ (align - 1)
}
