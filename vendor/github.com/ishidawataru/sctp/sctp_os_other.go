//go:build !freebsd

// Copyright 2019 Wataru Ishida. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Linux's socket option numbers, message flags and address handling, moved
// out of sctp.go so that FreeBSD (sctp_freebsd.go) can supply its own.

package sctp

import (
	"net"
	"syscall"
	"unsafe"
)

const (
	SOL_SCTP = 132

	MSG_NOTIFICATION = 0x8000
)

const (
	SCTP_RTOINFO = iota
	SCTP_ASSOCINFO
	SCTP_INITMSG
	SCTP_NODELAY
	SCTP_AUTOCLOSE
	SCTP_SET_PEER_PRIMARY_ADDR
	SCTP_PRIMARY_ADDR
	SCTP_ADAPTATION_LAYER
	SCTP_DISABLE_FRAGMENTS
	SCTP_PEER_ADDR_PARAMS
	SCTP_DEFAULT_SENT_PARAM
	SCTP_EVENTS
	SCTP_I_WANT_MAPPED_V4_ADDR
	SCTP_MAXSEG
	SCTP_STATUS
	SCTP_GET_PEER_ADDR_INFO
	SCTP_DELAYED_ACK_TIME
	SCTP_DELAYED_ACK  = SCTP_DELAYED_ACK_TIME
	SCTP_DELAYED_SACK = SCTP_DELAYED_ACK_TIME

	SCTP_SOCKOPT_BINDX_ADD = 100
	SCTP_SOCKOPT_BINDX_REM = 101
	SCTP_SOCKOPT_PEELOFF   = 102
	SCTP_GET_PEER_ADDRS    = 108
	SCTP_GET_LOCAL_ADDRS   = 109
	SCTP_SOCKOPT_CONNECTX  = 110
	SCTP_SOCKOPT_CONNECTX3 = 111
)

const (
	SCTP_CMSG_INIT = iota
	SCTP_CMSG_SNDRCV
	SCTP_CMSG_SNDINFO
	SCTP_CMSG_RCVINFO
	SCTP_CMSG_NXTINFO
)

const (
	SCTP_UNORDERED = 1 << iota
	SCTP_ADDR_OVER
	SCTP_ABORT
	SCTP_SACK_IMMEDIATELY
	SCTP_EOF
)

func (a *SCTPAddr) ToRawSockAddrBuf() []byte {
	p := htons(uint16(a.Port))
	if len(a.IPAddrs) == 0 { // if a.IPAddrs list is empty - fall back to IPv4 zero addr
		s := syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
			Port:   p,
		}
		copy(s.Addr[:], net.IPv4zero)
		return toBuf(s)
	}
	buf := []byte{}
	for _, ip := range a.IPAddrs {
		ipBytes := ip.IP
		if len(ipBytes) == 0 {
			ipBytes = net.IPv4zero
		}
		if ip4 := ipBytes.To4(); ip4 != nil {
			s := syscall.RawSockaddrInet4{
				Family: syscall.AF_INET,
				Port:   p,
			}
			copy(s.Addr[:], ip4)
			buf = append(buf, toBuf(s)...)
		} else {
			var scopeid uint32
			ifi, err := net.InterfaceByName(ip.Zone)
			if err == nil {
				scopeid = uint32(ifi.Index)
			}
			s := syscall.RawSockaddrInet6{
				Family:   syscall.AF_INET6,
				Port:     p,
				Scope_id: scopeid,
			}
			copy(s.Addr[:], ipBytes)
			buf = append(buf, toBuf(s)...)
		}
	}
	return buf
}

func SCTPConnect(fd int, addr *SCTPAddr) (int, error) {
	buf := addr.ToRawSockAddrBuf()
	param := GetAddrsOld{
		AddrNum: int32(len(buf)),
		Addrs:   uintptr(uintptr(unsafe.Pointer(&buf[0]))),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, SCTP_SOCKOPT_CONNECTX3, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err == nil {
		return int(param.AssocID), nil
	} else if err != syscall.ENOPROTOOPT {
		return 0, err
	}
	r0, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return int(r0), err
}

func SCTPBind(fd int, addr *SCTPAddr, flags int) error {
	var option uintptr
	switch flags {
	case SCTP_BINDX_ADD_ADDR:
		option = SCTP_SOCKOPT_BINDX_ADD
	case SCTP_BINDX_REM_ADDR:
		option = SCTP_SOCKOPT_BINDX_REM
	default:
		return syscall.EINVAL
	}

	buf := addr.ToRawSockAddrBuf()
	_, _, err := setsockopt(fd, option, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

func (c *SCTPConn) GetStatus() (*Status, error) { // Status
	sctpStatus := &Status{}
	optlen := unsafe.Sizeof(*sctpStatus)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_STATUS,
		uintptr(unsafe.Pointer(sctpStatus)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	return sctpStatus, err
}

func sctpGetAddrs(fd, id, optname int) (*SCTPAddr, error) {

	type getaddrs struct {
		assocId int32
		addrNum uint32
		addrs   [4096]byte
	}
	param := getaddrs{
		assocId: int32(id),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, uintptr(optname), uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return resolveFromRawAddr(unsafe.Pointer(&param.addrs), int(param.addrNum))
}

func (c *SCTPConn) SCTPGetPrimaryPeerAddr() (*SCTPAddr, error) {

	type sctpGetSetPrim struct {
		assocId int32
		addrs   [128]byte
	}
	param := sctpGetSetPrim{
		assocId: int32(0),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_PRIMARY_ADDR, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return resolveFromRawAddr(unsafe.Pointer(&param.addrs), 1)
}

func (c *SCTPConn) SCTPLocalAddr(id int) (*SCTPAddr, error) {
	return sctpGetAddrs(c.fd(), id, SCTP_GET_LOCAL_ADDRS)
}

func (c *SCTPConn) SCTPRemoteAddr(id int) (*SCTPAddr, error) {
	return sctpGetAddrs(c.fd(), id, SCTP_GET_PEER_ADDRS)
}

func (c *SCTPConn) LocalAddr() net.Addr {
	addr, err := sctpGetAddrs(c.fd(), 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		return nil
	}
	return addr
}

func (c *SCTPConn) RemoteAddr() net.Addr {
	addr, err := sctpGetAddrs(c.fd(), 0, SCTP_GET_PEER_ADDRS)
	if err != nil {
		return nil
	}
	return addr
}

func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	type peeloffArg struct {
		assocId int32
		sd      int
	}
	param := peeloffArg{
		assocId: int32(id),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_SOCKOPT_PEELOFF, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return &SCTPConn{_fd: int32(param.sd)}, nil
}

func (ln *SCTPListener) Addr() net.Addr {
	laddr, err := sctpGetAddrs(ln.fd, 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		return nil
	}
	return laddr
}
