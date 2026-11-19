//go:build freebsd

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

// FreeBSD port. FreeBSD has a native SCTP stack (sctp.ko) with the RFC 6458
// one-to-one socket API, but its socket option numbers, message flags and
// struct sizes differ from Linux's, and its sockaddrs carry a length byte.
// Values below come from sys/netinet/sctp.h, sctp_uio.h and sys/sys/socket.h.
//
// Not ported (they return ErrUnsupported): GetStatus,
// SCTPGetPrimaryPeerAddr and PeelOff, whose FreeBSD structs differ from the
// Linux ones this package exposes.

package sctp

import (
	"errors"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var ErrUnsupported = errors.New("not supported by the SCTP library on " + runtime.GOOS + "/" + runtime.GOARCH)

const (
	SOL_SCTP = syscall.IPPROTO_SCTP

	MSG_NOTIFICATION = 0x2000
)

// Socket options (sys/netinet/sctp.h). The SCTP_SOCKOPT_* and SCTP_GET_*
// names are Linux's; the values are FreeBSD's equivalents.
const (
	SCTP_RTOINFO               = 0x01
	SCTP_ASSOCINFO             = 0x02
	SCTP_INITMSG               = 0x03
	SCTP_NODELAY               = 0x04
	SCTP_AUTOCLOSE             = 0x05
	SCTP_SET_PEER_PRIMARY_ADDR = 0x06
	SCTP_PRIMARY_ADDR          = 0x07
	SCTP_ADAPTATION_LAYER      = 0x08
	SCTP_DISABLE_FRAGMENTS     = 0x09
	SCTP_PEER_ADDR_PARAMS      = 0x0a
	SCTP_DEFAULT_SENT_PARAM    = 0x0b
	SCTP_EVENTS                = 0x0c
	SCTP_I_WANT_MAPPED_V4_ADDR = 0x0d
	SCTP_MAXSEG                = 0x0e
	SCTP_DELAYED_SACK          = 0x0f
	SCTP_DELAYED_ACK_TIME      = SCTP_DELAYED_SACK
	SCTP_DELAYED_ACK           = SCTP_DELAYED_SACK
	SCTP_STATUS                = 0x100
	SCTP_GET_PEER_ADDR_INFO    = 0x101

	SCTP_SOCKOPT_BINDX_ADD = 0x8001 // SCTP_BINDX_ADD_ADDR
	SCTP_SOCKOPT_BINDX_REM = 0x8002 // SCTP_BINDX_REM_ADDR
	SCTP_GET_PEER_ADDRS    = 0x8003 // SCTP_GET_PEER_ADDRESSES
	SCTP_GET_LOCAL_ADDRS   = 0x8004 // SCTP_GET_LOCAL_ADDRESSES
	SCTP_SOCKOPT_CONNECTX  = 0x8007 // SCTP_CONNECT_X
	SCTP_SOCKOPT_PEELOFF   = 0x800a // SCTP_PEELOFF
)

// Ancillary data types (sys/netinet/sctp_uio.h).
const (
	SCTP_CMSG_INIT    = 0x0001
	SCTP_CMSG_SNDRCV  = 0x0002
	SCTP_CMSG_SNDINFO = 0x0004
	SCTP_CMSG_RCVINFO = 0x0005
	SCTP_CMSG_NXTINFO = 0x0006
)

// sinfo_flags (sys/netinet/sctp_uio.h).
const (
	SCTP_EOF              = 0x0100
	SCTP_ABORT            = 0x0200
	SCTP_UNORDERED        = 0x0400
	SCTP_ADDR_OVER        = 0x0800
	SCTP_SACK_IMMEDIATELY = 0x4000
)

// sizeof(struct sctp_sndrcvinfo): SndRcvInfo's 32 bytes (same layout) plus
// sinfo_keynumber, sinfo_keynumber_valid and 92 bytes of padding. The
// kernel ignores an SCTP_SNDRCV cmsg shorter than this.
const freebsdSndRcvInfoSize = 128

// freebsdOptSize gives FreeBSD's struct size for the options sctp.go passes
// Linux-sized structs to. FreeBSD's structs extend Linux's with fields at the
// end: struct sctp_event_subscribe adds sctp_stream_reset_event (11 bytes vs
// 10) and struct sctp_sndrcvinfo adds key fields and padding (128 vs 32).
func freebsdOptSize(optname uintptr) uintptr {
	switch optname {
	case SCTP_EVENTS:
		return unsafe.Sizeof(EventSubscribe{}) + 1
	case SCTP_DEFAULT_SENT_PARAM:
		return freebsdSndRcvInfoSize
	}
	return 0
}

func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	if size := freebsdOptSize(optname); size > optlen {
		buf := make([]byte, size)
		copy(buf, (*[1 << 16]byte)(unsafe.Pointer(optval))[:optlen:optlen])
		optval, optlen = uintptr(unsafe.Pointer(&buf[0])), size
		defer runtime.KeepAlive(buf)
	}
	r0, r1, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

// getsockopt takes optlen as a pointer to a socklen_t-sized value, as the
// callers in sctp.go pass it.
func getsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	if size := freebsdOptSize(optname); size > uintptr(*(*uint32)(unsafe.Pointer(optlen))) {
		want := uintptr(*(*uint32)(unsafe.Pointer(optlen)))
		buf := make([]byte, size)
		blen := uint32(size)
		r0, r1, err := getsockopt(fd, optname, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&blen)))
		if err == nil {
			copy((*[1 << 16]byte)(unsafe.Pointer(optval))[:want:want], buf)
		}
		return r0, r1, err
	}
	r0, r1, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

type rawConn struct {
	sockfd int
}

func (r rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(r.sockfd))
	return nil
}

func (r rawConn) Read(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func (r rawConn) Write(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

// rawSockaddrs returns a's addresses as FreeBSD sockaddrs (with sin_len),
// one entry per address, falling back to the IPv4 wildcard.
func (a *SCTPAddr) rawSockaddrs() [][]byte {
	p := htons(uint16(a.Port))
	ips := a.IPAddrs
	if len(ips) == 0 {
		ips = []net.IPAddr{{IP: net.IPv4zero}}
	}
	out := make([][]byte, 0, len(ips))
	for _, ip := range ips {
		ipBytes := ip.IP
		if len(ipBytes) == 0 {
			ipBytes = net.IPv4zero
		}
		if ip4 := ipBytes.To4(); ip4 != nil {
			s := syscall.RawSockaddrInet4{
				Len:    syscall.SizeofSockaddrInet4,
				Family: syscall.AF_INET,
				Port:   p,
			}
			copy(s.Addr[:], ip4)
			out = append(out, toBuf(s))
		} else {
			var scopeid uint32
			if ifi, err := net.InterfaceByName(ip.Zone); err == nil {
				scopeid = uint32(ifi.Index)
			}
			s := syscall.RawSockaddrInet6{
				Len:      syscall.SizeofSockaddrInet6,
				Family:   syscall.AF_INET6,
				Port:     p,
				Scope_id: scopeid,
			}
			copy(s.Addr[:], ipBytes)
			out = append(out, toBuf(s))
		}
	}
	return out
}

// ToRawSockAddrBuf returns a's addresses as packed FreeBSD sockaddrs.
func (a *SCTPAddr) ToRawSockAddrBuf() []byte {
	buf := []byte{}
	for _, s := range a.rawSockaddrs() {
		buf = append(buf, s...)
	}
	return buf
}

func (a *SCTPAddr) sockaddr(i int) syscall.Sockaddr {
	ip := net.IPv4zero
	zone := ""
	if i < len(a.IPAddrs) && len(a.IPAddrs[i].IP) != 0 {
		ip, zone = a.IPAddrs[i].IP, a.IPAddrs[i].Zone
	}
	if ip4 := ip.To4(); ip4 != nil {
		sa := &syscall.SockaddrInet4{Port: a.Port}
		copy(sa.Addr[:], ip4)
		return sa
	}
	sa := &syscall.SockaddrInet6{Port: a.Port}
	if ifi, err := net.InterfaceByName(zone); err == nil {
		sa.ZoneId = uint32(ifi.Index)
	}
	copy(sa.Addr[:], ip)
	return sa
}

// SCTPConnect connects fd to addr. One address is a plain connect(2), which
// blocks until the association is up (or fails) on a blocking socket. Several
// go through SCTP_CONNECT_X, as libc's sctp_connectx(3) does; that only starts
// the association, and FreeBSD does not return its id, so 0 is returned.
func SCTPConnect(fd int, addr *SCTPAddr) (int, error) {
	if len(addr.IPAddrs) <= 1 {
		return 0, syscall.Connect(fd, addr.sockaddr(0))
	}
	sas := addr.rawSockaddrs()
	buf := toBuf(int32(len(sas)))
	for _, s := range sas {
		buf = append(buf, s...)
	}
	_, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return 0, err
}

// SCTPBind adds addr's addresses to (or removes them from) fd's local
// addresses. FreeBSD's SCTP_BINDX_ADD_ADDR takes one sockaddr per call and
// refuses a socket bound to the wildcard, so an unbound socket gets its first
// address from bind(2).
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
	sas := addr.rawSockaddrs()
	first := 0
	if flags == SCTP_BINDX_ADD_ADDR && !isBound(fd) {
		if err := syscall.Bind(fd, addr.sockaddr(0)); err != nil {
			return err
		}
		first = 1
	}
	for _, s := range sas[first:] {
		// The option value is the bare sockaddr (sctp_setopt in
		// sys/netinet/sctp_usrreq.c), not a struct sctp_getaddresses.
		if _, _, err := setsockopt(fd, option, uintptr(unsafe.Pointer(&s[0])), uintptr(len(s))); err != nil {
			return err
		}
	}
	return nil
}

func isBound(fd int) bool {
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return false
	}
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return sa.Port != 0
	case *syscall.SockaddrInet6:
		return sa.Port != 0
	}
	return false
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	var cbuf []byte
	if info != nil {
		data := make([]byte, freebsdSndRcvInfoSize)
		copy(data, toBuf(info))
		hdr := &syscall.Cmsghdr{
			Level: syscall.IPPROTO_SCTP,
			Type:  SCTP_CMSG_SNDRCV,
		}
		hdr.SetLen(syscall.CmsgLen(len(data)))
		cbuf = make([]byte, syscall.CmsgSpace(len(data)))
		copy(cbuf, toBuf(hdr))
		copy(cbuf[syscall.CmsgLen(0):], data)
	}
	return syscall.SendmsgN(c.fd(), b, cbuf, nil, 0)
}

func parseSndRcvInfo(b []byte) (*SndRcvInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Level == syscall.IPPROTO_SCTP && m.Header.Type == SCTP_CMSG_SNDRCV {
			if len(m.Data) < int(unsafe.Sizeof(SndRcvInfo{})) {
				return nil, syscall.EINVAL
			}
			info := *(*SndRcvInfo)(unsafe.Pointer(&m.Data[0]))
			return &info, nil
		}
	}
	return nil, nil
}

func (c *SCTPConn) SCTPRead(b []byte) (int, *SndRcvInfo, error) {
	oob := make([]byte, syscall.CmsgSpace(freebsdSndRcvInfoSize))
	for {
		n, oobn, recvflags, _, err := syscall.Recvmsg(c.fd(), b, oob, 0)
		if err != nil {
			return n, nil, err
		}
		// SCTP has no empty messages, so 0 bytes that aren't a notification
		// is EOF. (FreeBSD still attaches a zeroed SCTP_SNDRCV cmsg here when
		// DATA_IO events are on, so oobn is not 0 as on Linux.)
		if n == 0 && recvflags&MSG_NOTIFICATION == 0 {
			return 0, nil, io.EOF
		}
		if recvflags&MSG_NOTIFICATION > 0 && c.notificationHandler != nil {
			if err := c.notificationHandler(b[:n]); err != nil {
				return 0, nil, err
			}
		} else {
			var info *SndRcvInfo
			if oobn > 0 {
				info, err = parseSndRcvInfo(oob[:oobn])
			}
			return n, info, err
		}
	}
}

// Close shuts the association down gracefully (close(2) on a one-to-one
// socket sends SHUTDOWN, so no SCTP_EOF message is needed) and wakes up any
// goroutine blocked reading it.
func (c *SCTPConn) Close() error {
	if c != nil {
		fd := atomic.SwapInt32(&c._fd, -1)
		if fd > 0 {
			syscall.Shutdown(int(fd), syscall.SHUT_RDWR)
			return syscall.Close(int(fd))
		}
	}
	return syscall.EBADF
}

func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	return syscall.SetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	return syscall.GetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
}

func (c *SCTPConn) SetReadBuffer(bytes int) error {
	return syscall.SetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	return syscall.GetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
}

// sctpGetAddrs reads SCTP_GET_LOCAL_ADDRESSES / SCTP_GET_PEER_ADDRESSES:
// struct sctp_getaddresses followed by packed sockaddrs, each sa_len long.
func sctpGetAddrs(fd, id, optname int) (*SCTPAddr, error) {
	buf := make([]byte, 4096)
	*(*uint32)(unsafe.Pointer(&buf[0])) = uint32(id)
	optlen := uint32(len(buf))
	_, _, err := getsockopt(fd, uintptr(optname), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	if int(optlen) > len(buf) {
		optlen = uint32(len(buf))
	}
	addr := &SCTPAddr{}
	for off := 4; off+2 <= int(optlen); {
		l, family := int(buf[off]), int(buf[off+1])
		if l == 0 || off+l > int(optlen) {
			break
		}
		switch family {
		case syscall.AF_INET:
			if l < syscall.SizeofSockaddrInet4 {
				return nil, syscall.EINVAL
			}
			sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&buf[off]))
			addr.Port = int(ntohs(sa.Port))
			addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: net.IP(append([]byte(nil), sa.Addr[:]...))})
		case syscall.AF_INET6:
			if l < syscall.SizeofSockaddrInet6 {
				return nil, syscall.EINVAL
			}
			sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&buf[off]))
			addr.Port = int(ntohs(sa.Port))
			var zone string
			if sa.Scope_id != 0 {
				if ifi, err := net.InterfaceByIndex(int(sa.Scope_id)); err == nil {
					zone = ifi.Name
				}
			}
			addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: net.IP(append([]byte(nil), sa.Addr[:]...)), Zone: zone})
		}
		off += l
	}
	return addr, nil
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

func (ln *SCTPListener) Addr() net.Addr {
	laddr, err := sctpGetAddrs(ln.fd, 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		return nil
	}
	return laddr
}

func (c *SCTPConn) GetStatus() (*Status, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) SCTPGetPrimaryPeerAddr() (*SCTPAddr, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

// ListenSCTP - start listener on specified address/port
func ListenSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return ListenSCTPExt(net, laddr, InitMsg{NumOstreams: SCTP_MAX_STREAM})
}

// ListenSCTPExt - start listener on specified address/port with given SCTP options
func ListenSCTPExt(network string, laddr *SCTPAddr, options InitMsg) (*SCTPListener, error) {
	return listenSCTPExtConfig(network, laddr, options, nil, nil)
}

func newSocket(network string, laddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, af int, ipv6only bool) (sock int, err error) {
	sock, err = syscall.Socket(af, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		return -1, err
	}
	defer func() {
		if err != nil {
			syscall.Close(sock)
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return -1, err
	}
	if control != nil {
		var localAddressString string
		if laddr != nil {
			localAddressString = laddr.String()
		}
		if err = control(network, localAddressString, rawConn{sockfd: sock}); err != nil {
			return -1, err
		}
	}
	if err = setInitOpts(sock, options); err != nil {
		return -1, err
	}
	if laddr != nil {
		if len(laddr.IPAddrs) == 0 {
			if af == syscall.AF_INET {
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv4zero})
			} else {
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv6zero})
			}
		}
		if err = SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR); err != nil {
			return -1, err
		}
	}
	return sock, nil
}

func listenSCTPExtConfig(network string, laddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler) (*SCTPListener, error) {
	af, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	sock, err := newSocket(network, laddr, options, control, af, ipv6only)
	if err != nil {
		return nil, err
	}
	if err = syscall.Listen(sock, syscall.SOMAXCONN); err != nil {
		syscall.Close(sock)
		return nil, err
	}
	return &SCTPListener{fd: sock, notificationHandler: notificationHandler}, nil
}

// AcceptSCTP waits for and returns the next SCTP connection to the listener.
func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	fd, _, err := syscall.Accept4(ln.fd, syscall.SOCK_CLOEXEC)
	return NewSCTPConn(fd, ln.notificationHandler), err
}

// Accept waits for and returns the next connection connection to the listener.
func (ln *SCTPListener) Accept() (net.Conn, error) {
	return ln.AcceptSCTP()
}

func (ln *SCTPListener) Close() error {
	syscall.Shutdown(ln.fd, syscall.SHUT_RDWR)
	return syscall.Close(ln.fd)
}

// DialSCTP - bind socket to laddr (if given) and connect to raddr
func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return DialSCTPExt(net, laddr, raddr, InitMsg{NumOstreams: SCTP_MAX_STREAM})
}

// DialSCTPExt - same as DialSCTP but with given SCTP options
func DialSCTPExt(network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return dialSCTPExtConfig(network, laddr, raddr, options, nil, nil)
}

func dialSCTPExtConfig(network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler) (*SCTPConn, error) {
	af, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	sock, err := newSocket(network, laddr, options, control, af, ipv6only)
	if err != nil {
		return nil, err
	}
	if _, err = SCTPConnect(sock, raddr); err != nil {
		syscall.Close(sock)
		return nil, err
	}
	return NewSCTPConn(sock, notificationHandler), nil
}
