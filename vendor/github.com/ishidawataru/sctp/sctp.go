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

package sctp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// SCTPBind flags (the library's own values, not socket options).
const (
	SCTP_BINDX_ADD_ADDR = 0x01
	SCTP_BINDX_REM_ADDR = 0x02
)

const (
	SCTP_EVENT_DATA_IO = 1 << iota
	SCTP_EVENT_ASSOCIATION
	SCTP_EVENT_ADDRESS
	SCTP_EVENT_SEND_FAILURE
	SCTP_EVENT_PEER_ERROR
	SCTP_EVENT_SHUTDOWN
	SCTP_EVENT_PARTIAL_DELIVERY
	SCTP_EVENT_ADAPTATION_LAYER
	SCTP_EVENT_AUTHENTICATION
	SCTP_EVENT_SENDER_DRY

	SCTP_EVENT_ALL = SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION | SCTP_EVENT_ADDRESS | SCTP_EVENT_SEND_FAILURE | SCTP_EVENT_PEER_ERROR | SCTP_EVENT_SHUTDOWN | SCTP_EVENT_PARTIAL_DELIVERY | SCTP_EVENT_ADAPTATION_LAYER | SCTP_EVENT_AUTHENTICATION | SCTP_EVENT_SENDER_DRY
)

type (
	SCTPNotificationType int
	SCTPAssocID          int32
)

const (
	SCTP_SN_TYPE_BASE = SCTPNotificationType(iota + (1 << 15))
	SCTP_ASSOC_CHANGE
	SCTP_PEER_ADDR_CHANGE
	SCTP_SEND_FAILED
	SCTP_REMOTE_ERROR
	SCTP_SHUTDOWN_EVENT
	SCTP_PARTIAL_DELIVERY_EVENT
	SCTP_ADAPTATION_INDICATION
	SCTP_AUTHENTICATION_INDICATION
	SCTP_SENDER_DRY_EVENT
)

type NotificationHandler func([]byte) error

type EventSubscribe struct {
	DataIO          uint8
	Association     uint8
	Address         uint8
	SendFailure     uint8
	PeerError       uint8
	Shutdown        uint8
	PartialDelivery uint8
	AdaptationLayer uint8
	Authentication  uint8
	SenderDry       uint8
}

const (
	SCTP_MAX_STREAM = 0xffff
)

type InitMsg struct {
	NumOstreams    uint16
	MaxInstreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

// SackTimer Parameters defined in RFC 6458 8.1.19 - SCTP_DELAYED_SACK Delayed Sack Timer sack_timeout
type SackTimer struct {
	AssocID       SCTPAssocID
	SackDelay     uint32
	SackFrequency uint32
}

type PeerState int32

const (
	SCTP_UNCONFIRMED PeerState = iota
	SCTP_ACTIVE
	SCTP_INACTIVE
)

// PeerAddrinfo Parameters defined in RFC 6458 8.2.2 - Peer Address Information (SCTP_GET_PEER_ADDR_INFO)
type PeerAddrinfo struct {
	AssocID SCTPAssocID
	Address [128]byte // if needed from here, retrieve using resolveFromRawAddr(unsafe.Pointer(&PeerAddrinfo.Address), 1), or get it from *SCTPConn.SCTPGetPrimaryPeerAddr()
	State   PeerState
	CWND    uint32
	SRTT    uint32
	RTO     uint32
	MTU     uint32
}

type StatusState int32

const (
	SCTP_CLOSED StatusState = iota
	SCTP_BOUND
	SCTP_LISTEN
	SCTP_COOKIE_WAIT
	SCTP_COOKIE_ECHOED
	SCTP_ESTABLISHED
	SCTP_SHUTDOWN_PENDING
	SCTP_SHUTDOWN_SENT
	SCTP_SHUTDOWN_RECEIVED
	SCTP_SHUTDOWN_ACK_SENT
)

// Status Parameters defined in RFC 6458 8.2.1 - Association Status (SCTP_STATUS)
type Status struct {
	AssocID            SCTPAssocID
	State              StatusState
	RWND               uint32
	Unackdata          uint16
	Penddata           uint16
	Instreams          uint16
	Ostreams           uint16
	FragmentationPoint uint32
	PrimaryPeerAddr    PeerAddrinfo
}

type SndRcvInfo struct {
	Stream  uint16
	SSN     uint16
	Flags   uint16
	_       uint16
	PPID    uint32
	Context uint32
	TTL     uint32
	TSN     uint32
	CumTSN  uint32
	AssocID int32
}

type SndInfo struct {
	SID     uint16
	Flags   uint16
	PPID    uint32
	Context uint32
	AssocID int32
}

type GetAddrsOld struct {
	AssocID int32
	AddrNum int32
	Addrs   uintptr
}

type NotificationHeader struct {
	Type   uint16
	Flags  uint16
	Length uint32
}

type SCTPState uint16

const (
	SCTP_COMM_UP = SCTPState(iota)
	SCTP_COMM_LOST
	SCTP_RESTART
	SCTP_SHUTDOWN_COMP
	SCTP_CANT_STR_ASSOC
)

var nativeEndian binary.ByteOrder
var sndRcvInfoSize uintptr

func init() {
	i := uint16(1)
	if *(*byte)(unsafe.Pointer(&i)) == 0 {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
	info := SndRcvInfo{}
	sndRcvInfoSize = unsafe.Sizeof(info)
}

func toBuf(v interface{}) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, nativeEndian, v)
	return buf.Bytes()
}

func htons(h uint16) uint16 {
	if nativeEndian == binary.LittleEndian {
		return (h << 8 & 0xff00) | (h >> 8 & 0xff)
	}
	return h
}

var ntohs = htons

// setInitOpts sets options for an SCTP association initialization
// see https://tools.ietf.org/html/rfc4960#page-25
func setInitOpts(fd int, options InitMsg) error {
	optlen := unsafe.Sizeof(options)
	_, _, err := setsockopt(fd, SCTP_INITMSG, uintptr(unsafe.Pointer(&options)), uintptr(optlen))
	return err
}

func setNumOstreams(fd, num int) error {
	return setInitOpts(fd, InitMsg{NumOstreams: uint16(num)})
}

type SCTPAddr struct {
	IPAddrs []net.IPAddr
	Port    int
}

func (a *SCTPAddr) String() string {
	var b bytes.Buffer

	for n, i := range a.IPAddrs {
		if i.IP.To4() != nil {
			b.WriteString(i.String())
		} else if i.IP.To16() != nil {
			b.WriteRune('[')
			b.WriteString(i.String())
			b.WriteRune(']')
		}
		if n < len(a.IPAddrs)-1 {
			b.WriteRune('/')
		}
	}
	b.WriteRune(':')
	b.WriteString(strconv.Itoa(a.Port))
	return b.String()
}

func (a *SCTPAddr) Network() string { return "sctp" }

func ResolveSCTPAddr(network, addrs string) (*SCTPAddr, error) {
	tcpnet := ""
	switch network {
	case "", "sctp":
		tcpnet = "tcp"
	case "sctp4":
		tcpnet = "tcp4"
	case "sctp6":
		tcpnet = "tcp6"
	default:
		return nil, fmt.Errorf("invalid net: %s", network)
	}
	elems := strings.Split(addrs, "/")
	if len(elems) == 0 {
		return nil, fmt.Errorf("invalid input: %s", addrs)
	}
	ipaddrs := make([]net.IPAddr, 0, len(elems))
	for _, e := range elems[:len(elems)-1] {
		tcpa, err := net.ResolveTCPAddr(tcpnet, e+":")
		if err != nil {
			return nil, err
		}
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	}
	tcpa, err := net.ResolveTCPAddr(tcpnet, elems[len(elems)-1])
	if err != nil {
		return nil, err
	}
	if tcpa.IP != nil {
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	} else {
		ipaddrs = nil
	}
	return &SCTPAddr{
		IPAddrs: ipaddrs,
		Port:    tcpa.Port,
	}, nil
}

type SCTPConn struct {
	_fd                 int32
	notificationHandler NotificationHandler
}

func (c *SCTPConn) fd() int {
	return int(atomic.LoadInt32(&c._fd))
}

func NewSCTPConn(fd int, handler NotificationHandler) *SCTPConn {
	conn := &SCTPConn{
		_fd:                 int32(fd),
		notificationHandler: handler,
	}
	return conn
}

func (c *SCTPConn) Write(b []byte) (int, error) {
	return c.SCTPWrite(b, nil)
}

func (c *SCTPConn) Read(b []byte) (int, error) {
	n, _, err := c.SCTPRead(b)
	if n < 0 {
		n = 0
	}
	return n, err
}

func (c *SCTPConn) SetInitMsg(numOstreams, maxInstreams, maxAttempts, maxInitTimeout int) error {
	return setInitOpts(c.fd(), InitMsg{
		NumOstreams:    uint16(numOstreams),
		MaxInstreams:   uint16(maxInstreams),
		MaxAttempts:    uint16(maxAttempts),
		MaxInitTimeout: uint16(maxInitTimeout),
	})
}

func (c *SCTPConn) SubscribeEvents(flags int) error {
	var d, a, ad, sf, p, sh, pa, ada, au, se uint8
	if flags&SCTP_EVENT_DATA_IO > 0 {
		d = 1
	}
	if flags&SCTP_EVENT_ASSOCIATION > 0 {
		a = 1
	}
	if flags&SCTP_EVENT_ADDRESS > 0 {
		ad = 1
	}
	if flags&SCTP_EVENT_SEND_FAILURE > 0 {
		sf = 1
	}
	if flags&SCTP_EVENT_PEER_ERROR > 0 {
		p = 1
	}
	if flags&SCTP_EVENT_SHUTDOWN > 0 {
		sh = 1
	}
	if flags&SCTP_EVENT_PARTIAL_DELIVERY > 0 {
		pa = 1
	}
	if flags&SCTP_EVENT_ADAPTATION_LAYER > 0 {
		ada = 1
	}
	if flags&SCTP_EVENT_AUTHENTICATION > 0 {
		au = 1
	}
	if flags&SCTP_EVENT_SENDER_DRY > 0 {
		se = 1
	}
	param := EventSubscribe{
		DataIO:          d,
		Association:     a,
		Address:         ad,
		SendFailure:     sf,
		PeerError:       p,
		Shutdown:        sh,
		PartialDelivery: pa,
		AdaptationLayer: ada,
		Authentication:  au,
		SenderDry:       se,
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := setsockopt(c.fd(), SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

func (c *SCTPConn) SubscribedEvents() (int, error) {
	param := EventSubscribe{}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return 0, err
	}
	var flags int
	if param.DataIO > 0 {
		flags |= SCTP_EVENT_DATA_IO
	}
	if param.Association > 0 {
		flags |= SCTP_EVENT_ASSOCIATION
	}
	if param.Address > 0 {
		flags |= SCTP_EVENT_ADDRESS
	}
	if param.SendFailure > 0 {
		flags |= SCTP_EVENT_SEND_FAILURE
	}
	if param.PeerError > 0 {
		flags |= SCTP_EVENT_PEER_ERROR
	}
	if param.Shutdown > 0 {
		flags |= SCTP_EVENT_SHUTDOWN
	}
	if param.PartialDelivery > 0 {
		flags |= SCTP_EVENT_PARTIAL_DELIVERY
	}
	if param.AdaptationLayer > 0 {
		flags |= SCTP_EVENT_ADAPTATION_LAYER
	}
	if param.Authentication > 0 {
		flags |= SCTP_EVENT_AUTHENTICATION
	}
	if param.SenderDry > 0 {
		flags |= SCTP_EVENT_SENDER_DRY
	}
	return flags, nil
}

func (c *SCTPConn) SetDefaultSentParam(info *SndRcvInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(c.fd(), SCTP_DEFAULT_SENT_PARAM, uintptr(unsafe.Pointer(info)), uintptr(optlen))
	return err
}

func (c *SCTPConn) GetDefaultSentParam() (*SndRcvInfo, error) {
	info := &SndRcvInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(c.fd(), SCTP_DEFAULT_SENT_PARAM, uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&optlen)))
	return info, err
}

func (c *SCTPConn) SetSackTimer(timer *SackTimer) error { // SackTimer
	optlen := unsafe.Sizeof(*timer)
	_, _, err := setsockopt(c.fd(), SCTP_DELAYED_SACK, uintptr(unsafe.Pointer(timer)), optlen)
	return err
}

func (c *SCTPConn) GetSackTimer() (*SackTimer, error) { // SackTimer
	timer := &SackTimer{}
	optlen := unsafe.Sizeof(*timer)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_DELAYED_SACK,
		uintptr(unsafe.Pointer(timer)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	return timer, err
}

func (c *SCTPConn) Getsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return getsockopt(c.fd(), optname, optval, optlen)
}

func (c *SCTPConn) Setsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return setsockopt(c.fd(), optname, optval, optlen)
}

func resolveFromRawAddr(ptr unsafe.Pointer, n int) (*SCTPAddr, error) {
	addr := &SCTPAddr{
		IPAddrs: make([]net.IPAddr, n),
	}

	switch family := (*(*syscall.RawSockaddrAny)(ptr)).Addr.Family; family {
	case syscall.AF_INET:
		addr.Port = int(ntohs(uint16((*(*syscall.RawSockaddrInet4)(ptr)).Port)))
		tmp := syscall.RawSockaddrInet4{}
		size := unsafe.Sizeof(tmp)
		for i := 0; i < n; i++ {
			a := *(*syscall.RawSockaddrInet4)(unsafe.Pointer(
				uintptr(ptr) + size*uintptr(i)))
			addr.IPAddrs[i] = net.IPAddr{IP: a.Addr[:]}
		}
	case syscall.AF_INET6:
		addr.Port = int(ntohs(uint16((*(*syscall.RawSockaddrInet4)(ptr)).Port)))
		tmp := syscall.RawSockaddrInet6{}
		size := unsafe.Sizeof(tmp)
		for i := 0; i < n; i++ {
			a := *(*syscall.RawSockaddrInet6)(unsafe.Pointer(
				uintptr(ptr) + size*uintptr(i)))
			var zone string
			ifi, err := net.InterfaceByIndex(int(a.Scope_id))
			if err == nil {
				zone = ifi.Name
			}
			addr.IPAddrs[i] = net.IPAddr{IP: a.Addr[:], Zone: zone}
		}
	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
	return addr, nil
}

func (c *SCTPConn) SetDeadline(t time.Time) error {
	return syscall.EOPNOTSUPP
}

func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	return syscall.EOPNOTSUPP
}

func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	return syscall.EOPNOTSUPP
}

type SCTPListener struct {
	fd                  int
	m                   sync.Mutex
	notificationHandler NotificationHandler
}

type SCTPSndRcvInfoWrappedConn struct {
	conn *SCTPConn
}

func NewSCTPSndRcvInfoWrappedConn(conn *SCTPConn) *SCTPSndRcvInfoWrappedConn {
	conn.SubscribeEvents(SCTP_EVENT_DATA_IO)
	return &SCTPSndRcvInfoWrappedConn{conn}
}

func (c *SCTPSndRcvInfoWrappedConn) Write(b []byte) (int, error) {
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	info := (*SndRcvInfo)(unsafe.Pointer(&b[0]))
	n, err := c.conn.SCTPWrite(b[sndRcvInfoSize:], info)
	return n + int(sndRcvInfoSize), err
}

func (c *SCTPSndRcvInfoWrappedConn) Read(b []byte) (int, error) {
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	n, info, err := c.conn.SCTPRead(b[sndRcvInfoSize:])
	if err != nil {
		return n, err
	}
	copy(b, toBuf(info))
	return n + int(sndRcvInfoSize), err
}

func (c *SCTPSndRcvInfoWrappedConn) Close() error {
	return c.conn.Close()
}

func (c *SCTPSndRcvInfoWrappedConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *SCTPSndRcvInfoWrappedConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *SCTPSndRcvInfoWrappedConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}

func (c *SCTPSndRcvInfoWrappedConn) GetWriteBuffer() (int, error) {
	return c.conn.GetWriteBuffer()
}

func (c *SCTPSndRcvInfoWrappedConn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

func (c *SCTPSndRcvInfoWrappedConn) GetReadBuffer() (int, error) {
	return c.conn.GetReadBuffer()
}

// SocketConfig contains options for the SCTP socket.
type SocketConfig struct {
	// If Control is not nil it is called after the socket is created but before
	// it is bound or connected.
	Control func(network, address string, c syscall.RawConn) error
	// NotificationHandler defines actions taken on received notifications when MSG_NOTIFICATION flag is set.
	NotificationHandler NotificationHandler
	// InitMsg is the options to send in the initial SCTP message
	InitMsg InitMsg
}

func (cfg *SocketConfig) Listen(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return listenSCTPExtConfig(net, laddr, cfg.InitMsg, cfg.Control, cfg.NotificationHandler)
}

func (cfg *SocketConfig) Dial(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return dialSCTPExtConfig(net, laddr, raddr, cfg.InitMsg, cfg.Control, cfg.NotificationHandler)
}
