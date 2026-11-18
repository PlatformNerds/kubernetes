/*
Copyright 2015 The Kubernetes Authors.

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

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/metaproxier"
	"k8s.io/kubernetes/pkg/proxy/metrics"
	"k8s.io/kubernetes/pkg/proxy/runner"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
	utilexec "k8s.io/utils/exec"
	netutils "k8s.io/utils/net"
)

// internal struct for string service information
type servicePortInfo struct {
	*proxy.BaseServicePortInfo
	// The following fields are computed and stored for performance reasons.
	nameString string
	anchorName string
}

// returns a new proxy.ServicePort which abstracts a serviceInfo
func newServiceInfo(port *v1.ServicePort, service *v1.Service, bsvcPortInfo *proxy.BaseServicePortInfo, ipFamily v1.IPFamily) proxy.ServicePort {
	svcPort := &servicePortInfo{BaseServicePortInfo: bsvcPortInfo}

	// Store the following for performance reasons.
	svcName := types.NamespacedName{Namespace: service.Namespace, Name: service.Name}
	svcPortName := proxy.ServicePortName{NamespacedName: svcName, Port: port.Name}
	protocol := strings.ToLower(string(svcPort.Protocol()))
	svcPort.nameString = svcPortName.String()
	svcPort.anchorName = anchorName(svcPort.nameString, protocol, ipFamily)

	return svcPort
}

// internal struct for endpoints information
type endpointsInfo struct {
	*proxy.BaseEndpointInfo
}

// returns a new proxy.Endpoint which abstracts a endpointsInfo
func newEndpointInfo(baseInfo *proxy.BaseEndpointInfo, svcPortName *proxy.ServicePortName) proxy.Endpoint {
	return &endpointsInfo{
		BaseEndpointInfo: baseInfo,
	}
}

type LocalTrafficDetector interface {
	// IsImplemented returns true if the implementation does something, false otherwise
	IsImplemented() bool

	// IfLocal returns pf expression that will match traffic from a pod
	IfLocal() string

	// IfNotLocal returns pf expression that will match traffic that is not from a pod
	IfNotLocal() string

	// Address expression to translate non-local source address
	ToAddress() string
}

// Proxier is an pf based proxy for connections between a localhost:lport
// and services that provide the actual backends.
type Proxier struct {
	// Address family for this proxier
	ipFamily v1.IPFamily

	// endpointsChanges and serviceChanges contains all changes to endpoints
	// and services that happened since pf was synced. For a single object,
	// changes are accumulated, i.e. previous is state from before all of
	// them, current is state after applying all of those.
	endpointsChanges *proxy.EndpointsChangeTracker
	serviceChanges   *proxy.ServiceChangeTracker

	mu             sync.Mutex // protects the following fields
	svcPortMap     proxy.ServicePortMap
	endpointsMap   proxy.EndpointsMap
	topologyLabels map[string]string
	// endpointSlicesSynced, and servicesSynced are set to true when
	// corresponding objects are synced after startup. This is used to avoid
	// updating pf with some partial data after kube-proxy restart.
	endpointSlicesSynced bool
	servicesSynced       bool
	lastFullSync         time.Time
	needFullSync         bool
	initialized          int32
	syncRunner           *runner.BoundedFrequencyRunner // governs calls to syncProxyRules
	syncPeriod           time.Duration

	// These are effectively const and do not need the mutex to be held.
	exec          utilexec.Interface
	localDetector LocalTrafficDetector
	nodeName      string
	nodeIP        net.IP
	recorder      events.EventRecorder

	serviceHealthServer healthcheck.ServiceHealthServer
	healthzServer       *healthcheck.ProxyHealthServer

	// The following buffers are used to reuse memory and avoid allocations
	// that are significantly impacting performance.
	pfData proxyutil.LineBuffer

	// Values are as a parameter to select the interfaces where nodePort works.
	nodePortAddresses *proxyutil.NodePortAddresses
	// networkInterfacer defines an interface for several net library functions.
	// Inject for test purpose.
	networkInterfacer proxyutil.NetworkInterfacer

	logger klog.Logger
}

// Proxier implements proxy.Provider
var _ proxy.Provider = &Proxier{}

// NewProxier returns a new Proxier for PF
func NewProxier(ctx context.Context,
	ipFamily v1.IPFamily,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	localDetector LocalTrafficDetector,
	nodeName string,
	nodeIP net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	nodePortAddressStrings []string,
) (*Proxier, error) {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "ipFamily", ipFamily)
	nodePortAddresses := proxyutil.NewNodePortAddresses(ipFamily, nodePortAddressStrings)

	serviceHealthServer := healthcheck.NewServiceHealthServer(nodeName, recorder, nodePortAddresses, healthzServer, ipFamily)

	newServiceInfoWrapper := func(port *v1.ServicePort, service *v1.Service, bsvcPortInfo *proxy.BaseServicePortInfo) proxy.ServicePort {
		return newServiceInfo(port, service, bsvcPortInfo, ipFamily)
	}
	proxier := &Proxier{
		ipFamily:            ipFamily,
		svcPortMap:          make(proxy.ServicePortMap),
		serviceChanges:      proxy.NewServiceChangeTracker(ipFamily, newServiceInfoWrapper, nil),
		endpointsMap:        make(proxy.EndpointsMap),
		endpointsChanges:    proxy.NewEndpointsChangeTracker(ipFamily, nodeName, newEndpointInfo, nil),
		needFullSync:        true,
		exec:                exec,
		localDetector:       localDetector,
		nodeName:            nodeName,
		nodeIP:              nodeIP,
		recorder:            recorder,
		serviceHealthServer: serviceHealthServer,
		healthzServer:       healthzServer,
		pfData:              proxyutil.NewLineBuffer(),
		nodePortAddresses:   nodePortAddresses,
		networkInterfacer:   proxyutil.RealNetwork{},
		logger:              logger,
	}

	logger.V(2).Info("PF sync params", "minSyncPeriod", minSyncPeriod, "syncPeriod", syncPeriod, "maxSyncPeriod", proxyutil.FullSyncPeriod)
	proxier.syncRunner = runner.NewBoundedFrequencyRunner("sync-runner", proxier.syncProxyRules, minSyncPeriod, syncPeriod, proxyutil.FullSyncPeriod)

	return proxier, nil
}

// NewDualStackProxier creates a MetaProxier instance, with IPv4 and IPv6 proxies.
func NewDualStackProxier(
	ctx context.Context,
	exec utilexec.Interface,
	syncPeriod time.Duration,
	minSyncPeriod time.Duration,
	localDetectors map[v1.IPFamily]LocalTrafficDetector,
	nodeName string,
	nodeIPs map[v1.IPFamily]net.IP,
	recorder events.EventRecorder,
	healthzServer *healthcheck.ProxyHealthServer,
	nodePortAddresses []string,
) (proxy.Provider, error) {
	ipv4Proxier, err := NewProxier(
		ctx,
		v1.IPv4Protocol,
		exec,
		syncPeriod,
		minSyncPeriod,
		localDetectors[v1.IPv4Protocol],
		nodeName,
		nodeIPs[v1.IPv4Protocol],
		recorder,
		healthzServer,
		nodePortAddresses,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv4 proxier: %v", err)
	}
	ipv6Proxier, err := NewProxier(
		ctx,
		v1.IPv6Protocol,
		exec,
		syncPeriod,
		minSyncPeriod,
		localDetectors[v1.IPv6Protocol],
		nodeName,
		nodeIPs[v1.IPv6Protocol],
		recorder,
		healthzServer,
		nodePortAddresses,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create ipv6 proxier: %v", err)
	}
	return metaproxier.NewMetaProxier(ipv4Proxier, ipv6Proxier), nil
}

// CleanupLeftovers removes all pf rules created by the Proxier It returns true
// if an error was encountered. Errors are logged.
func CleanupLeftovers(exec utilexec.Interface) (encounteredError bool) {
	klog.V(2).Info("listing PF anchors")
	cmd := exec.Command("pfctl", "-a", "cni-rdr", "-s", "Anchors")
	out, err := cmd.Output()
	if err != nil {
		klog.Errorf("listing PF anchors: %v", err)
		return true
	}

	encounteredError = false
	anchors := strings.Split(string(out), "\n")
	for _, anchor := range anchors {
		anchor = strings.TrimSpace(anchor)
		if strings.HasPrefix(anchor, "cni-rdr/kube-svc-") {
			klog.V(2).Infof("deleting PF anchor %s", anchor)
			if err := flushAnchor(exec, anchor); err != nil {
				klog.Errorf("deleting anchor %s: %v", anchor, err)
				encounteredError = true
			}
		}
	}
	return encounteredError
}

// Sync is called to synchronize the proxier state to pf as soon as possible.
func (proxier *Proxier) Sync() {
	if proxier.healthzServer != nil {
		proxier.healthzServer.QueuedUpdate(proxier.ipFamily)
	}
	metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(proxier.ipFamily)).SetToCurrentTime()
	proxier.syncRunner.Run()
}

// SyncLoop runs periodic work.  This is expected to run as a goroutine or as the main loop of the app.  It does not return.
func (proxier *Proxier) SyncLoop() {
	// Update healthz timestamp at beginning in case Sync() never succeeds.
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated(proxier.ipFamily)
	}

	// synthesize "last change queued" time as the informers are syncing.
	metrics.SyncProxyRulesLastQueuedTimestamp.WithLabelValues(string(proxier.ipFamily)).SetToCurrentTime()
	proxier.syncRunner.Loop(wait.NeverStop)
}

func (proxier *Proxier) setInitialized(value bool) {
	var initialized int32
	if value {
		initialized = 1
	}
	atomic.StoreInt32(&proxier.initialized, initialized)
}

func (proxier *Proxier) isInitialized() bool {
	return atomic.LoadInt32(&proxier.initialized) > 0
}

// OnServiceAdd is called whenever creation of new service object
// is observed.
func (proxier *Proxier) OnServiceAdd(service *v1.Service) {
	proxier.OnServiceUpdate(nil, service)
}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (proxier *Proxier) OnServiceUpdate(oldService, service *v1.Service) {
	if proxier.serviceChanges.Update(oldService, service) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (proxier *Proxier) OnServiceDelete(service *v1.Service) {
	proxier.OnServiceUpdate(service, nil)

}

// OnServiceSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *Proxier) OnServiceSynced() {
	proxier.mu.Lock()
	proxier.servicesSynced = true
	proxier.setInitialized(proxier.endpointSlicesSynced)
	proxier.mu.Unlock()

	// Sync unconditionally - this is called once per lifetime.
	proxier.syncProxyRules()
}

// OnEndpointSliceAdd is called whenever creation of a new endpoint slice object
// is observed.
func (proxier *Proxier) OnEndpointSliceAdd(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnEndpointSliceUpdate is called whenever modification of an existing endpoint
// slice object is observed.
func (proxier *Proxier) OnEndpointSliceUpdate(_, endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, false) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnEndpointSliceDelete is called whenever deletion of an existing endpoint slice
// object is observed.
func (proxier *Proxier) OnEndpointSliceDelete(endpointSlice *discovery.EndpointSlice) {
	if proxier.endpointsChanges.EndpointSliceUpdate(endpointSlice, true) && proxier.isInitialized() {
		proxier.Sync()
	}
}

// OnEndpointSlicesSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (proxier *Proxier) OnEndpointSlicesSynced() {
	proxier.mu.Lock()
	proxier.endpointSlicesSynced = true
	proxier.setInitialized(proxier.servicesSynced)
	proxier.mu.Unlock()

	// Sync unconditionally - this is called once per lifetime.
	proxier.syncProxyRules()
}

// OnTopologyChange is called whenever this node's proxy relevant topology-related labels change.
func (proxier *Proxier) OnTopologyChange(topologyLabels map[string]string) {
	proxier.mu.Lock()
	proxier.topologyLabels = topologyLabels
	proxier.needFullSync = true
	proxier.mu.Unlock()
	proxier.logger.V(4).Info("Updated proxier node topology labels", "labels", topologyLabels)
	proxier.Sync()
}

// OnServiceCIDRsChanged is called whenever a change is observed
// in any of the ServiceCIDRs, and provides complete list of service cidrs.
func (proxier *Proxier) OnServiceCIDRsChanged(_ []string) {}

// portProtoHash takes the ServicePortName and protocol for a service returns
// the associated 16 character hash. This is computed by hashing (sha256) then
// encoding to base32 and truncating to 16 chars. We do this because PF anchor
// names must be <= 64 chars long, and the longer they are the harder they are
// to read.
func portProtoHash(servicePortName string, protocol string) string {
	hash := sha256.Sum256([]byte(servicePortName + protocol))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return encoded[:16]
}

// Construct an anchor name based on the ServicePortName and protocol
func anchorName(servicePortName string, protocol string, ipFamily v1.IPFamily) string {
	af := "v4"
	if ipFamily == v1.IPv6Protocol {
		af = "v6"
	}
	return fmt.Sprintf("kube-svc-%s-%s", af, portProtoHash(servicePortName, protocol))
}

// nodePortTag marks packets redirected by a NodePort rdr rule so that
// nodePortSNATRule can masquerade the ones forwarded to other nodes.
const nodePortTag = "KUBE_NODEPORT"

// redirectRule writes an rdr rule from destinationIP:destinationPort to the
// endpoints in targetIPs (a single address or a pf address list "{ a, b }").
// With more than one endpoint the pool is round-robin; with sticky (Service
// sessionAffinity: ClientIP) pf's sticky-address keeps each client address on
// the same endpoint for as long as pf tracks the source (while the client has
// states; the global "set timeout src.track" extends that). A non-empty tag
// is attached to the redirected packets.
func (proxier *Proxier) redirectRule(af, proto, source string, destinationIP net.IP, destinationPort int, targetIPs string, targetPort int, sticky bool, tag string) {
	words := []interface{}{
		"rdr", af, "proto", proto,
		"from", source, "to", destinationIP.String(),
		"port", strconv.Itoa(destinationPort),
	}
	if tag != "" {
		words = append(words, "tag", tag)
	}
	words = append(words, "->", targetIPs, "port", strconv.Itoa(targetPort))
	if strings.HasPrefix(targetIPs, "{") {
		words = append(words, "round-robin")
		if sticky {
			words = append(words, "sticky-address")
		}
	}
	proxier.pfData.Write(words...)
}

// pfTarget is a set of endpoints that one rdr rule redirects to. pf
// redirects to a single port, so when the endpoints listen on different
// ports only the largest group with the same port is used; spreading over
// several ports would need an external load balancer.
type pfTarget struct {
	hosts  string   // "{ ip, ... }"
	port   int      // the endpoints' port
	local  []string // endpoints on this node
	remote []string // endpoints on other nodes
}

// newPFTarget returns the target for endpoints, or nil if there are none.
func newPFTarget(endpoints []proxy.Endpoint) *pfTarget {
	byPort := map[int][]proxy.Endpoint{}
	for _, ep := range endpoints {
		byPort[ep.Port()] = append(byPort[ep.Port()], ep)
	}
	var group []proxy.Endpoint
	port := 0
	for p, eps := range byPort {
		if len(eps) > len(group) || len(eps) == len(group) && p < port {
			group, port = eps, p
		}
	}
	if len(group) == 0 {
		return nil
	}
	t := &pfTarget{port: port}
	ips := make([]string, 0, len(group))
	for _, ep := range group {
		ips = append(ips, ep.IP())
		if ep.IsLocal() {
			t.local = append(t.local, ep.IP())
		} else {
			t.remote = append(t.remote, ep.IP())
		}
	}
	t.hosts = "{ " + strings.Join(ips, ", ") + " }"
	return t
}

// addrPorts returns the target's endpoints as pf address:port strings.
func (t *pfTarget) addrPorts() sets.Set[string] {
	s := sets.New[string]()
	for _, ip := range append(append([]string{}, t.local...), t.remote...) {
		s.Insert(pfAddrPort(ip, t.port))
	}
	return s
}

// serviceRules describes one service port's anchor.
type serviceRules struct {
	name, af, proto string
	clusterIP       net.IP
	port, nodePort  int
	nodeIPs         []net.IP
	externalIPs     []net.IP // externalIPs and LoadBalancer ingress IPs
	sticky          bool

	// internal is where ClusterIP traffic goes (internalTrafficPolicy).
	internal *pfTarget
	// external is where traffic from outside the cluster to a NodePort,
	// an external IP or a LoadBalancer IP goes (externalTrafficPolicy). With externalLocal and no local endpoint
	// it is nil, and that traffic is dropped, as on Linux.
	external      *pfTarget
	externalLocal bool
	// shortCircuit, with externalLocal only, is where NodePort traffic
	// from pods and from the node itself goes: the cluster-wide endpoints.
	shortCircuit *pfTarget
}

// writeServiceRules writes one service port's anchor: rdr for its ClusterIP
// and NodePorts, nat for NodePort traffic to remote endpoints, and filter
// rules for traffic the node itself sends to the ClusterIP or a NodePort.
// pf rejects a ruleset whose translation rules don't all come before its
// filter rules, so the filter rules go last.
func (proxier *Proxier) writeServiceRules(r *serviceRules) {
	af, proto := r.af, r.proto
	if r.internal != nil {
		proxier.redirectRule(af, proto, "any", r.clusterIP, r.port, r.internal.hosts, r.internal.port, r.sticky, "")
	}
	// hairpin: a local endpoint redirected to itself
	if proxier.nodeIP != nil && !proxier.nodeIP.IsUnspecified() {
		seen := sets.New[string]()
		for _, t := range []*pfTarget{r.internal, r.shortCircuit, r.external} {
			if t == nil {
				continue
			}
			for _, ip := range t.local {
				if k := pfAddrPort(ip, t.port); !seen.Has(k) {
					seen.Insert(k)
					proxier.hairpinSNATRule(af, proto, ip, t.port)
				}
			}
		}
	}
	// With externalTrafficPolicy: Local, the node's own connections to
	// external destinations short-circuit to all endpoints.
	nodeTarget := r.external
	if r.externalLocal && r.shortCircuit != nil {
		nodeTarget = r.shortCircuit
	}
	dests := r.externalDestinations()
	if len(dests) > 0 {
		// So do this node's pods'. Without a local traffic detector
		// they are treated as external, as on Linux.
		podSource := ""
		if r.externalLocal && r.shortCircuit != nil && proxier.localDetector != nil &&
			proxier.localDetector.IsImplemented() {
			podSource = proxier.localDetector.IfLocal()
		}
		for _, d := range dests {
			if podSource != "" {
				proxier.redirectRule(af, proto, podSource, d.ip, d.port, r.shortCircuit.hosts, r.shortCircuit.port, r.sticky, nodePortTag)
			}
			if r.external != nil {
				proxier.redirectRule(af, proto, "any", d.ip, d.port, r.external.hosts, r.external.port, r.sticky, nodePortTag)
			}
		}
		// Masquerade only what goes to other nodes, to this node's
		// own address: a single cluster-wide masquerade address
		// (LocalModeClusterCIDR) would route replies to a node
		// that can't reverse the NAT. With externalTrafficPolicy:
		// Local, external traffic only reaches local endpoints and
		// keeps its source address.
		seen := sets.New[string]()
		for _, t := range []*pfTarget{nodeTarget, r.external} {
			if t == nil || len(t.remote) == 0 {
				continue
			}
			if k := strings.Join(t.remote, ",") + "/" + strconv.Itoa(t.port); seen.Has(k) {
				continue
			} else {
				seen.Insert(k)
			}
			if proxier.nodeIP == nil || proxier.nodeIP.IsUnspecified() {
				klog.ErrorS(nil, "No node IP: external traffic to endpoints on other nodes is not masqueraded and may fail", "service", r.name)
				break
			}
			proxier.nodePortSNATRule(af, proto, "{ "+strings.Join(t.remote, ", ")+" }", t.port)
		}
	}
	if r.internal != nil {
		proxier.hostRedirectRule(af, proto, r.clusterIP, r.port, r.internal.hosts, r.internal.port)
	}
	for _, d := range dests {
		if nodeTarget != nil {
			if d.isNodePort {
				proxier.hostNodePortRule(af, proto, d.ip, d.port, nodeTarget.hosts, nodeTarget.port)
			} else {
				proxier.hostRedirectRule(af, proto, d.ip, d.port, nodeTarget.hosts, nodeTarget.port)
			}
		}
		if r.external == nil {
			// externalTrafficPolicy: Local and no local
			// endpoint: drop, so that a load balancer's
			// health check sends clients elsewhere.
			proxier.pfData.Write("block drop in quick", af, "proto", proto,
				"from any to", d.ip.String(), "port", strconv.Itoa(d.port))
		}
	}
}

// externalDestination is an address and port that takes external traffic.
type externalDestination struct {
	ip         net.IP
	port       int
	isNodePort bool
}

// externalDestinations returns the node IPs with the NodePort, then the
// externalIPs and LoadBalancer IPs with the service port.
func (r *serviceRules) externalDestinations() []externalDestination {
	var d []externalDestination
	if r.nodePort != 0 {
		for _, ip := range r.nodeIPs {
			// Don't try to redirect ::1/128 or 127.0.0.0/8
			if !ip.IsLoopback() {
				d = append(d, externalDestination{ip, r.nodePort, true})
			}
		}
	}
	for _, ip := range r.externalIPs {
		d = append(d, externalDestination{ip, r.port, false})
	}
	return d
}

// hairpinSNATRule masquerades a pod's connection to a Service that was
// redirected to the pod itself. Without it the pod answers itself directly
// inside its own network stack, the reply never passes this node, the rdr is
// never reversed, and the client sees a reply from its own address instead
// of the Service's, so the connection fails (every time round-robin picks the
// client). Linux kube-proxy masquerades hairpin traffic the same way. With
// the node IP as source, the reply comes back through the node, which
// reverses both translations.
func (proxier *Proxier) hairpinSNATRule(af, proto string, endpointIP string, targetPort int) {
	proxier.pfData.Write(
		"nat", af, "proto", proto,
		"from", endpointIP, "to", endpointIP,
		"port", strconv.Itoa(targetPort),
		"->", proxier.nodeIP.String(),
	)
}

// hostNodePortRule redirects the node's own connections to one of its
// NodePorts. Those go out through lo0 and back in, where the NodePort rdr
// rule matches but the redirected packet isn't forwarded off lo0, so they
// are redirected on the way out instead. The replies then come back with the
// node's own address as source on the endpoint's interface, which source
// address validation drops unless pf delivers them (the bsdk8s pf change
// "deliver replies of redirected connections to the host's own address");
// on other kernels this rule is harmless: such connections failed anyway.
func (proxier *Proxier) hostNodePortRule(af, proto string, nodeIP net.IP, nodePort int, targetIPs string, targetPort int) {
	words := []interface{}{
		"pass out quick on lo0", af, "proto", proto,
		"from any to", nodeIP.String(),
		"port", strconv.Itoa(nodePort),
		"rdr-to", targetIPs, "port", strconv.Itoa(targetPort),
	}
	if strings.HasPrefix(targetIPs, "{") {
		words = append(words, "round-robin")
	}
	proxier.pfData.Write(words...)
}

// hostRedirectRule redirects traffic the node itself sends to a ClusterIP
// (host-network pods, the kubelet, the apiserver calling webhooks): rdr rules
// only apply to packets arriving on an interface, never to locally
// originated ones, so these go out unredirected and fail. FreeBSD 15's pf
// can translate on output with a filter rule's rdr-to. The rule goes in the
// service's anchor, which the main ruleset must reference as a filter anchor
// (anchor "cni-rdr/*"). The reply must come back to this node: its source is
// the address of the interface the Service CIDR routes through, so on a
// multi-homed node route the Service CIDR via the node IP's interface.
//
// No sticky-address: pf (15.x) records the wrong address for outbound rdr-to
// source tracking and would redirect every later connection of a client to
// the client itself (fixed by the bsdk8s pf patch, not yet upstream), so
// sessionAffinity is not honoured for host-network clients.
func (proxier *Proxier) hostRedirectRule(af, proto string, destinationIP net.IP, destinationPort int, targetIPs string, targetPort int) {
	words := []interface{}{
		"pass out quick", af, "proto", proto,
		"from any to", destinationIP.String(),
		"port", strconv.Itoa(destinationPort),
		"rdr-to", targetIPs, "port", strconv.Itoa(targetPort),
	}
	if strings.HasPrefix(targetIPs, "{") {
		words = append(words, "round-robin")
	}
	proxier.pfData.Write(words...)
}

// flushAnchor removes all translation and filter rules of an anchor. Not
// "-F all": that would also flush the global state table and source nodes.
func flushAnchor(execer utilexec.Interface, anchor string) error {
	for _, what := range []string{"nat", "rules"} {
		if out, err := execer.Command("pfctl", "-a", anchor, "-F", what).CombinedOutput(); err != nil {
			return fmt.Errorf("pfctl -a %s -F %s: %w: %s", anchor, what, err, out)
		}
	}
	return nil
}

// nodePortSNATRule masquerades NodePort traffic that was redirected to an
// endpoint on another node (remoteIPs) to this node's IP. Without it the
// endpoint replies straight to the client, bypassing this node, so the rdr is
// never reversed and the connection fails: e.g. a client on node B calling
// nodeA:nodePort with the endpoint on node B, or any external client whose
// return path doesn't run through this node. Only packets tagged by a NodePort
// rdr match: ClusterIP traffic keeps its source address, and with
// externalTrafficPolicy: Local there are no remote endpoints, so client
// addresses are preserved as the API promises.
func (proxier *Proxier) nodePortSNATRule(af, proto string, remoteIPs string, targetPort int) {
	proxier.pfData.Write(
		"nat", af, "proto", proto,
		"from any to", remoteIPs,
		"port", strconv.Itoa(targetPort),
		"tagged", nodePortTag,
		"->", proxier.nodeIP.String(),
	)
}

// This is where all of the iptables-save/restore calls happen.
// The only other iptables rules are those that are setup in iptablesInit()
// This assumes proxier.mu is NOT held
func (proxier *Proxier) syncProxyRules() error {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()

	// don't sync rules till we've received services and endpoints
	if !proxier.isInitialized() {
		proxier.logger.V(2).Info("Not syncing pf until Services and Endpoints have been received from master")
		return nil
	}

	// Keep track of how long syncs take.
	start := time.Now()

	doFullSync := proxier.needFullSync ||
		(time.Since(proxier.lastFullSync) > proxyutil.FullSyncPeriod)

	defer func() {
		metrics.SyncProxyRulesLatency.WithLabelValues(string(proxier.ipFamily)).Observe(metrics.SinceInSeconds(start))
		if !doFullSync {
			metrics.SyncPartialProxyRulesLatency.WithLabelValues(string(proxier.ipFamily)).Observe(metrics.SinceInSeconds(start))
		} else {
			metrics.SyncFullProxyRulesLatency.WithLabelValues(string(proxier.ipFamily)).Observe(metrics.SinceInSeconds(start))
		}
		proxier.logger.V(2).Info("SyncProxyRules complete", "elapsed", time.Since(start))
	}()

	// Get a pre-update list of anchors - we will remove entries from this
	// set for each active anchor and what remains can be removed.
	staleAnchors := sets.NewString()
	for _, svc := range proxier.svcPortMap {
		if svcInfo, ok := svc.(*servicePortInfo); ok {
			staleAnchors.Insert(svcInfo.anchorName)
		}
	}

	// TODO: figure out if partial sync makes sense. For now, just re-write all the rules
	proxier.svcPortMap.Update(proxier.serviceChanges)
	proxier.endpointsMap.Update(proxier.endpointsChanges)

	// TODO: figure out how to delete anchors for stale services

	proxier.logger.V(2).Info("Syncing pf rules")

	//
	// Below this point we will not return until we try to write the pf rules.
	nodeIPs, err := proxier.nodePortAddresses.GetNodeIPs(proxier.networkInterfacer)
	if err != nil {
		klog.ErrorS(err, "Failed to get node ip address matching nodeport cidrs, services with nodeport may not work as intended", "CIDRs", proxier.nodePortAddresses)
	}

	// UDP frontends and their current endpoints, for killStaleUDPStates.
	udpFronts := udpFrontends{}

	// Build rules for each service-port.
	for svcName, svc := range proxier.svcPortMap {
		svcInfo, ok := svc.(*servicePortInfo)
		if !ok {
			klog.ErrorS(nil, "Failed to cast serviceInfo", "serviceName", svcName)
			continue
		}
		staleAnchors.Delete(svcInfo.anchorName)
		//protocol := strings.ToLower(string(svcInfo.Protocol()))
		//svcPortNameString := svcInfo.nameString

		// Figure out the endpoints for Cluster and Local traffic policy.
		// allLocallyReachableEndpoints is the set of all endpoints that can be routed to
		// from this node, given the service's traffic policies. hasEndpoints is true
		// if the service has any usable endpoints on any node, not just this one.
		allEndpoints := proxier.endpointsMap[svcName]
		clusterEndpoints, localEndpoints, allLocallyReachableEndpoints, _ := proxy.CategorizeEndpoints(allEndpoints, svcInfo, proxier.nodeName, proxier.topologyLabels)
		if proxier.logger.V(2).Enabled() {
			klog.Infof("Service %s:", svcName)
			klog.Infof("clusterEndpoints: %v", clusterEndpoints)
			klog.Infof("localEndpoints: %v", localEndpoints)
			klog.Infof("allLocallyReachableEndpoints: %v", allLocallyReachableEndpoints)
		}

		// Which endpoints each kind of traffic may reach, as in the
		// iptables proxier: ClusterIP traffic follows
		// internalTrafficPolicy, NodePort traffic from outside the
		// cluster follows externalTrafficPolicy, and with
		// externalTrafficPolicy: Local, NodePort traffic from pods and
		// from the node itself short-circuits to the cluster-wide
		// endpoints (Local only exists to keep external clients'
		// addresses, which pods and the node don't need).
		internalEndpoints := clusterEndpoints
		if svcInfo.InternalPolicyLocal() {
			internalEndpoints = localEndpoints
		}
		externalEndpoints := clusterEndpoints
		var shortCircuitEndpoints []proxy.Endpoint
		if svcInfo.ExternalPolicyLocal() {
			externalEndpoints = localEndpoints
			shortCircuitEndpoints = clusterEndpoints
			if len(shortCircuitEndpoints) == 0 {
				shortCircuitEndpoints = internalEndpoints
			}
		}
		rules := serviceRules{
			name:      svcName.String(),
			clusterIP: svcInfo.ClusterIP(),
			port:      svcInfo.Port(),
			nodePort:  svcInfo.NodePort(),
			nodeIPs:   nodeIPs,
			sticky:    svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP,
			internal:  newPFTarget(internalEndpoints),
		}
		// externalIPs and LoadBalancer ingress IPs (MetalLB and the
		// like) take external traffic on the service port.
		rules.externalIPs = append(append(rules.externalIPs, svcInfo.ExternalIPs()...), svcInfo.LoadBalancerVIPs()...)
		if svcInfo.ExternallyAccessible() {
			rules.external = newPFTarget(externalEndpoints)
			rules.externalLocal = svcInfo.ExternalPolicyLocal()
			if rules.externalLocal {
				rules.shortCircuit = newPFTarget(shortCircuitEndpoints)
			}
		}
		if svcInfo.Protocol() == v1.ProtocolUDP {
			if rules.internal != nil {
				udpFronts[pfAddrPort(svcInfo.ClusterIP().String(), svcInfo.Port())] = rules.internal.addrPorts()
			}
			endpoints := sets.New[string]()
			for _, t := range []*pfTarget{rules.external, rules.shortCircuit} {
				if t != nil {
					endpoints = endpoints.Union(t.addrPorts())
				}
			}
			for _, d := range rules.externalDestinations() {
				udpFronts[pfAddrPort(d.ip.String(), d.port)] = endpoints
			}
		}
		if rules.internal == nil && rules.external == nil && rules.shortCircuit == nil {
			// No endpoints (left): drop the rules that still redirect
			// to the old ones.
			if err := flushAnchor(proxier.exec, "cni-rdr/"+svcInfo.anchorName); err != nil {
				klog.ErrorS(err, "Failed to flush rules of service without endpoints", "service", svcName)
			}
			continue
		}

		rules.af = "inet"
		if proxier.ipFamily == v1.IPv6Protocol {
			rules.af = "inet6"
		}

		switch svcInfo.Protocol() {
		case v1.ProtocolTCP:
			rules.proto = "tcp"
		case v1.ProtocolUDP:
			rules.proto = "udp"
		case v1.ProtocolSCTP:
			rules.proto = "sctp"
		}

		proxier.pfData.Reset()
		proxier.writeServiceRules(&rules)

		if proxier.logger.V(2).Enabled() {
			klog.Infof("pfctl -a cni-rdr/%s -f - <EOF", svcInfo.anchorName)
			tmp := strings.Split(proxier.pfData.String(), "\n")
			for _, r := range tmp[:len(tmp)-1] {
				klog.Infof("%s", r)
			}
			klog.Infof("EOF")
		}
		input := proxier.pfData.Bytes()
		cmd := proxier.exec.Command("pfctl", "-a", "cni-rdr/"+svcInfo.anchorName, "-f", "-")
		cmd.SetStdin(bytes.NewReader(input))
		output, err := cmd.CombinedOutput()
		if err != nil {
			klog.Errorf("error loading rules input: '%s', output: %s, err: %v", input, output, err)
		}
	}
	proxier.killStaleUDPStates(udpFronts)
	for a := range staleAnchors {
		proxier.logger.V(2).Info("deleting PF anchor", a)
		if err := flushAnchor(proxier.exec, "cni-rdr/"+a); err != nil {
			klog.Errorf("error flushing rules, err: %v", err)
		}
	}

	// Without this, /healthz and /livez report kube-proxy unhealthy from
	// the first Service change on.
	if proxier.healthzServer != nil {
		proxier.healthzServer.Updated(proxier.ipFamily)
	}
	metrics.SyncProxyRulesLastTimestamp.WithLabelValues(string(proxier.ipFamily)).SetToCurrentTime()

	// Serve each externalTrafficPolicy: Local Service's healthCheckNodePort:
	// 200 while this node has a ready endpoint, 503 otherwise, so that a
	// load balancer only sends traffic to nodes that won't drop it.
	if err := proxier.serviceHealthServer.SyncServices(proxier.svcPortMap.HealthCheckNodePorts()); err != nil {
		proxier.logger.Error(err, "Error syncing healthcheck services")
	}
	if err := proxier.serviceHealthServer.SyncEndpoints(proxier.endpointsMap.LocalReadyEndpoints()); err != nil {
		proxier.logger.Error(err, "Error syncing healthcheck endpoints")
	}
	return nil
}

func (proxier *Proxier) writeServiceToEndpointRules(svcPortNameString string, svcInfo proxy.ServicePort, endpoints []proxy.Endpoint, args []string) {
	// First write session affinity rules, if applicable.
	if svcInfo.SessionAffinityType() == v1.ServiceAffinityClientIP {
		for _, ep := range endpoints {
			epInfo, ok := ep.(*endpointsInfo)
			if !ok {
				continue
			}
			klog.Infof(`affinity: "%s -> %s"`, svcPortNameString, epInfo.String())
		}
	}

	// Now write loadbalancing rules.
	for _, ep := range endpoints {
		epInfo, ok := ep.(*endpointsInfo)
		if !ok {
			continue
		}
		klog.Infof(`loadbalance: "%s -> %s"`, svcPortNameString, epInfo.String())
	}
}

type noOpLocalDetector struct{}

// NewNoOpLocalDetector is a no-op implementation of LocalTrafficDetector
func NewNoOpLocalDetector() LocalTrafficDetector {
	return &noOpLocalDetector{}
}

func (n *noOpLocalDetector) IsImplemented() bool {
	return false
}

func (n *noOpLocalDetector) IfLocal() string {
	return "any" // no-op; matches all traffic
}

func (n *noOpLocalDetector) IfNotLocal() string {
	return "any" // no-op; matches all traffic
}

func (n *noOpLocalDetector) ToAddress() string {
	return ""
}

type detectLocalByCIDR struct {
	ifLocal    string
	ifNotLocal string
	toAddress  string
}

// NewDetectLocalByCIDR implements the LocalTrafficDetector interface using a CIDR. This can be used when a single CIDR
// range can be used to capture the notion of local traffic.

func NewDetectLocalByCIDR(cidr string) LocalTrafficDetector {
	_, cidrNet, err := netutils.ParseCIDRSloppy(cidr)
	if err != nil {
		return NewNoOpLocalDetector()
	}
	cidrIp, err := netutils.GetIndexedIP(cidrNet, 1)
	if err != nil {
		return NewNoOpLocalDetector()
	}

	return &detectLocalByCIDR{
		ifLocal:    cidr,
		ifNotLocal: "! " + cidr,
		toAddress:  cidrIp.String(),
	}
}

func (d *detectLocalByCIDR) IsImplemented() bool {
	return true
}

func (d *detectLocalByCIDR) IfLocal() string {
	return d.ifLocal
}

func (d *detectLocalByCIDR) IfNotLocal() string {
	return d.ifNotLocal
}

func (d *detectLocalByCIDR) ToAddress() string {
	return d.toAddress
}

type detectLocalByBridgeInterface struct {
	ifLocal    string
	ifNotLocal string
	toAddress  string
}

// NewDetectLocalByBridgeInterface implements the LocalTrafficDetector interface using a bridge interface name.
// This can be used when a bridge can be used to capture the notion of local traffic from pods.
func NewDetectLocalByBridgeInterface(interfaceName string) LocalTrafficDetector {
	if len(interfaceName) == 0 {
		klog.Errorf("no bridge interface name set")
		return NewNoOpLocalDetector()
	}
	return &detectLocalByBridgeInterface{
		ifLocal:    fmt.Sprintf("(%s)", interfaceName),
		ifNotLocal: fmt.Sprintf("! (%s)", interfaceName),
		toAddress:  fmt.Sprintf("(%s)", interfaceName),
	}
}

func (d *detectLocalByBridgeInterface) IsImplemented() bool {
	return true
}

func (d *detectLocalByBridgeInterface) IfLocal() string {
	return d.ifLocal
}

func (d *detectLocalByBridgeInterface) IfNotLocal() string {
	return d.ifNotLocal
}

func (d *detectLocalByBridgeInterface) ToAddress() string {
	return d.toAddress
}
