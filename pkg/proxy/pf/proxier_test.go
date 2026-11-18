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

import (
	"net"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
	proxyutil "k8s.io/kubernetes/pkg/proxy/util"
)

func TestRedirectRule(t *testing.T) {
	ip := net.ParseIP("192.168.100.1")
	for _, tc := range []struct {
		name    string
		targets string
		sticky  bool
		tag     string
		want    string
	}{
		{"single", "10.244.1.7", false, "",
			"rdr inet proto tcp from any to 192.168.100.1 port 30080 -> 10.244.1.7 port 8080\n"},
		{"pool", "{ 10.244.1.7, 10.244.0.5 }", false, "",
			"rdr inet proto tcp from any to 192.168.100.1 port 30080 -> { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n"},
		{"sticky", "{ 10.244.1.7, 10.244.0.5 }", true, "",
			"rdr inet proto tcp from any to 192.168.100.1 port 30080 -> { 10.244.1.7, 10.244.0.5 } port 8080 round-robin sticky-address\n"},
		{"nodeport tag", "{ 10.244.1.7 }", false, nodePortTag,
			"rdr inet proto tcp from any to 192.168.100.1 port 30080 tag KUBE_NODEPORT -> { 10.244.1.7 } port 8080 round-robin\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxier{pfData: proxyutil.NewLineBuffer()}
			p.redirectRule("inet", "tcp", "any", ip, 30080, tc.targets, 8080, tc.sticky, tc.tag)
			if got := p.pfData.String(); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestHostRedirectRule(t *testing.T) {
	p := &Proxier{pfData: proxyutil.NewLineBuffer()}
	p.hostRedirectRule("inet", "udp", net.ParseIP("10.96.0.10"), 53, "{ 10.244.0.206, 10.244.0.207 }", 53)
	p.hostRedirectRule("inet", "tcp", net.ParseIP("10.96.0.1"), 443, "{ 192.168.100.1 }", 6443)
	want := "pass out quick inet proto udp from any to 10.96.0.10 port 53 rdr-to { 10.244.0.206, 10.244.0.207 } port 53 round-robin\n" +
		"pass out quick inet proto tcp from any to 10.96.0.1 port 443 rdr-to { 192.168.100.1 } port 6443 round-robin\n"
	if got := p.pfData.String(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// checkOrder fails if a translation rule follows a filter rule: pf refuses
// such an anchor.
func checkOrder(t *testing.T, rules string) {
	t.Helper()
	seenFilter := false
	for _, l := range strings.Split(strings.TrimSpace(rules), "\n") {
		isFilter := strings.HasPrefix(l, "pass") || strings.HasPrefix(l, "block") || strings.HasPrefix(l, "match")
		if seenFilter && !isFilter {
			t.Errorf("translation rule after a filter rule: %q", l)
		}
		seenFilter = seenFilter || isFilter
	}
}

func target(local, remote []string, port int) *pfTarget {
	ips := append(append([]string{}, remote...), local...)
	return &pfTarget{hosts: "{ " + strings.Join(ips, ", ") + " }", port: port, local: local, remote: remote}
}

// A NodePort service with externalTrafficPolicy: Cluster: every kind of
// traffic goes to all endpoints, and the host rules come last.
func TestWriteServiceRulesOrder(t *testing.T) {
	p := &Proxier{pfData: proxyutil.NewLineBuffer(), nodeIP: net.ParseIP("192.168.100.1")}
	all := target([]string{"10.244.0.5"}, []string{"10.244.1.7"}, 8080)
	p.writeServiceRules(&serviceRules{name: "ns/svc:http", af: "inet", proto: "tcp",
		clusterIP: net.ParseIP("10.96.0.20"), port: 80, nodePort: 30080,
		nodeIPs:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.100.1")},
		internal: all, external: all})
	want := "rdr inet proto tcp from any to 10.96.0.20 port 80 -> { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n" +
		"nat inet proto tcp from 10.244.0.5 to 10.244.0.5 port 8080 -> 192.168.100.1\n" +
		"rdr inet proto tcp from any to 192.168.100.1 port 30080 tag KUBE_NODEPORT -> { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n" +
		"nat inet proto tcp from any to { 10.244.1.7 } port 8080 tagged KUBE_NODEPORT -> 192.168.100.1\n" +
		"pass out quick inet proto tcp from any to 10.96.0.20 port 80 rdr-to { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n" +
		"pass out quick on lo0 inet proto tcp from any to 192.168.100.1 port 30080 rdr-to { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n"
	if got := p.pfData.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	checkOrder(t, p.pfData.String())
}

// externalTrafficPolicy: Local with a local endpoint: external clients reach
// only the local endpoint, unmasqueraded (their address is kept); pods and
// the node itself reach all endpoints.
func TestWriteServiceRulesExternalLocal(t *testing.T) {
	p := &Proxier{pfData: proxyutil.NewLineBuffer(), nodeIP: net.ParseIP("192.168.100.1"),
		localDetector: NewDetectLocalByCIDR("10.244.0.0/16")}
	all := target([]string{"10.244.0.5"}, []string{"10.244.1.7"}, 8080)
	p.writeServiceRules(&serviceRules{name: "ns/svc:http", af: "inet", proto: "tcp",
		clusterIP: net.ParseIP("10.96.0.20"), port: 80, nodePort: 30080,
		nodeIPs:  []net.IP{net.ParseIP("192.168.100.1")},
		internal: all, external: target([]string{"10.244.0.5"}, nil, 8080),
		externalLocal: true, shortCircuit: all})
	want := "rdr inet proto tcp from any to 10.96.0.20 port 80 -> { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n" +
		"nat inet proto tcp from 10.244.0.5 to 10.244.0.5 port 8080 -> 192.168.100.1\n" +
		"rdr inet proto tcp from 10.244.0.0/16 to 192.168.100.1 port 30080 tag KUBE_NODEPORT -> { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n" +
		"rdr inet proto tcp from any to 192.168.100.1 port 30080 tag KUBE_NODEPORT -> { 10.244.0.5 } port 8080 round-robin\n" +
		"nat inet proto tcp from any to { 10.244.1.7 } port 8080 tagged KUBE_NODEPORT -> 192.168.100.1\n" +
		"pass out quick inet proto tcp from any to 10.96.0.20 port 80 rdr-to { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n" +
		"pass out quick on lo0 inet proto tcp from any to 192.168.100.1 port 30080 rdr-to { 10.244.1.7, 10.244.0.5 } port 8080 round-robin\n"
	if got := p.pfData.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	checkOrder(t, p.pfData.String())
}

// externalTrafficPolicy: Local without a local endpoint: external NodePort
// traffic is dropped; pods and the node itself still reach the service.
func TestWriteServiceRulesExternalLocalNoLocalEndpoint(t *testing.T) {
	p := &Proxier{pfData: proxyutil.NewLineBuffer(), nodeIP: net.ParseIP("192.168.100.1"),
		localDetector: NewDetectLocalByCIDR("10.244.0.0/16")}
	remote := target(nil, []string{"10.244.1.7"}, 8080)
	p.writeServiceRules(&serviceRules{name: "ns/svc:http", af: "inet", proto: "tcp",
		clusterIP: net.ParseIP("10.96.0.20"), port: 80, nodePort: 30080,
		nodeIPs:  []net.IP{net.ParseIP("192.168.100.1")},
		internal: remote, externalLocal: true, shortCircuit: remote})
	want := "rdr inet proto tcp from any to 10.96.0.20 port 80 -> { 10.244.1.7 } port 8080 round-robin\n" +
		"rdr inet proto tcp from 10.244.0.0/16 to 192.168.100.1 port 30080 tag KUBE_NODEPORT -> { 10.244.1.7 } port 8080 round-robin\n" +
		"nat inet proto tcp from any to { 10.244.1.7 } port 8080 tagged KUBE_NODEPORT -> 192.168.100.1\n" +
		"pass out quick inet proto tcp from any to 10.96.0.20 port 80 rdr-to { 10.244.1.7 } port 8080 round-robin\n" +
		"pass out quick on lo0 inet proto tcp from any to 192.168.100.1 port 30080 rdr-to { 10.244.1.7 } port 8080 round-robin\n" +
		"block drop in quick inet proto tcp from any to 192.168.100.1 port 30080\n"
	if got := p.pfData.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	checkOrder(t, p.pfData.String())
}

func TestNodePortSNATRule(t *testing.T) {
	p := &Proxier{pfData: proxyutil.NewLineBuffer(), nodeIP: net.ParseIP("192.168.100.1")}
	p.nodePortSNATRule("inet", "tcp", "{ 10.244.1.7 }", 8080)
	want := "nat inet proto tcp from any to { 10.244.1.7 } port 8080 tagged KUBE_NODEPORT -> 192.168.100.1\n"
	if got := p.pfData.String(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestStaleUDPStates(t *testing.T) {
	out := `all tcp 10.244.1.7:8080 (192.168.100.2:30080) <- 10.244.0.88:5555       ESTABLISHED:ESTABLISHED
all udp 10.244.1.7:8081 (192.168.100.2:30081) <- 10.244.0.88:4444       MULTIPLE:MULTIPLE
all udp 10.244.1.9:8081 (10.96.0.20:81) <- 10.244.0.88:4445       MULTIPLE:MULTIPLE
all udp 10.244.1.9:8082 (10.96.0.20:81) <- 10.244.0.88:4446       MULTIPLE:MULTIPLE
all udp 10.244.1.5:53 (10.96.0.99:53) <- 10.244.0.88:4447       MULTIPLE:MULTIPLE
all udp fd00::7[53] (fd01::a[53]) <- fd00::8[4448]       MULTIPLE:MULTIPLE
all udp 192.168.100.1:61234 (10.244.0.88:4444) -> 10.244.1.7:8081       MULTIPLE:MULTIPLE
all udp 10.0.2.15:68 <- 10.0.2.2:67       MULTIPLE:MULTIPLE
all udp 192.168.100.2:5353 -> 10.244.0.207:53 (10.96.0.20:81)       SINGLE:NO_TRAFFIC
all udp 192.168.100.2:5354 -> 10.244.1.9:8082 (10.96.0.20:81)       SINGLE:NO_TRAFFIC
`
	states := parseRdrStates(out)
	if len(states) != 8 {
		t.Fatalf("parsed %d rdr states, want 8: %v", len(states), states)
	}
	fronts := udpFrontends{
		// endpoint 10.244.1.7 is gone: state 4444 is stale
		pfAddrPort("192.168.100.2", 30081): sets.New(pfAddrPort("10.244.1.8", 8081)),
		// target port changed 8081 -> 8082: state 4445 is stale, 4446 is not
		pfAddrPort("10.96.0.20", 81): sets.New(pfAddrPort("10.244.1.9", 8082)),
		// no endpoints left: state 4448 is stale
		pfAddrPort("fd01::a", 53): sets.New[string](),
		// 10.96.0.99:53 is not a known UDP frontend: 4447 is left alone
	}
	var got []string
	for _, s := range staleUDPStates(states, fronts) {
		got = append(got, s.key())
	}
	want := []string{
		"udp 192.168.100.2:30081 <- 10.244.0.88:4444",
		"udp 10.96.0.20:81 <- 10.244.0.88:4445",
		"udp fd01::a[53] <- fd00::8[4448]",
		// host-originated (outbound rdr-to) to a gone endpoint; 5354 is current
		"udp 192.168.100.2:5353 -> 10.244.0.207:53",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("stale states:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
