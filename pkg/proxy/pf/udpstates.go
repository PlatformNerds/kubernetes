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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

// UDP has no connection teardown, so a pf state created by an rdr rule keeps
// sending a client (same source address and port) to the endpoint it first
// picked, even after that endpoint is gone or the Service's target port has
// changed, until the state expires; a client that keeps sending never lets it
// expire. The iptables proxier deletes such conntrack entries; this is the pf
// equivalent: after each sync, kill rdr states for UDP Service frontends whose
// redirect target is no longer a current endpoint.

// udpFrontends maps a UDP Service frontend (ClusterIP:port, NodeIP:nodePort),
// formatted as pfctl prints it, to its current endpoints in the same format.
// An empty set means the Service has no endpoints.
type udpFrontends map[string]sets.Set[string]

// pfAddrPort formats an address and port like pfctl -ss does: "a.b.c.d:port"
// for IPv4, "addr[port]" for IPv6.
func pfAddrPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("%s[%d]", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// pfState is a redirected state from pfctl -ss. Inbound (rdr rules, traffic
// from pods and other nodes):
//
//	all udp 10.244.1.7:8081 (192.168.100.2:30081) <- 10.244.0.88:4444       MULTIPLE:MULTIPLE
//
// outbound (hostRedirectRule, traffic from the node itself):
//
//	all udp 192.168.100.2:5353 -> 10.244.0.207:53 (10.96.0.10:53)       MULTIPLE:MULTIPLE
//
// endpoint is the address after the redirection, frontend the address the
// client sent to (the Service frontend), peer the client.
type pfState struct {
	proto, endpoint, frontend, peer string
	outbound                        bool
}

// key is the state key that pfctl -k key accepts for this state: the
// addresses as they are on the wire.
func (s pfState) key() string {
	if s.outbound {
		return s.proto + " " + s.peer + " -> " + s.endpoint
	}
	return s.proto + " " + s.frontend + " <- " + s.peer
}

func parenthesized(s string) bool {
	return strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")")
}

// parseRdrStates returns the redirected states in pfctl -ss output.
func parseRdrStates(out string) []pfState {
	var states []pfState
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 6 && f[4] == "<-" && parenthesized(f[3]):
			states = append(states, pfState{proto: f[1], endpoint: f[2], frontend: strings.Trim(f[3], "()"), peer: f[5]})
		case len(f) >= 6 && f[3] == "->" && parenthesized(f[5]):
			states = append(states, pfState{proto: f[1], peer: f[2], endpoint: f[4], frontend: strings.Trim(f[5], "()"), outbound: true})
		}
	}
	return states
}

// staleUDPStates returns the UDP states to a known frontend whose endpoint is
// no longer one of that frontend's endpoints.
func staleUDPStates(states []pfState, frontends udpFrontends) []pfState {
	var stale []pfState
	for _, s := range states {
		if s.proto != "udp" {
			continue
		}
		if endpoints, ok := frontends[s.frontend]; ok && !endpoints.Has(s.endpoint) {
			stale = append(stale, s)
		}
	}
	return stale
}

// killStaleUDPStates kills the stale UDP rdr states (see above).
func (proxier *Proxier) killStaleUDPStates(frontends udpFrontends) {
	if len(frontends) == 0 {
		return
	}
	out, err := proxier.exec.Command("pfctl", "-ss").Output()
	if err != nil {
		klog.ErrorS(err, "Failed to list pf states, stale UDP states not cleared")
		return
	}
	for _, s := range staleUDPStates(parseRdrStates(string(out)), frontends) {
		proxier.logger.V(2).Info("Killing stale UDP state", "state", s.key(), "endpoint", s.endpoint)
		if out, err := runPfctl(proxier.exec, nil, "-k", "key", "-k", s.key()); err != nil {
			klog.ErrorS(err, "Failed to kill stale UDP state", "state", s.key(), "output", string(out))
		}
	}
}
