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

import (
	"net"
	"testing"

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
			p.redirectRule("inet", "tcp", ip, 30080, tc.targets, 8080, tc.sticky, tc.tag)
			if got := p.pfData.String(); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestNodePortSNATRule(t *testing.T) {
	p := &Proxier{pfData: proxyutil.NewLineBuffer(), nodeIP: net.ParseIP("192.168.100.1")}
	p.nodePortSNATRule("inet", "tcp", "{ 10.244.1.7 }", 8080)
	want := "nat inet proto tcp from any to { 10.244.1.7 } port 8080 tagged KUBE_NODEPORT -> 192.168.100.1\n"
	if got := p.pfData.String(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
