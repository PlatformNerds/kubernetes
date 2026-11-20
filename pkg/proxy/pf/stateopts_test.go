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
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	"k8s.io/utils/ptr"
)

func TestStateOptions(t *testing.T) {
	d := func(x time.Duration) *metav1.Duration { return &metav1.Duration{Duration: x} }
	for _, tc := range []struct {
		name   string
		config proxyconfigapi.KubeProxyConntrackConfiguration
		cpus   int
		want   []string
	}{{
		name: "kube-proxy defaults",
		config: proxyconfigapi.KubeProxyConntrackConfiguration{
			MaxPerCore: ptr.To[int32](32 * 1024), Min: ptr.To[int32](128 * 1024),
			TCPEstablishedTimeout: d(24 * time.Hour), TCPCloseWaitTimeout: d(time.Hour),
		},
		cpus: 8,
		want: []string{"set limit states 262144", "set timeout tcp.established 86400", "set timeout tcp.closing 3600"},
	}, {
		name:   "min wins on few CPUs",
		config: proxyconfigapi.KubeProxyConntrackConfiguration{MaxPerCore: ptr.To[int32](32 * 1024), Min: ptr.To[int32](128 * 1024)},
		cpus:   2,
		want:   []string{"set limit states 131072"},
	}, {
		name:   "capped",
		config: proxyconfigapi.KubeProxyConntrackConfiguration{MaxPerCore: ptr.To[int32](1 << 20)},
		cpus:   4,
		want:   []string{"set limit states 1048576"},
	}, {
		name: "udp, and zero leaves pf alone",
		config: proxyconfigapi.KubeProxyConntrackConfiguration{
			MaxPerCore: ptr.To[int32](0), TCPEstablishedTimeout: d(0),
			UDPTimeout: metav1.Duration{Duration: 30 * time.Second}, UDPStreamTimeout: metav1.Duration{Duration: 2 * time.Minute},
		},
		cpus: 8,
		want: []string{"set timeout udp.single 30", "set timeout udp.multiple 120"},
	}} {
		if got := StateOptions(&tc.config, tc.cpus); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
