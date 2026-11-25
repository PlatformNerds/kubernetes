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

package componentconfigs

import (
	"testing"

	kubeletconfig "k8s.io/kubelet/config/v1beta1"
	"k8s.io/utils/ptr"
)

func TestMutatePlatformPathsFreeBSD(t *testing.T) {
	cfg := &kubeletconfig.KubeletConfiguration{
		StaticPodPath:  "/etc/kubernetes/manifests",
		ResolverConfig: ptr.To(kubeletSystemdResolverConfig),
	}
	cfg.Authentication.X509.ClientCAFile = "/etc/kubernetes/pki/ca.crt"
	mutatePlatformPaths(cfg)
	if cfg.StaticPodPath != "/usr/local/etc/kubernetes/manifests" {
		t.Errorf("staticPodPath = %q", cfg.StaticPodPath)
	}
	if cfg.Authentication.X509.ClientCAFile != "/usr/local/etc/kubernetes/pki/ca.crt" {
		t.Errorf("clientCAFile = %q", cfg.Authentication.X509.ClientCAFile)
	}
	if cfg.ResolverConfig != nil {
		t.Errorf("resolvConf = %q, want unset", *cfg.ResolverConfig)
	}

	// A FreeBSD control plane's config is left alone.
	own := &kubeletconfig.KubeletConfiguration{
		StaticPodPath:  "/usr/local/etc/kubernetes/manifests",
		ResolverConfig: ptr.To("/usr/local/etc/kubernetes/resolv.conf"),
	}
	mutatePlatformPaths(own)
	if own.StaticPodPath != "/usr/local/etc/kubernetes/manifests" || *own.ResolverConfig != "/usr/local/etc/kubernetes/resolv.conf" {
		t.Errorf("FreeBSD paths changed: %q %q", own.StaticPodPath, *own.ResolverConfig)
	}
}
