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
	"path/filepath"
	"strings"

	"k8s.io/klog/v2"
	kubeletconfig "k8s.io/kubelet/config/v1beta1"

	"k8s.io/kubernetes/cmd/kubeadm/app/constants"
)

// linuxKubernetesDir is constants.KubernetesDir on Linux.
const linuxKubernetesDir = "/etc/kubernetes"

// mutatePlatformPaths adapts the KubeletConfiguration that "kubeadm join" downloads from the cluster
// when a Linux control plane generated it, like Mutate does for Windows nodes: kubeadm keeps its
// files under constants.KubernetesDir, /usr/local/etc/kubernetes on FreeBSD, so the Linux paths of
// the client CA and the static pod directory don't exist here and the kubelet fails to start. The
// systemd-resolved resolver file doesn't exist on FreeBSD either; the kubelet default is used.
func mutatePlatformPaths(cfg *kubeletconfig.KubeletConfiguration) {
	mutateStringField := func(name string, field *string) {
		rest, ok := strings.CutPrefix(*field, linuxKubernetesDir+"/")
		if !ok || constants.KubernetesDir == linuxKubernetesDir {
			return
		}
		*field = filepath.Join(constants.KubernetesDir, rest)
		klog.V(2).Infof("[componentconfig] kubelet/FreeBSD: adapted path for field %q to %q", name, *field)
	}
	mutateStringField("staticPodPath", &cfg.StaticPodPath)
	mutateStringField("authentication.x509.clientCAFile", &cfg.Authentication.X509.ClientCAFile)
	if cfg.ResolverConfig != nil && *cfg.ResolverConfig == kubeletSystemdResolverConfig {
		klog.V(2).Infof("[componentconfig] kubelet/FreeBSD: dropping systemd-resolved field \"resolvConf\" %q", *cfg.ResolverConfig)
		cfg.ResolverConfig = nil
	}
}
