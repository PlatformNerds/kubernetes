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

package mount

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// FreeBSD has no mount propagation: a mount made in a jail (a container) is
// not seen by the host, so a CSI node plugin in a pod can't mount volumes for
// the kubelet the way it does on Linux (mountPropagation: Bidirectional).
// When running in a jail that can reach bsdk8s-mount-proxy (a host daemon,
// like Windows' csi-proxy), Mount, Unmount and List go to it instead: it runs
// them on the host with the caller's paths translated to host paths.

// MountProxySocketEnv overrides where the proxy's socket is looked for.
const MountProxySocketEnv = "BSDK8S_MOUNT_PROXY"

// The proxy listens in the kubelet's plugins/ and in plugins/kubernetes.io/csi/:
// many node plugins mount only the latter (the kubelet's staging directory)
// and their own plugins/<driver>/, not all of plugins/.
var mountProxySockets = []string{
	"/var/db/kubelet/plugins/bsdk8s-mount-proxy.sock",
	"/var/lib/kubelet/plugins/bsdk8s-mount-proxy.sock",
	"/var/db/kubelet/plugins/kubernetes.io/csi/bsdk8s-mount-proxy.sock",
	"/var/lib/kubelet/plugins/kubernetes.io/csi/bsdk8s-mount-proxy.sock",
}

type mountProxyRequest struct {
	Op      string   `json:"op"`
	Source  string   `json:"source,omitempty"`
	Target  string   `json:"target,omitempty"`
	FSType  string   `json:"fstype,omitempty"`
	Options []string `json:"options,omitempty"`
}

type mountProxyMount struct {
	Device string   `json:"device"`
	Path   string   `json:"path"`
	Type   string   `json:"type"`
	Opts   []string `json:"opts,omitempty"`
}

type mountProxyResponse struct {
	Error  string            `json:"error,omitempty"`
	Mounts []mountProxyMount `json:"mounts,omitempty"`
}

// mountProxySocket returns the proxy's socket if this process runs in a jail
// and the socket is reachable, else "".
func mountProxySocket() string {
	if jailed, err := unix.SysctlUint32("security.jail.jailed"); err != nil || jailed == 0 {
		return ""
	}
	candidates := mountProxySockets
	if p := os.Getenv(MountProxySocketEnv); p != "" {
		candidates = []string{p}
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

func mountProxyCall(socket string, req mountProxyRequest) (*mountProxyResponse, error) {
	c, err := net.DialTimeout("unix", socket, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("mount proxy %s: %w", socket, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return nil, fmt.Errorf("mount proxy %s: %w", socket, err)
	}
	var resp mountProxyResponse
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return nil, fmt.Errorf("mount proxy %s: %w", socket, err)
	}
	if resp.Error != "" {
		return &resp, fmt.Errorf("mount proxy: %s", resp.Error)
	}
	return &resp, nil
}

func mountThroughProxy(socket, source, target, fstype string, options []string) error {
	klog.V(4).Infof("Mounting %s on %s (%s, %v) through %s", source, target, fstype, options, socket)
	_, err := mountProxyCall(socket, mountProxyRequest{Op: "mount", Source: source, Target: target, FSType: fstype, Options: options})
	return err
}

func unmountThroughProxy(socket, target string) error {
	klog.V(4).Infof("Unmounting %s through %s", target, socket)
	_, err := mountProxyCall(socket, mountProxyRequest{Op: "unmount", Target: target})
	return err
}

func listThroughProxy(socket string) ([]MountPoint, error) {
	resp, err := mountProxyCall(socket, mountProxyRequest{Op: "list"})
	if err != nil {
		return nil, err
	}
	mps := make([]MountPoint, 0, len(resp.Mounts))
	for _, m := range resp.Mounts {
		mps = append(mps, MountPoint{Device: m.Device, Path: m.Path, Type: m.Type, Opts: m.Opts})
	}
	return mps, nil
}
