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
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/klog/v2"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/config"
	utilexec "k8s.io/utils/exec"
)

// maxStates caps the state limit like kube-proxy caps nf_conntrack_max on
// Linux (pkg/proxy/conntrack).
const maxStates = 1048576

// StateOptions returns the pf options ("set" lines of pf.conf) that do what
// kube-proxy's conntrack settings do on Linux. pf's state table plays the part
// of conntrack, and its options are global, like the nf_conntrack sysctls:
//
//   - maxPerCore x CPUs (at least min) -> "set limit states"
//   - tcpEstablishedTimeout -> "set timeout tcp.established"
//   - tcpCloseWaitTimeout -> "set timeout tcp.closing", pf's timeout once one
//     side has sent a FIN (conntrack's CLOSE_WAIT). pf's default is 15
//     minutes; kube-proxy's is an hour, because a half-closed connection
//     through a Service loses its translation when the state expires.
//   - udpTimeout -> "set timeout udp.single" (one side has sent: conntrack's
//     UNREPLIED), udpStreamTimeout -> "set timeout udp.multiple" (both sides).
//
// Unset and zero values leave pf's setting alone, as on Linux. tcpBeLiberal has
// no global pf counterpart (pf's "sloppy" state tracking is per rule).
func StateOptions(config *proxyconfigapi.KubeProxyConntrackConfiguration, numCPU int) []string {
	var opts []string
	if config.MaxPerCore != nil && *config.MaxPerCore > 0 {
		limit := int(*config.MaxPerCore) * numCPU
		if config.Min != nil && int(*config.Min) > limit {
			limit = int(*config.Min)
		}
		if limit > maxStates {
			limit = maxStates
		}
		opts = append(opts, fmt.Sprintf("set limit states %d", limit))
	}
	timeout := func(name string, d time.Duration) {
		if s := int(d / time.Second); s > 0 {
			opts = append(opts, fmt.Sprintf("set timeout %s %d", name, s))
		}
	}
	if config.TCPEstablishedTimeout != nil {
		timeout("tcp.established", config.TCPEstablishedTimeout.Duration)
	}
	if config.TCPCloseWaitTimeout != nil {
		timeout("tcp.closing", config.TCPCloseWaitTimeout.Duration)
	}
	timeout("udp.single", config.UDPTimeout.Duration)
	timeout("udp.multiple", config.UDPStreamTimeout.Duration)
	return opts
}

// SetStateOptions applies StateOptions to pf, changing only those options
// (pfctl -m: merge; -O: options only, rules untouched).
func SetStateOptions(ctx context.Context, execer utilexec.Interface, config *proxyconfigapi.KubeProxyConntrackConfiguration, numCPU int) error {
	logger := klog.FromContext(ctx)
	if config.TCPBeLiberal {
		logger.Info("Ignoring conntrack tcpBeLiberal: pf has no global equivalent")
	}
	opts := StateOptions(config, numCPU)
	if len(opts) == 0 {
		return nil
	}
	logger.Info("Setting pf state options from the conntrack configuration", "options", opts)
	cmd := execer.CommandContext(ctx, "pfctl", "-m", "-O", "-f", "-")
	cmd.SetStdin(strings.NewReader(strings.Join(opts, "\n") + "\n"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl -m -O -f -: %w: %s", err, out)
	}
	return nil
}
