//go:build freebsd

package sysctl

import (
	"context"
	"testing"
)

func TestSafeSysctlAllowlistFreeBSD(t *testing.T) {
	got := SafeSysctlAllowlist(context.Background())
	want := map[string]bool{"net.ipv4.ip_local_port_range": true, "net.ipv4.ip_unprivileged_port_start": true}
	if len(got) != len(want) {
		t.Fatalf("SafeSysctlAllowlist() = %v, want %v", got, want)
	}
	for _, s := range got {
		if !want[s] {
			t.Errorf("unexpected safe sysctl %q", s)
		}
	}
}
