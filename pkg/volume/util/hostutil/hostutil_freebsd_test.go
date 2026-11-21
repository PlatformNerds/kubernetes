//go:build freebsd

package hostutil

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

var (
	unixSysctl = unix.Sysctl
	fields     = strings.Fields
)

func splitLines(s string) []string { return strings.Split(s, "\n") }

func TestGeomProviderListed(t *testing.T) {
	conf := "0 DISK vtbd0 85899345920 512 hd 16 sc 63\n1 PART vtbd0p4 84790426624 512 i 4\n2 LABEL gpt/swapfs 1073741824 512 i 0 o 0\n0 MD md0 20971520 512 u 0 s 512\n"
	for name, want := range map[string]bool{"vtbd0": true, "vtbd0p4": true, "gpt/swapfs": true, "md0": true, "md1": false, "null": false, "DISK": false} {
		if got := geomProviderListed(conf, name); got != want {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
}

func TestGetFileTypeDevices(t *testing.T) {
	hu := NewHostUtil()
	if got, err := hu.GetFileType("/dev/null"); err != nil || got != FileTypeCharDev {
		t.Errorf("/dev/null: %v %v", got, err)
	}
	conf, err := unixSysctl("kern.geom.conftxt")
	if err != nil {
		t.Skip(err)
	}
	for _, line := range splitLines(conf) {
		f := fields(line)
		if len(f) >= 3 && f[1] == "DISK" {
			if got, err := hu.GetFileType("/dev/" + f[2]); err != nil || got != FileTypeBlockDev {
				t.Errorf("/dev/%s: %v %v", f[2], got, err)
			}
			return
		}
	}
}
