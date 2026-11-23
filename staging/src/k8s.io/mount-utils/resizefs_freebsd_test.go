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

import "testing"

// Header of dumpfs(8) on a 64 MiB UFS2 file system made by newfs -U.
const dumpfs64M = `magic	19540119 (UFS2)
last mounted time	Mon Nov 23 01:39:28 2026
last modified time	Mon Nov 23 01:39:28 2026
superblock location	65536	id	[ 6b039950 fd87530d ]
ncg	4	size	16384	blocks	15751
bsize	32768	shift	15	mask	0xffff8000
fsize	4096	shift	12	mask	0xfffff000
frag	8	shift	3	fsbtodb	3
minfree	8%	optim	time	symlinklen 120
maxbsize 32768	maxbpg	4096	maxcontig 32	contigsumsize 16
nbfree	1966	ndir	2	nifree	8700	nffree	21
bpg	513	fpg	4104	ipg	2176	unrefs	0
cs[].cs_(nbfree,ndir,nifree,nffree):
	(498,2,2172,13) (500,0,2176,8)

cg 0:
magic	90255	tell	10000	time	Mon Nov 23 01:39:28 2026
cgx	0	ndblk	4104	niblk	2176	initiblk 2176	unrefs 0
`

func TestParseDumpfsSize(t *testing.T) {
	bsize, size, err := parseDumpfsSize(dumpfs64M)
	if err != nil {
		t.Fatal(err)
	}
	if bsize != 32768 || size != 64<<20 {
		t.Errorf("got bsize %d size %d, want 32768 %d", bsize, size, 64<<20)
	}
	if _, _, err := parseDumpfsSize("magic 19540119 (UFS2)\n"); err == nil {
		t.Error("expected an error for output without sizes")
	}
}
