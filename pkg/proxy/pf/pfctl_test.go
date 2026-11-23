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
	"errors"
	"io"
	"testing"
	"time"

	"k8s.io/utils/exec"
	fakeexec "k8s.io/utils/exec/testing"
)

// fakePfctl returns an exec whose pfctl commands give results in turn, and
// records each command's stdin.
func fakePfctl(results []error, outputs []string, stdins *[]string) *fakeexec.FakeExec {
	fe := &fakeexec.FakeExec{}
	for i := range results {
		i := i
		fcmd := &fakeexec.FakeCmd{
			CombinedOutputScript: []fakeexec.FakeAction{
				func() ([]byte, []byte, error) { return []byte(outputs[i]), nil, results[i] },
			},
		}
		fe.CommandScript = append(fe.CommandScript, func(cmd string, args ...string) exec.Cmd {
			c := fakeexec.InitFakeCmd(fcmd, cmd, args...)
			return &stdinRecorder{Cmd: c, fcmd: fcmd, stdins: stdins}
		})
	}
	return fe
}

type stdinRecorder struct {
	exec.Cmd
	fcmd   *fakeexec.FakeCmd
	stdins *[]string
}

func (r *stdinRecorder) CombinedOutput() ([]byte, error) {
	if r.fcmd.Stdin != nil {
		b, _ := io.ReadAll(r.fcmd.Stdin)
		*r.stdins = append(*r.stdins, string(b))
	}
	return r.Cmd.CombinedOutput()
}

func TestRunPfctl(t *testing.T) {
	sleep = func(time.Duration) {}
	defer func() { sleep = time.Sleep }()
	fail := errors.New("exit status 1")
	busy := "pfctl: DIOCADDADDR: Device busy\n"

	for _, tc := range []struct {
		name    string
		results []error
		outputs []string
		calls   int
		wantErr bool
	}{
		{"ok", []error{nil}, []string{""}, 1, false},
		{"busy, then ok", []error{fail, fail, nil}, []string{busy, busy, ""}, 3, false},
		{"other error: no retry", []error{fail}, []string{"pfctl: syntax error\n"}, 1, true},
		{"busy every time: gives up", make([]error, pfctlBusyRetries+1), nil, pfctlBusyRetries + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.outputs == nil {
				for i := range tc.results {
					tc.results[i] = fail
					tc.outputs = append(tc.outputs, busy)
				}
			}
			var stdins []string
			fe := fakePfctl(tc.results, tc.outputs, &stdins)
			_, err := runPfctl(fe, []byte("rules\n"), "-a", "cni-rdr/x", "-f", "-")
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error %v", err, tc.wantErr)
			}
			if fe.CommandCalls != tc.calls {
				t.Errorf("%d pfctl calls, want %d", fe.CommandCalls, tc.calls)
			}
			if len(stdins) != tc.calls {
				t.Errorf("stdin seen %d times, want %d", len(stdins), tc.calls)
			}
			for i, s := range stdins {
				if s != "rules\n" {
					t.Errorf("call %d got stdin %q", i, s)
				}
			}
		})
	}
}
