//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNetworkBenchmarkDiagnosticStaging(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell unavailable")
	}
	for _, tc := range []struct {
		name    string
		enabled bool
		helper  bool
		wantErr bool
	}{
		{"receive", true, true, false},
		{"missing-helper", true, false, true},
		{"ordinary", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `set -eu
mount --make-rprivate /
mount -t tmpfs -o size=8m tmpfs /run
mkdir -p /run/diode-controller /run/dtb-exec /run/network-benchmark
`
			if tc.enabled {
				script += "printf 'receive_diagnostics=1\\n' >/run/network-benchmark/plan.sh\n"
			} else {
				script += "printf 'receive_diagnostics=0\\n' >/run/network-benchmark/plan.sh\n"
			}
			if tc.helper {
				script += "printf '#!/bin/sh\\necho helper-ran\\n' >/run/diode-controller/diode-controller\n"
			}
			script += networkBenchmarkDiagnosticStage("/run/network-benchmark/plan.sh") + "\n"
			if tc.enabled {
				script += "/run/dtb-exec/diode-controller net-diagnostics\n"
			} else {
				script += "test ! -e /run/dtb-exec/diode-controller\n"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, shell, "-u", "root", "--exec", "unshare", "--mount", "--fork", "/bin/sh")
			cmd.Stdin = strings.NewReader(script)
			output, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantErr {
				t.Fatalf("staging error=%v, want error=%v\n%s", err, tc.wantErr, output)
			}
			if tc.wantErr && !strings.Contains(string(output), "diagnostic helper staging failed") {
				t.Fatalf("missing explicit staging failure: %s", output)
			}
			if tc.enabled && !tc.wantErr && !strings.Contains(string(output), "helper-ran") {
				t.Fatalf("staged helper did not execute: %s", output)
			}
		})
	}
}

func TestDemoControllerStaging(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell unavailable")
	}
	script := `set -eu
mount --make-rprivate /
mount -t tmpfs -o size=48m tmpfs /run
for spec in diode-tcpbulk:diode_tcpbulk diode-covert:covert_udp diode-tcpdump:diode_tcpdump diode-tc:diode_tc diode-controller:diode-controller; do
    directory=/run/${spec%%:*}; file=${spec#*:}
    mkdir -p "$directory"
    dd if=/dev/zero of="$directory/$file" bs=1M count=4 2>/dev/null
done
mkdir -p /run/diode-demo ` + iperfGuestShare + `
printf '#!/bin/sh\nexit 0\n' >/run/diode-demo/demo.sh
dd if=/dev/zero of=` + iperfGuestShare + `/` + iperfGuestName + ` bs=1M count=4 2>/dev/null
` + siblingTCPBulkStage + `
test -x /run/dtb-exec/diode-controller
test -x /run/dtb-exec/demo.sh
cmp /run/diode-controller/diode-controller /run/dtb-exec/diode-controller
cmp /run/diode-demo/demo.sh /run/dtb-exec/demo.sh
cmp ` + iperfGuestShare + `/` + iperfGuestName + ` /run/dtb-exec/ipf
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-u", "root", "--exec", "unshare", "--mount", "--fork", "/bin/sh")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("demo/controller executable staging failed: %v\n%s", err, output)
	}
}
