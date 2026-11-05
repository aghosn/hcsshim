//go:build windows

package main

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

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
