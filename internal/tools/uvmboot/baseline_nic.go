//go:build windows

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/uvm"
)

// Baselines for the diode, both over ordinary HCN NICs (hv_netvsc through the
// host vSwitch) on the diode-uplink NAT network:
//   - baselineNICArgName: one UVM measuring the host endpoint, as the
//     workload does through the diode.
//   - baselinePairArgName: two UVMs, uvmboot-1 measuring uvmboot-0, as the
//     workload does over the sibling link to the diode.
const (
	baselineNICArgName  = "baseline-nic-tcpbulk"
	baselinePairArgName = "baseline-vm-pair-tcpbulk"
)

// baselinePeerAddress carries the pair peer's address to the measuring UVM.
// Both UVMs run in this process (--parallel 2).
var baselinePeerAddress = make(chan string, 1)

// baselineNICUp configures the hot-added NIC, named $up, with the stage of
// diode_tcpbulk as $dtb.
func baselineNICUp(nic *diodeUplink) string {
	return "set +eu; " + siblingTCPBulkStage +
		guestWaitFor("up=; for n in /sys/class/net/*; do n=${n##*/}; "+
			"[ -e /sys/class/net/$n/device ] && up=$n; done; [ -n \"$up\" ]", "baseline nic") +
		"ip addr add " + nic.address + " dev $up; ip link set $up up; " +
		"ip route add default via " + nic.gateway + " dev $up; "
}

func baselineCommand(ctx context.Context, c *cli.Context, vm *uvm.UtilityVM) (string, func(), error) {
	tool := c.String(baselineNICArgName)
	if tool == "" {
		tool = c.String(baselinePairArgName)
	}
	if err := vm.Share(ctx, tool, "/run/diode-tcpbulk", true); err != nil {
		return "", nil, fmt.Errorf("share diode_tcpbulk: %w", err)
	}
	if err := vm.Share(ctx, filepath.Join(filepath.Dir(tool), iperfGuestName), iperfGuestShare, true); err != nil {
		return "", nil, fmt.Errorf("share %s: %w", iperfGuestName, err)
	}
	nic, cleanup, err := attachDiodeUplink(ctx, vm)
	if err != nil {
		return "", nil, err
	}
	if c.IsSet(baselineNICArgName) {
		if c.String(networkBenchmarkScriptArgName) != "" {
			return baselineNICUp(nic) + networkBenchmarkClient(c, "baseline"), cleanup, nil
		}
		// iperf retries its connect for 30s while the NIC comes up.
		return baselineNICUp(nic) + hostEndpointTests(), cleanup, nil
	}

	role, err := sharedMemoryProofRole(vm.ID())
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if role == diodeRole {
		baselinePeerAddress <- strings.Split(nic.address, "/")[0]
		// The measuring UVM connects to the sink once iperf is done.
		return baselineNICUp(nic) +
			fmt.Sprintf("(\"$ipf\" -s -p %d >/dev/null 2>&1 &); ", iperfLinkPort) +
			"(\"$dtb\" sink 5001 >/tmp/dn-tcp 2>&1 &); " +
			fmt.Sprintf("i=0; until grep -q sink /tmp/dn-tcp 2>/dev/null; do i=$((i+1)); [ $i -le %d ] || break; sleep 1; done; ",
				2*benchSeconds+180) +
			"echo \"diode_net: peer done $(tr '\\n' ' ' </tmp/dn-tcp)\"", cleanup, nil
	}
	var peer string
	select {
	case peer = <-baselinePeerAddress:
	case <-time.After(3 * time.Minute):
		cleanup()
		return "", nil, fmt.Errorf("baseline peer address not published")
	case <-ctx.Done():
		cleanup()
		return "", nil, ctx.Err()
	}
	fmt.Printf("baseline pair: addr=%s peer=%s\n", nic.address, peer)
	return baselineNICUp(nic) +
			guestWaitFor("ping -c 1 -W 1 "+peer+" >/dev/null 2>&1", "baseline peer") +
			ipbench("peer", peer, iperfLinkPort) +
			"\"$dtb\" send " + peer + " 5001 1 >/dev/null 2>&1; ",
		cleanup, nil
}
