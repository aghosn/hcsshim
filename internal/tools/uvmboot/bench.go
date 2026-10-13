//go:build windows

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"

	"github.com/Microsoft/hcsshim/internal/cpugroup"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

// The network benchmarks use iperf 2: a static Linux build shared into the
// guests as diode_iperf and the Windows build (iperf.exe) as the host
// endpoint, both next to uvmboot.
const (
	benchSecondsArgName = "bench-seconds"
	cpuGroupLPsArgName  = "cpu-group-lps"
	iperfGuestShare     = "/run/diode-iperf"
	iperfGuestName      = "diode_iperf"
	iperfHostName       = "iperf.exe"
	iperfLinkPort       = 5301
)

// benchSeconds is the duration of each iperf test, set from the flag.
var benchSeconds = 15

// iperfStage copies diode_iperf into the exec tmpfs of siblingTCPBulkStage
// as $ipf and defines "ipbench tag ip port secs". ipbench runs a single TCP
// stream upload, then TCP round trips of 100 bytes (bounceback, back to
// back), and prints one diode_net line for each: the final iperf throughput
// line, and the round-trip count with p50/p99/p99.7 in microseconds.
const iperfStage = `ipf=/run/dtb-exec/ipf; cp ` + iperfGuestShare + `/` + iperfGuestName + ` $ipf && chmod 755 $ipf; ` +
	`ipbench() { f=/tmp/ipf-$1; ` +
	`"$ipf" -c $2 -p $3 -t $4 -f m --connect-retry-time 30 >$f-bulk 2>&1; ` +
	`l=$(grep 'Mbits/sec' $f-bulk | tail -n 1); ` +
	`if [ -n "$l" ]; then echo "diode_net: $1-bulk $l"; ` +
	`else echo "diode_net: $1-bulk failed $(tail -n 3 $f-bulk | tr '\n' ' ')"; fi; ` +
	`"$ipf" -c $2 -p $3 -t $4 -e -N --bounceback --bounceback-period 0 ` +
	`--histograms=1u,100000,50,99 --connect-retry-time 30 >$f-rr 2>&1; ` +
	`n=$(grep -o 'cnt([0-9]*)' $f-rr | tail -n 1 | tr -dc 0-9); ` +
	`p=$(grep -o '50.00/99.00/99.7%=[0-9/]*' $f-rr | tail -n 1); ` +
	`if [ -n "$p" ]; then echo "diode_net: $1-rr round_trips=$n p50/p99/p99.7_us=${p#*=}"; ` +
	`else echo "diode_net: $1-rr failed $(tail -n 3 $f-rr | tr '\n' ' ')"; fi; }; `

// ipbench runs the iperf benchmark against ip:port, tagged tag.
func ipbench(tag, ip string, port int) string {
	return fmt.Sprintf("ipbench %s %s %d %d; ", tag, ip, port, benchSeconds)
}

// parseCPUGroupLPs parses "2,3;4,5" into one logical processor list per UVM.
func parseCPUGroupLPs(s string) ([][]uint32, error) {
	if s == "" {
		return nil, nil
	}
	var groups [][]uint32
	for _, group := range strings.Split(s, ";") {
		var lps []uint32
		for _, lp := range strings.Split(group, ",") {
			n, err := strconv.ParseUint(strings.TrimSpace(lp), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("--%s: %w", cpuGroupLPsArgName, err)
			}
			lps = append(lps, uint32(n))
		}
		groups = append(groups, lps)
	}
	return groups, nil
}

// joinCPUGroup creates a host CPU group from uvmboot-N's processor list and
// puts the UVM in it. On failure the UVM runs unpinned. It returns the
// group's cleanup, or nil.
func joinCPUGroup(ctx context.Context, id string, groups [][]uint32, options *uvm.OptionsLCOW) func() {
	n, err := strconv.Atoi(strings.TrimPrefix(id, "uvmboot-"))
	if err != nil || n >= len(groups) {
		return nil
	}
	g, err := guid.NewV4()
	if err == nil {
		err = cpugroup.Create(ctx, g.String(), groups[n])
	}
	if err != nil {
		fmt.Printf("cpu group: %s lps=%v failed: %v\n", id, groups[n], err)
		return nil
	}
	options.CPUGroupID = g.String()
	fmt.Printf("cpu group: %s id=%s lps=%v\n", id, g, groups[n])
	return func() {
		if err := cpugroup.Delete(ctx, g.String()); err != nil {
			fmt.Printf("cpu group: %s delete failed: %v\n", id, err)
		}
	}
}
