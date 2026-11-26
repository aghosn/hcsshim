//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/urfave/cli"
	"golang.org/x/sys/windows"
)

const baselineVsockArgName = "network-benchmark-vsock-directory"

type baselineVsockKey struct{}

type baselineVsockSession struct {
	workload chan string
	ready    chan struct{}
}

func validateBaselineVsock(c *cli.Context, groups [][]uint32) error {
	root := c.String(baselineVsockArgName)
	if root == "" {
		return nil
	}
	if !filepath.IsAbs(root) || c.String(networkBenchmarkScriptArgName) == "" ||
		c.GlobalInt(countArgName) != 2 || c.GlobalInt(parallelArgName) != 2 ||
		c.IsSet(baselineNICArgName) || c.IsSet(baselinePairArgName) ||
		c.IsSet(sharedMemorySizeArgName) || c.IsSet(sharedMemoryNameArgName) ||
		c.Bool(sharedMemoryTwoUVMArgName) || c.IsSet(siblingBusGuestModuleArgName) ||
		c.Bool(siblingDiodeUplinkArgName) || c.Bool(siblingStorageRootArgName) ||
		c.String(unikraftPackageArgName) != "" || len(groups) != 2 {
		return errors.New("vsock requires a two-UVM network benchmark, absolute runtime directory and no sibling, shared memory, other baseline or Unikraft")
	}
	priorities, err := parseCPUGroupPriorities(c.String(cpuGroupPrioritiesArgName))
	if err != nil {
		return err
	}
	_, first, err := canonicalLPs(groups[0])
	if err != nil {
		return err
	}
	_, second, err := canonicalLPs(groups[1])
	if err != nil {
		return err
	}
	if first == second {
		if len(groups[0]) != 2 || len(priorities) != 2 || priorities[0] != 1 || priorities[1] != 1 {
			return errors.New("vsock11 requires identical two-LP affinities and explicit scheduling priorities 1,1")
		}
	} else {
		if len(priorities) != 0 {
			return errors.New("vsockseparate requires disjoint guest CPU groups without explicit priorities")
		}
		for _, a := range groups[0] {
			for _, b := range groups[1] {
				if a == b {
					return errors.New("vsockseparate requires disjoint guest CPU groups without overlapping LPs")
				}
			}
		}
	}
	for _, name := range []string{
		"podctrl/bin/vsock-tun-windows.exe", "podctrl/bin/vsock-tun-linux-musl",
		"tun.ko", "diode_tcpbulk", iperfGuestName, "diode_iptables",
	} {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return fmt.Errorf("vsock input %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("vsock input is not a regular file: %s", name)
		}
	}
	return nil
}

// Keep subprocess output separate from guest measurement markers, while waiting
// for the relay's actual bind/listen completion rather than a fixed startup sleep.
type baselineVsockRelayLog struct {
	mu    sync.Mutex
	text  string
	ready chan struct{}
	once  sync.Once
	out   io.Writer
}

func (l *baselineVsockRelayLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.out.Write(p); err != nil {
		return 0, err
	}
	l.text += string(p)
	if strings.Contains(l.text, "relay ready; waiting for VM ") {
		l.once.Do(func() { close(l.ready) })
	}
	if len(l.text) > 4096 {
		l.text = l.text[len(l.text)-4096:]
	}
	return len(p), nil
}

func sampleBaselineVsockRelayCPU(pid int, output io.Writer) (func() error, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, fmt.Errorf("open vsock relay CPU counters: %w", err)
	}
	type sample struct {
		TimeUTC   time.Time `json:"time_utc"`
		RuntimeNS uint64    `json:"runtime_ns"`
	}
	var samples []sample
	query := func() error {
		var created, exited, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
			return fmt.Errorf("query vsock relay CPU: %w", err)
		}
		ticks := (uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)) +
			(uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime))
		samples = append(samples, sample{time.Now().UTC(), ticks * 100})
		return nil
	}
	if err := query(); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var samplingErr error
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if samplingErr = query(); samplingErr != nil {
					return
				}
			case <-stop:
				samplingErr = query()
				return
			}
		}
	}()
	var once sync.Once
	var resultErr error
	return func() error {
		once.Do(func() {
			close(stop)
			<-done
			resultErr = errors.Join(samplingErr, windows.CloseHandle(handle))
			if resultErr != nil {
				return
			}
			record, err := json.Marshal(struct {
				PID     int      `json:"pid"`
				Samples []sample `json:"samples"`
			}{pid, samples})
			if err == nil {
				_, err = fmt.Fprintf(output, "network_benchmark_relay_cpu: %s\n", record)
			}
			resultErr = err
		})
		return resultErr
	}, nil
}

func startBaselineVsockRelay(ctx context.Context, executable, diodeID, workloadID string, sampleCPU bool) (func() error, error) {
	command := exec.CommandContext(ctx, executable, "--relay", "--vm-id", diodeID,
		"--peer-vm-id", workloadID, "--port", "1024", "--mtu", "1500")
	output := &baselineVsockRelayLog{ready: make(chan struct{}), out: os.Stdout}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start vsock host relay: %w", err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(done) }()
	stopSampling := func() error { return nil }
	if sampleCPU {
		sampler, err := sampleBaselineVsockRelayCPU(command.Process.Pid, os.Stdout)
		if err != nil {
			killErr := command.Process.Kill()
			<-done
			return nil, errors.Join(err, killErr)
		}
		stopSampling = sampler
	}
	var once sync.Once
	var stopErr error
	stop := func() error {
		once.Do(func() {
			stopErr = stopSampling()
			select {
			case <-done:
				stopErr = errors.Join(stopErr, errors.New("vsock relay exited unexpectedly"))
				if waitErr != nil {
					stopErr = fmt.Errorf("%w: %w", stopErr, waitErr)
				}
			default:
				if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					stopErr = fmt.Errorf("stop vsock relay: %w", err)
				}
				<-done
			}
			if command.ProcessState != nil {
				fmt.Printf("vsock_relay_cpu: pid=%d user_ns=%d system_ns=%d scope=relay-process-entire-lifetime\n",
					command.Process.Pid, command.ProcessState.UserTime().Nanoseconds(),
					command.ProcessState.SystemTime().Nanoseconds())
			}
		})
		return stopErr
	}
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-output.ready:
		fmt.Printf("vsock_relay: pid=%d diode=%s workload=%s port=1024 mtu=1500\n",
			command.Process.Pid, diodeID, workloadID)
		return stop, nil
	case <-done:
		_ = stop()
		return nil, fmt.Errorf("vsock relay exited before listening: %w", waitErr)
	case <-timer.C:
		_ = stop()
		return nil, errors.New("vsock relay did not listen within 30 seconds")
	case <-ctx.Done():
		_ = stop()
		return nil, ctx.Err()
	}
}

func baselineVsockGuestCommand(c *cli.Context, role string, nic *diodeUplink) string {
	command := `set -eu; ` + siblingTCPBulkStage + `set -eu; ` +
		`cp /run/vsock-endpoint/vsock-tun-linux-musl /run/dtb-exec/vsock-tun-linux; ` +
		`chmod 755 /run/dtb-exec/vsock-tun-linux; ` +
		`insmod /run/vsock-tun/tun.ko; ` +
		`[ "$(cat /sys/class/misc/tun/dev)" = 10:200 ]; ` +
		`mkdir -p /dev/net; [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200; ` +
		`(/run/dtb-exec/vsock-tun-linux --cid 2 --port 1024 --iface tun0 --mtu 1500 ` +
		`>/run/dtb-exec/vsock-tun.log 2>&1) & endpoint=$!; ` +
		`trap 'status=$?; kill "$endpoint" 2>/dev/null || :; wait "$endpoint" 2>/dev/null || :; ` +
		`if [ "$status" -ne 0 ]; then cat /run/dtb-exec/vsock-tun.log >&2; fi; exit "$status"' EXIT; ` +
		guestWaitFor(`ip link show tun0 >/dev/null 2>&1`, "vsock tunnel")
	if role == diodeRole {
		command += siblingDiodeUplinkCommand(nic, guestWaitFor) + `set -eu; ` +
			`ip addr add 192.168.127.1/30 dev tun0; ` +
			`echo 1 >/proc/sys/net/ipv4/ip_forward; ` +
			`"$ipt" iptables -w -t nat -A POSTROUTING -s 192.168.127.0/30 -o "$up" -j MASQUERADE; ` +
			networkBenchmarkVPPreflight("vsock-diode", c.String(networkBenchmarkServerArgName),
				c.Bool(networkBenchmarkNoSMTArgName), c.String(networkBenchmarkIdleArgName), requestedVMProcessors(c, "uvmboot-0")) +
			`[ "$(basename "$(readlink /sys/class/net/$up/device/driver)")" = hv_netvsc ]; ` +
			`echo 'network_benchmark: vsock diode forwarding ready'; ` +
			`(status=0; "$dtb" sink 5001 >/run/dtb-exec/vsock-done.log 2>&1 || status=$?; ` +
			`echo "$status" >/run/dtb-exec/vsock-done.status) & sink=$!; ` +
			`ip link set tun0 up mtu 1500; ` +
			`while [ ! -f /run/dtb-exec/vsock-done.status ]; do ` +
			`kill -0 "$endpoint" || { echo 'vsock: endpoint died' >&2; exit 1; }; sleep 1; done; ` +
			`wait "$sink"; cat /run/dtb-exec/vsock-done.log; [ "$(cat /run/dtb-exec/vsock-done.status)" = 0 ]; `
	} else {
		command += `ip addr add 192.168.127.2/30 dev tun0; ip link set tun0 up mtu 1500; ` +
			`ip route add default via 192.168.127.1 dev tun0; ` +
			guestWaitFor(`ping -c 1 -W 1 192.168.127.1 >/dev/null 2>&1`, "vsock diode") +
			networkBenchmarkClient(c, "vsock") +
			`"$dtb" send 192.168.127.1 5001 1 >/dev/null; `
	}
	return command
}

func prepareBaselineVsock(ctx context.Context, c *cli.Context, vm *uvm.UtilityVM) (string, func() error, error) {
	session, ok := ctx.Value(baselineVsockKey{}).(*baselineVsockSession)
	if !ok {
		return "", nil, errors.New("vsock session is not initialized")
	}
	role, err := sharedMemoryProofRole(vm.ID())
	if err != nil {
		return "", nil, err
	}
	root := c.String(baselineVsockArgName)
	for _, item := range []struct{ file, guest string }{
		{"podctrl/bin/vsock-tun-linux-musl", "/run/vsock-endpoint"},
		{"tun.ko", "/run/vsock-tun"},
		{"diode_tcpbulk", "/run/diode-tcpbulk"},
		{iperfGuestName, iperfGuestShare},
		{"diode_iptables", "/run/diode-iptables"},
	} {
		if err := vm.Share(ctx, filepath.Join(root, filepath.FromSlash(item.file)), item.guest, true); err != nil {
			return "", nil, fmt.Errorf("stage vsock %s: %w", item.file, err)
		}
	}
	noop := func() error { return nil }
	if role == workloadRole {
		select {
		case session.workload <- vm.RuntimeID().String():
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
		select {
		case <-session.ready:
			return baselineVsockGuestCommand(c, role, nil), noop, nil
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}
	nic, release, err := attachDiodeUplink(ctx, vm)
	if err != nil {
		return "", nil, err
	}
	var peer string
	select {
	case peer = <-session.workload:
	case <-ctx.Done():
		release()
		return "", nil, ctx.Err()
	}
	sampleCPU, err := networkBenchmarkCPUEnabled(c)
	if err != nil {
		release()
		return "", nil, err
	}
	stop, err := startBaselineVsockRelay(ctx,
		filepath.Join(root, "podctrl", "bin", "vsock-tun-windows.exe"), vm.RuntimeID().String(), peer, sampleCPU)
	if err != nil {
		release()
		return "", nil, err
	}
	close(session.ready)
	return baselineVsockGuestCommand(c, role, nic), func() error {
		err := stop()
		release()
		return err
	}, nil
}
