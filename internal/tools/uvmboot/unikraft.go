//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/hcsshim/hcn"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/security"
	"github.com/Microsoft/hcsshim/internal/sibling"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/urfave/cli"
)

func prepareUnikraftUplink(name string, cfg *unikraftNetwork) (_ *hcn.HostComputeEndpoint, _ func() error, resultErr error) {
	network, err := sibling.EnsureUplinkNetwork()
	if err != nil {
		return nil, nil, err
	}
	endpoint, err := network.CreateEndpoint(&hcn.HostComputeEndpoint{
		Name: name, SchemaVersion: hcn.V2SchemaVersion(),
		IpConfigurations: []hcn.IpConfig{{IpAddress: cfg.uplink.String(), PrefixLength: 24}},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("allocate configured Unikraft uplink %s: %w", cfg.uplink, err)
	}
	var namespace *hcn.HostComputeNamespace
	joined := false
	cleanup := func() error {
		var err error
		if joined {
			err = errors.Join(err, hcn.RemoveNamespaceEndpoint(namespace.Id, endpoint.Id))
		}
		err = errors.Join(err, endpoint.Delete())
		if namespace != nil {
			err = errors.Join(err, namespace.Delete())
		}
		return err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, cleanup())
		}
	}()
	namespace, err = hcn.NewNamespace(hcn.NamespaceTypeGuest).Create()
	if err != nil {
		return nil, nil, err
	}
	if err := hcn.AddNamespaceEndpoint(namespace.Id, endpoint.Id); err != nil {
		return nil, nil, err
	}
	joined = true
	actual, err := hcn.GetEndpointByID(endpoint.Id)
	if err != nil {
		return nil, nil, err
	}
	if len(actual.IpConfigurations) != 1 || actual.IpConfigurations[0].IpAddress != cfg.uplink.String() ||
		actual.IpConfigurations[0].PrefixLength != 24 || actual.MacAddress == "" {
		return nil, nil, errors.New("HNS did not assign the address embedded in the Unikraft image")
	}
	return actual, cleanup, nil
}

func runUnikraftProvider(ctx context.Context, c *cli.Context, cfg *unikraftConfig,
	plan *siblingStoragePlan, group, cpuGroup string, section *sharedMemorySection) (resultErr error) {
	directory, err := filepath.Abs(c.String(unikraftPackageArgName))
	if err != nil {
		return err
	}
	bundle, err := os.MkdirTemp("", "uvmboot-unikraft-")
	if err != nil {
		return err
	}
	retainResources := false
	defer func() {
		if !retainResources {
			resultErr = errors.Join(resultErr, os.RemoveAll(bundle))
		}
	}()
	options := uvm.NewDefaultOptionsLCOW("uvmboot-0", "uvmboot")
	options.BootFilesPath, options.GuestStateFilePath, options.BundleDirectory = directory, "guest.vmgs", bundle
	options.UseGuestConnection, options.ForwardStdout, options.ForwardStderr = false, false, false
	options.PreferredRootFSType, options.DmVerityMode = uvm.PreferredRootFSTypeNA, false
	options.VPMemDeviceCount, options.SCSIControllerCount = 0, 1
	options.MemorySizeInMB, options.ProcessorCount = cfg.memoryMB+2, 1
	options.AllowOvercommit, options.EnableDeferredCommit = false, false
	hcl := false
	options.HclEnabled, options.SecurityPolicyEnabled = &hcl, true
	options.SecurityPolicy = c.String(securityPolicyArgName)
	options.CPUGroupID = cpuGroup
	options.ConsolePipe = `\\.\pipe\uvmboot-unikraft-` + filepath.Base(bundle)
	scsi, reports, err := cfg.storageDevices(plan)
	if err != nil {
		return err
	}
	options.Appliance = &uvm.LCOWApplianceOptions{SCSI: scsi}
	for _, report := range reports {
		if err := security.GrantVmGroupAccessWithMask(report.HostPath, security.AccessMaskAll); err != nil {
			return fmt.Errorf("grant VM access to %s: %w", report.DiskID, err)
		}
	}
	var releaseEndpoint func() error
	if cfg.network != nil {
		endpoint, release, err := prepareUnikraftUplink(filepath.Base(bundle), cfg.network)
		if err != nil {
			return err
		}
		releaseEndpoint = release
		defer func() {
			if !retainResources {
				resultErr = errors.Join(resultErr, releaseEndpoint())
			}
		}()
		options.Appliance.NetworkAdapters = map[string]hcsschema.NetworkAdapter{
			"00000000-0000-0000-0000-000000000001": {EndpointId: endpoint.Id, MacAddress: endpoint.MacAddress},
		}
	}
	options.SharedMemoryRegions = []uvm.LCOWSharedMemoryRegion{{
		SectionName: section.hcsName, Length: int32(section.size), AllowGuestWrite: true,
	}}
	endpoint, err := siblingCommunicationEndpoint(options.ID, group)
	if err != nil {
		return err
	}
	endpoint.SharedMemorySectionName = section.hcsName
	options.SiblingCommunicationEndpoints = []hcsschema.SiblingCommunicationEndpoint{endpoint}
	listener, err := winio.ListenPipe(options.ConsolePipe, nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	results := filepath.Join(directory, "results")
	if err := os.MkdirAll(results, 0755); err != nil {
		return err
	}
	log, err := os.Create(filepath.Join(results, "unikraft-console.log"))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, log.Close()) }()
	consoleCtx, cancelConsole := context.WithCancel(context.Background())
	consoleDone, ready := make(chan error, 1), make(chan time.Time, 1)
	go func() {
		stopAccept := context.AfterFunc(consoleCtx, func() { _ = listener.Close() })
		defer stopAccept()
		connection, err := listener.Accept()
		if err != nil {
			consoleDone <- err
			return
		}
		defer connection.Close()
		stopRead := context.AfterFunc(consoleCtx, func() { _ = connection.Close() })
		defer stopRead()
		consoleDone <- captureUnikraftConsole(connection, io.MultiWriter(log, os.Stdout), ready)
	}()
	defer func() {
		cancelConsole()
		// VM teardown closes the serial peer; cancellation also unblocks accept/read.
		<-consoleDone
	}()
	createStarted := time.Now()
	vm, err := uvm.CreateLCOW(ctx, options)
	if err != nil {
		return err
	}
	createElapsed := time.Since(createStarted)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := vm.CloseCtx(cleanupCtx); err != nil {
			retainResources = true
			resultErr = errors.Join(resultErr, fmt.Errorf("close Unikraft UVM; retaining boot state %s and endpoint: %w", bundle, err))
		}
	}()
	startRequested := time.Now()
	if err := vm.Start(ctx); err != nil {
		return err
	}
	for _, report := range reports {
		data, err := json.Marshal(report)
		if err != nil {
			return err
		}
		fmt.Printf("storage_backend_config: %s\n", data)
	}
	waitCtx, cancelWait := context.WithCancel(context.Background())
	defer cancelWait()
	exited := make(chan error, 1)
	go func() { exited <- vm.WaitCtx(waitCtx) }()
	timer := time.NewTimer(120 * time.Second)
	defer timer.Stop()
	select {
	case readyAt := <-ready:
		if _, err := fmt.Fprintf(io.MultiWriter(log, os.Stdout),
			"unikraft_boot_timing: create_ms=%.3f start_to_provider_ready_ms=%.3f create_to_provider_ready_ms=%.3f\n",
			float64(createElapsed)/float64(time.Millisecond),
			float64(readyAt.Sub(startRequested))/float64(time.Millisecond),
			float64(readyAt.Sub(createStarted))/float64(time.Millisecond)); err != nil {
			return fmt.Errorf("write Unikraft boot timing: %w", err)
		}
		fmt.Println("Unikraft diode: direct SNP/provider startup observed; dataplane tests run in the workload")
	case <-ctx.Done():
		return fmt.Errorf("unikraft stopped before SNP/provider startup was observed: %w", ctx.Err())
	case <-timer.C:
		return errors.New("unikraft SNP/provider startup timed out; inspect results\\unikraft-console.log")
	case err := <-exited:
		return errors.Join(errors.New("unikraft exited before startup"), err)
	case err := <-consoleDone:
		consoleDone <- err
		return errors.Join(errors.New("unikraft console ended before startup"), err)
	}
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	case err := <-exited:
		return errors.Join(errors.New("unikraft diode exited while workload was active"), err)
	case err := <-consoleDone:
		consoleDone <- err
		return errors.Join(errors.New("unikraft console ended while workload was active"), err)
	}
}

func captureUnikraftConsole(reader io.Reader, output io.Writer, ready chan<- time.Time) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 65536)
	snp, offers, provider, reported := false, false, false, false
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
		snp = snp || strings.Contains(line, "hyperv: isolation type 2 (SNP), paravisor absent")
		offers = offers || strings.Contains(line, "vmbus: all offers delivered")
		if _, version, ok := strings.Cut(line, "sibling: provider ready protocol="); ok {
			fields := strings.Fields(version)
			if len(fields) == 0 {
				return errors.New("unikraft provider omitted its transport version")
			}
			actual, err := strconv.Atoi(strings.TrimSuffix(fields[0], ";"))
			if err != nil || actual != siblingTransportVersion {
				return fmt.Errorf("unikraft provider transport version mismatch: expected=%d actual=%s", siblingTransportVersion, fields[0])
			}
			provider = true
		}
		if snp && offers && provider && !reported {
			ready <- time.Now()
			reported = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}

func unikraftWorkloadCommand(module string, cfg *unikraftConfig, plan *siblingStoragePlan, command string) (string, error) {
	setup := "set -eu; " + siblingBusLoadCommand(module) + siblingInstanceDiscoveryCommand()
	// The shared interactive shell starts here even for a network-only appliance.
	setup += `mkdir -p /run/dtb-exec; mountpoint -q /run/dtb-exec || mount -t tmpfs -o mode=0755 tmpfs /run/dtb-exec; `
	if cfg.network != nil {
		network := cfg.network
		setup += siblingStockNICCommand("dvsc0")
		setup += `[ "$(cat /sys/class/net/dvsc0/address)" = ` + shellSingleQuote(network.peerMAC.String()) +
			` ] || { echo 'Unikraft peer MAC does not match launch manifest' >&2; exit 1; }; ` +
			"ip addr replace " + shellSingleQuote(network.peer.String()+"/30") + " dev dvsc0; " +
			"ip link set dvsc0 up; ip route replace default via " + shellSingleQuote(network.provider.String()) + "; " +
			guestWaitFor(`[ "$(cat /sys/class/net/dvsc0/carrier)" = 1 ]`, "Unikraft peer NIC")
	}
	if plan != nil {
		storage, err := siblingStorageGuestCommand("", workloadRole, plan, nil, false)
		if err != nil {
			return "", err
		}
		setup += storage + "; "
	}
	setup += "echo 'Unikraft workload: requested sibling devices ready'; "
	if command == "" {
		command = ":"
	}
	return setup + command, nil
}
