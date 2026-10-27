//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/containerd/console"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/Microsoft/hcsshim/internal/cmd"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/memory"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

const (
	annotationsArgName                = "annotation"
	bootFilesPathArgName              = "boot-files-path"
	consolePipeArgName                = "console-pipe"
	execFileArgName                   = "exec-file"
	kernelDirectArgName               = "kernel-direct"
	kernelFileArgName                 = "kernel-file"
	forwardStdoutArgName              = "fwd-stdout"
	forwardStderrArgName              = "fwd-stderr"
	outputHandlingArgName             = "output-handling"
	kernelArgsArgName                 = "kernel-args"
	rootFSTypeArgName                 = "root-fs-type"
	vpMemMaxCountArgName              = "vpmem-max-count"
	vpMemMaxSizeArgName               = "vpmem-max-size"
	scsiMountsArgName                 = "mount-scsi"
	vpmemMountsArgName                = "mount-vpmem"
	shareFilesArgName                 = "share"
	securityPolicyArgName             = "security-policy"
	securityHardwareFlag              = "security-hardware"
	noVerityBoot                      = "no-verity-boot"
	securityPolicyEnforcerArgName     = "security-policy-enforcer"
	sharedMemoryNameArgName           = "shared-memory-name"
	sharedMemorySizeArgName           = "shared-memory-size"
	sharedMemoryObserveArgName        = "shared-memory-observe-duration"
	sharedMemoryTwoUVMArgName         = "shared-memory-two-uvm-proof"
	sharedMemoryMappingOnlyArgName    = "shared-memory-mapping-only"
	sharedMemoryGuestInventoryArgName = "shared-memory-guest-inventory"
	sharedMemoryGuestModuleArgName    = "shared-memory-guest-module"
	siblingBusGuestModuleArgName      = "sibling-bus-guest-module"
	siblingDiodeUplinkArgName         = "sibling-diode-uplink"
	siblingOpenShellBundleArgName     = "sibling-openshell-bundle"
)

var (
	lcowUseTerminal     bool
	lcowDisableTimeSync bool
)

var lcowCommand = cli.Command{
	Name:  "lcow",
	Usage: "Boot an LCOW UVM",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name: annotationsArgName,
			Usage: "Annotations in the form of `key=value` to apply to the uVM. Use repeat instances to add multiple. " +
				"Annotations will be applied to uVM settings BEFORE all other settings.",
		},
		cli.StringFlag{
			Name:  kernelArgsArgName,
			Value: "",
			Usage: "Additional arguments to pass to the kernel",
		},
		cli.StringFlag{
			Name:  rootFSTypeArgName,
			Usage: "Either 'initrd', 'vhd' or 'none'. (default: 'vhd' if rootfs.vhd exists)",
		},
		cli.StringFlag{
			Name:  bootFilesPathArgName,
			Usage: "The `path` to the boot files directory",
		},
		cli.UintFlag{
			Name:  vpMemMaxCountArgName,
			Usage: "Number of VPMem devices on the UVM. Uses hcsshim default if not specified",
		},
		cli.Uint64Flag{
			Name:  vpMemMaxSizeArgName,
			Usage: "Size of each VPMem device, in MB. Uses hcsshim default if not specified",
		},
		cli.BoolFlag{
			Name:  kernelDirectArgName,
			Usage: "Use kernel direct booting for UVM (default: true on builds >= 18286)",
		},
		cli.StringFlag{
			Name:  kernelFileArgName,
			Usage: "The kernel `file` to use; either 'kernel' or 'vmlinux'. (default: 'kernel')",
		},
		cli.BoolFlag{
			Name:        "disable-time-sync",
			Usage:       "Disable the time synchronization service",
			Destination: &lcowDisableTimeSync,
		},
		cli.StringFlag{
			Name:  securityPolicyArgName,
			Usage: "Security policy to set on the UVM. Leave empty to use an open door policy",
		},
		cli.StringFlag{
			Name: securityPolicyEnforcerArgName,
			Usage: "Security policy enforcer to use for a given security policy. " +
				"Leave empty to use the default enforcer",
		},
		cli.BoolFlag{
			Name:  securityHardwareFlag,
			Usage: "Use VMGS file to run on secure hardware. ('root-fs-type' must be set to 'none')",
		},
		cli.BoolFlag{
			Name:  noVerityBoot,
			Usage: "Do not use verity boot. (IMPORTANT: can only be used together with --security-hardware flag)",
		},
		cli.StringFlag{
			Name:  execCommandLineArgName,
			Usage: "Command to execute in the UVM.",
		},
		cli.StringFlag{
			Name: execFileArgName,
			Usage: "Read the command to execute in the UVM from a host " +
				"file. Mutually exclusive with --exec.",
		},
		cli.BoolFlag{
			Name:  forwardStdoutArgName,
			Usage: "Whether stdout from the process in the UVM should be forwarded",
		},
		cli.BoolFlag{
			Name:  forwardStderrArgName,
			Usage: "Whether stderr from the process in the UVM should be forwarded",
		},
		cli.StringFlag{
			Name:  outputHandlingArgName,
			Usage: "Controls how output from UVM is handled. Use 'stdout' to print all output to stdout",
		},
		cli.StringFlag{
			Name:  consolePipeArgName,
			Usage: "Named `pipe` for serial console output (which will be enabled)",
		},
		cli.BoolFlag{
			Name:        "tty,t",
			Usage:       "create the process in the UVM with a TTY enabled",
			Destination: &lcowUseTerminal,
		},
		cli.StringSliceFlag{
			Name: scsiMountsArgName,
			Usage: "List of VHDs to SCSI mount into the UVM. Use repeat instances to add multiple. " +
				"Value is of the form `'host[,guest[,w]]'`, where 'host' is path to the VHD, " +
				`'guest' is an optional mount path inside the UVM, and 'w' mounts the VHD as writeable`,
		},
		cli.StringSliceFlag{
			Name: shareFilesArgName,
			Usage: "List of paths or files to plan9 share into the UVM. Use repeat instances to add multiple. " +
				"Value is of the form `'host,guest[,w]' where 'host' is path to the VHD, " +
				`'guest' is the mount path inside the UVM, and 'w' sets the shared files to writeable`,
		},
		cli.StringSliceFlag{
			Name:  vpmemMountsArgName,
			Usage: "List of VHDs to VPMem mount into the UVM. Use repeat instances to add multiple. ",
		},
		cli.StringFlag{
			Name: sharedMemoryNameArgName,
			Usage: "Name of a pagefile-backed Windows section to map into every UVM. " +
				"Requires --shared-memory-size.",
		},
		cli.Uint64Flag{
			Name:  sharedMemorySizeArgName,
			Usage: "Size in bytes of the shared-memory section. Maximum 2147483647.",
		},
		cli.DurationFlag{
			Name: sharedMemoryObserveArgName,
			Usage: "When GCS is disabled, keep the UVM running for this " +
				"duration before terminating it.",
		},
		cli.BoolFlag{
			Name: sharedMemoryTwoUVMArgName,
			Usage: "Assign proof roles A and B to exactly two parallel UVMs " +
				"and verify their shared-memory handshake.",
		},
		cli.BoolFlag{
			Name: sharedMemoryMappingOnlyArgName,
			Usage: "Require every UVM to start with the same shared-memory " +
				"mapping, without accessing the guest pages.",
		},
		cli.BoolFlag{
			Name: sharedMemoryGuestInventoryArgName,
			Usage: "Continue when HCS does not expose the shared-memory GPA " +
				"so a read-only guest resource inventory can run.",
		},
		cli.StringFlag{
			Name: sharedMemoryGuestModuleArgName,
			Usage: "Load this matching hcs_shmem_diag.ko through GCS using " +
				"the exact GPA returned by HCS.",
		},
		cli.StringFlag{
			Name: siblingBusGuestModuleArgName,
			Usage: "After the shared-memory guest module, load this matching " +
				"sibling_bus.ko and wait for the host's sibling-link offer.",
		},
		cli.BoolFlag{
			Name: siblingDiodeUplinkArgName,
			Usage: "With the sibling bus, give the diode a NIC on the " +
				diodeUplinkNetworkName + " HNS NAT network, NAT the workload " +
				"through it and route the workload's default traffic via the diode.",
		},
		cli.StringFlag{
			Name: siblingOpenShellBundleArgName,
			Usage: "Optional OpenShell tar bundle for an interactive sibling pair. " +
				"Run gateway/supervisor on the diode and a network-isolated sandbox " +
				"on the workload; do not load either sibling IP driver.",
		},
		cli.StringFlag{
			Name: baselineNICArgName,
			Usage: "Baseline without the diode: give one UVM a NIC on the " +
				diodeUplinkNetworkName + " HNS NAT network and measure the host " +
				"endpoint over it with this diode_tcpbulk `file`.",
		},
		cli.StringFlag{
			Name: baselinePairArgName,
			Usage: "Reference without the diode: give two UVMs NICs on the " +
				diodeUplinkNetworkName + " HNS NAT network and measure one from " +
				"the other through the host vSwitch with this diode_tcpbulk `file`.",
		},
		cli.IntFlag{
			Name:  benchSecondsArgName,
			Value: 15,
			Usage: "Duration of each iperf test (bulk and round trips) in seconds.",
		},
		cli.StringFlag{
			Name:  siblingTestsArgName,
			Value: allSiblingTests,
			Usage: "Comma-separated tests the sibling workload runs: " + allSiblingTests + ".",
		},
		cli.BoolFlag{
			Name: siblingInteractiveArgName,
			Usage: "With the two-UVM sibling network, run no tests and keep both UVMs " +
				"running for \"attach workload|diode\" until \"stop\".",
		},
		cli.StringFlag{
			Name: cpuGroupLPsArgName,
			Usage: "Pin each UVM to a host CPU group: semicolon-separated logical " +
				"processor lists, the Nth for uvmboot-N, e.g. \"2,3;4,5\".",
		},
		cli.StringFlag{
			Name: cpuGroupPrioritiesArgName,
			Usage: "Optional comma-separated scheduling priorities (0-7), one per UVM. " +
				"Requires CPU affinity; creates distinct groups even for identical LP lists.",
		},
		cli.StringFlag{
			Name:  networkBenchmarkScriptArgName,
			Usage: "Run this network-only benchmark shell script against an external LAN iperf2 server.",
		},
		cli.StringFlag{
			Name:  networkBenchmarkServerArgName,
			Usage: "External LAN server IPv4 address (not this host or a test-network endpoint).",
		},
		cli.IntFlag{
			Name:  networkBenchmarkPortArgName,
			Value: 5201,
			Usage: "External iperf2 base port; port+1 is used for concurrent bulk load.",
		},
		cli.DurationFlag{
			Name:  networkBenchmarkTimeoutArgName,
			Value: time.Hour,
			Usage: "Hard deadline for the complete network-only VM run, including startup.",
		},
		cli.BoolFlag{
			Name:  networkBenchmarkNoSMTArgName,
			Usage: "Use a two-physical-core budget with host SMT disabled, for a baseline or shared-affinity pair.",
		},
	},
	Action: func(c *cli.Context) (resultErr error) {
		execCommand, err := loadExecCommand(c)
		if err != nil {
			return err
		}
		benchSeconds = c.Int(benchSecondsArgName)
		if benchSeconds < 1 {
			return fmt.Errorf("--%s must be at least 1", benchSecondsArgName)
		}
		if siblingTests, err = parseSiblingTests(c.String(siblingTestsArgName)); err != nil {
			return err
		}
		if siblingInteractive = c.Bool(siblingInteractiveArgName); siblingInteractive {
			if !c.Bool(sharedMemoryTwoUVMArgName) {
				return fmt.Errorf("--%s requires --%s", siblingInteractiveArgName, sharedMemoryTwoUVMArgName)
			}
			siblingTests = map[string]bool{}
		}
		cpuGroupLPs, err := parseCPUGroupLPs(c.String(cpuGroupLPsArgName))
		if err != nil {
			return err
		}
		cpuGroupPriorities, err := parseCPUGroupPriorities(c.String(cpuGroupPrioritiesArgName))
		if err != nil {
			return err
		}
		if c.IsSet(cpuGroupPrioritiesArgName) && len(cpuGroupPriorities) == 0 {
			return fmt.Errorf("--%s cannot be empty", cpuGroupPrioritiesArgName)
		}
		if err := validateNetworkBenchmark(c, cpuGroupLPs); err != nil {
			return err
		}
		benchmarkCtx := context.Background()
		var cancelBenchmark context.CancelFunc
		if c.String(networkBenchmarkScriptArgName) != "" {
			topology, err := hostProcessorTopology(benchmarkCtx)
			if err != nil {
				return err
			}
			if err := validateBenchmarkCPUs(topology, cpuGroupLPs, c.Bool(networkBenchmarkNoSMTArgName)); err != nil {
				return err
			}
			siblingTests = map[string]bool{}
			var cancel context.CancelFunc
			benchmarkCtx, cancel = context.WithTimeout(benchmarkCtx, c.Duration(networkBenchmarkTimeoutArgName))
			cancelBenchmark = cancel
			defer cancel()
		}
		cpuGroups, err := prepareCPUGroups(context.Background(), cpuGroupLPs,
			c.GlobalInt(countArgName), hostCPUGroupOperations, cpuGroupPriorities...)
		if err != nil {
			return err
		}
		defer func() {
			resultErr = errors.Join(resultErr, cpuGroups.close(context.Background()))
		}()
		for _, report := range cpuGroups.reports {
			data, err := json.Marshal(report)
			if err != nil {
				return fmt.Errorf("encode CPU group configuration: %w", err)
			}
			fmt.Printf("cpu_group_config: %s\n", data)
		}

		if c.Bool(sharedMemoryGuestInventoryArgName) &&
			(c.Bool(sharedMemoryMappingOnlyArgName) ||
				c.Bool(sharedMemoryTwoUVMArgName)) {
			return fmt.Errorf(
				"--%s is mutually exclusive with --%s and --%s",
				sharedMemoryGuestInventoryArgName,
				sharedMemoryMappingOnlyArgName,
				sharedMemoryTwoUVMArgName,
			)
		}
		if c.Bool(sharedMemoryGuestInventoryArgName) &&
			!c.IsSet(sharedMemorySizeArgName) {
			return fmt.Errorf(
				"--%s requires --%s",
				sharedMemoryGuestInventoryArgName,
				sharedMemorySizeArgName,
			)
		}
		if c.IsSet(sharedMemoryGuestModuleArgName) {
			if !useGCS {
				return fmt.Errorf(
					"--%s requires --gcs",
					sharedMemoryGuestModuleArgName,
				)
			}
			if !c.IsSet(sharedMemorySizeArgName) {
				return fmt.Errorf(
					"--%s requires --%s",
					sharedMemoryGuestModuleArgName,
					sharedMemorySizeArgName,
				)
			}
			if c.IsSet(execCommandLineArgName) || c.IsSet(execFileArgName) {
				return fmt.Errorf(
					"--%s is mutually exclusive with --%s and --%s",
					sharedMemoryGuestModuleArgName,
					execCommandLineArgName,
					execFileArgName,
				)
			}
			if !c.Bool(sharedMemoryTwoUVMArgName) &&
				(c.GlobalInt(countArgName) != 1 ||
					c.GlobalInt(parallelArgName) != 1) {
				return fmt.Errorf(
					"--%s requires --count 1 --parallel 1",
					sharedMemoryGuestModuleArgName,
				)
			}
			if c.Bool(sharedMemoryMappingOnlyArgName) ||
				c.Bool(sharedMemoryGuestInventoryArgName) {
				return fmt.Errorf(
					"--%s is incompatible with other shared-memory "+
						"diagnostic modes",
					sharedMemoryGuestModuleArgName,
				)
			}
			if _, err := os.Stat(c.String(sharedMemoryGuestModuleArgName)); err != nil {
				return fmt.Errorf(
					"inspect shared-memory guest module: %w",
					err,
				)
			}
		}
		if c.IsSet(siblingBusGuestModuleArgName) {
			if !c.IsSet(sharedMemoryGuestModuleArgName) ||
				!c.Bool(sharedMemoryTwoUVMArgName) {
				return fmt.Errorf(
					"--%s requires --%s and --%s",
					siblingBusGuestModuleArgName,
					sharedMemoryGuestModuleArgName,
					sharedMemoryTwoUVMArgName,
				)
			}
			if _, err := os.Stat(c.String(siblingBusGuestModuleArgName)); err != nil {
				return fmt.Errorf("inspect sibling-bus guest module: %w", err)
			}
		}
		for _, flag := range []struct {
			name  string
			count int
		}{{baselineNICArgName, 1}, {baselinePairArgName, 2}} {
			if !c.IsSet(flag.name) {
				continue
			}
			if !useGCS || c.GlobalInt(countArgName) != flag.count ||
				c.GlobalInt(parallelArgName) != flag.count {
				return fmt.Errorf("--%s requires --gcs --count %d --parallel %d",
					flag.name, flag.count, flag.count)
			}
			if c.IsSet(sharedMemorySizeArgName) || c.IsSet(sharedMemoryNameArgName) ||
				c.Bool(sharedMemoryTwoUVMArgName) || c.IsSet(execCommandLineArgName) ||
				c.IsSet(execFileArgName) || (c.IsSet(baselineNICArgName) && c.IsSet(baselinePairArgName)) {
				return fmt.Errorf("--%s is mutually exclusive with shared memory, the other "+
					"baseline and --%s/--%s", flag.name, execCommandLineArgName, execFileArgName)
			}
			if _, err := os.Stat(c.String(flag.name)); err != nil {
				return fmt.Errorf("inspect diode_tcpbulk: %w", err)
			}
		}
		if bundle := c.String(siblingOpenShellBundleArgName); bundle != "" {
			if !siblingInteractive || !c.IsSet(siblingBusGuestModuleArgName) ||
				!c.Bool(siblingDiodeUplinkArgName) {
				return fmt.Errorf("--%s requires the interactive sibling pair and diode uplink",
					siblingOpenShellBundleArgName)
			}
			if info, err := os.Stat(bundle); err != nil {
				return fmt.Errorf("inspect OpenShell bundle: %w", err)
			} else if !info.Mode().IsRegular() {
				return fmt.Errorf("OpenShell bundle is not a regular file: %s", bundle)
			}
		}
		if c.String(networkBenchmarkScriptArgName) == "" && (c.IsSet(baselineNICArgName) ||
			(c.Bool(siblingDiodeUplinkArgName) && c.String(siblingOpenShellBundleArgName) == "")) {
			stop, err := startHostEndpoint()
			if err != nil {
				return err
			}
			defer stop()
		}
		if c.Bool(sharedMemoryMappingOnlyArgName) &&
			c.Bool(sharedMemoryTwoUVMArgName) {
			return fmt.Errorf(
				"--%s and --%s are mutually exclusive",
				sharedMemoryMappingOnlyArgName,
				sharedMemoryTwoUVMArgName,
			)
		}
		if c.Bool(sharedMemoryMappingOnlyArgName) {
			if !c.IsSet(sharedMemorySizeArgName) {
				return fmt.Errorf(
					"--%s requires --%s",
					sharedMemoryMappingOnlyArgName,
					sharedMemorySizeArgName,
				)
			}
			if c.Duration(sharedMemoryObserveArgName) <= 0 {
				return fmt.Errorf(
					"--%s requires a positive --%s",
					sharedMemoryMappingOnlyArgName,
					sharedMemoryObserveArgName,
				)
			}
		}
		if c.Bool(sharedMemoryTwoUVMArgName) {
			if c.GlobalInt(countArgName) != 2 ||
				c.GlobalInt(parallelArgName) != 2 {
				return fmt.Errorf(
					"--%s requires --count 2 --parallel 2",
					sharedMemoryTwoUVMArgName,
				)
			}
			if !c.IsSet(sharedMemoryGuestModuleArgName) &&
				c.Duration(sharedMemoryObserveArgName) < 6*time.Second {
				return fmt.Errorf(
					"--%s requires --%s of at least 6s",
					sharedMemoryTwoUVMArgName,
					sharedMemoryObserveArgName,
				)
			}
		}

		var section *sharedMemorySection
		var siblingCommunicationGroupID string
		if c.Bool(sharedMemoryTwoUVMArgName) {
			groupID, err := guid.NewV4()
			if err != nil {
				return fmt.Errorf("create sibling communication group ID: %w", err)
			}
			siblingCommunicationGroupID = groupID.String()
			logrus.WithField("group-id", siblingCommunicationGroupID).
				Info("created sibling communication group")
		}

		if c.IsSet(sharedMemoryNameArgName) || c.IsSet(sharedMemorySizeArgName) {
			name := c.String(sharedMemoryNameArgName)
			size := c.Uint64(sharedMemorySizeArgName)
			if name == "" {
				name = fmt.Sprintf("hcsshim-uvmboot-shared-%d", os.Getpid())
			}

			var err error
			section, err = createSharedMemorySection(name, size)
			if err != nil {
				return err
			}
			defer func() {
				if err := section.Close(); err != nil {
					logrus.WithError(err).Warn("failed to close shared-memory section")
				}
			}()

			logrus.WithFields(logrus.Fields{
				"section":     section.name,
				"hcs-section": section.hcsName,
				"size":        section.size,
				"seed":        "HCSHMEM1-HOST-SEED",
			}).Info("created shared-memory section")
		}

		var (
			firstErr       error
			errMu          sync.Mutex
			mappingMu      sync.Mutex
			mappingAddress = make(map[string]uint32)
		)
		runMany(c, func(id string) (workerErr error) {
			ctx := benchmarkCtx
			defer func() {
				if workerErr != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = workerErr
					}
					errMu.Unlock()
					if cancelBenchmark != nil {
						cancelBenchmark()
					}
				}
			}()

			options, err := createLCOWOptions(ctx, c, id)
			if err != nil {
				return err
			}
			options.CPUGroupID, err = cpuGroups.groupForVM(id)
			if err != nil {
				return err
			}
			if options.CPUGroupID != "" {
				fmt.Printf("cpu group: %s id=%s\n", id, options.CPUGroupID)
			}
			if c.Bool(securityHardwareFlag) {
				defer os.RemoveAll(options.BundleDirectory)
			}
			if !useGCS && execCommand != "" {
				options.ExecCommandLine = execCommand
			}
			if section != nil {
				options.SharedMemoryRegions = []hcsschema.SharedMemoryRegion{
					{
						SectionName:     section.hcsName,
						Length:          int32(section.size),
						AllowGuestWrite: true,
					},
				}
			}
			if siblingCommunicationGroupID != "" {
				endpoint, err := siblingCommunicationEndpoint(
					id,
					siblingCommunicationGroupID,
				)
				if err != nil {
					return err
				}
				if section != nil {
					endpoint.SharedMemorySectionName = section.hcsName
				}
				options.SiblingCommunicationEndpoints =
					[]hcsschema.SiblingCommunicationEndpoint{endpoint}
			}

			err = runLCOW(
				ctx,
				options,
				c,
				execCommand,
				func(
					uvmID string,
					regions []hcsschema.SharedMemoryRegionInfo,
				) error {
					if !c.Bool(sharedMemoryMappingOnlyArgName) {
						return nil
					}
					if len(regions) != 1 {
						return fmt.Errorf(
							"UVM %s returned %d shared-memory mappings, expected 1",
							uvmID,
							len(regions),
						)
					}
					rawAddress := uint32(
						regions[0].GuestPhysicalAddress,
					)
					mappingMu.Lock()
					mappingAddress[uvmID] = rawAddress
					mappingMu.Unlock()
					return nil
				},
			)
			return err
		})

		if c.Bool(sharedMemoryMappingOnlyArgName) {
			if firstErr != nil {
				return firstErr
			}
			if len(mappingAddress) != c.GlobalInt(countArgName) {
				return fmt.Errorf(
					"received %d shared-memory mappings for %d UVMs",
					len(mappingAddress),
					c.GlobalInt(countArgName),
				)
			}
			var (
				expected     uint32
				haveExpected bool
			)
			for id, address := range mappingAddress {
				if !haveExpected {
					expected = address
					haveExpected = true
					continue
				}
				if address != expected {
					return fmt.Errorf(
						"UVM %s mapped shared memory at %#x, expected %#x",
						id,
						address,
						expected,
					)
				}
			}
			logrus.WithFields(logrus.Fields{
				"byte-gpa":  uint64(expected) << 12,
				"raw":       fmt.Sprintf("%#x", expected),
				"uvm-count": len(mappingAddress),
			}).Info("verified identical shared-memory mappings")
		}

		markerVerified := false
		if section != nil {
			prefixLength := uint64(96)
			if c.Bool(sharedMemoryMappingOnlyArgName) {
				// Mapping-only mode intentionally does not access guest pages.
			} else if c.Bool(sharedMemoryTwoUVMArgName) {
				prefixLength = 160
			}
			prefix, err := section.hexPrefix(prefixLength)
			if err != nil {
				return err
			}
			logrus.WithField("hex", prefix).Info(
				"final shared-memory prefix",
			)
			if c.Bool(sharedMemoryTwoUVMArgName) &&
				!c.Bool(sharedMemoryMappingOnlyArgName) {
				section.printCrashLogs()
			}
			if c.Bool(sharedMemoryMappingOnlyArgName) {
				// Mapping-only mode intentionally does not access guest pages.
			} else if c.Bool(sharedMemoryTwoUVMArgName) {
				markers := []struct {
					offset uint64
					value  string
				}{
					{offset: 64, value: "GUEST-A-READY"},
					{offset: 96, value: "GUEST-B-SEEN-A"},
					{offset: 128, value: "GUEST-A-SEEN-B"},
				}
				for _, marker := range markers {
					if err := section.expect(
						marker.offset,
						[]byte(marker.value),
					); err != nil {
						return err
					}
					logrus.WithFields(logrus.Fields{
						"marker": marker.value,
						"offset": marker.offset,
					}).Info("observed guest shared-memory marker")
				}
				markerVerified = true
			} else if c.Duration(sharedMemoryObserveArgName) > 0 ||
				c.IsSet(sharedMemoryGuestModuleArgName) {
				const markerOffset = 64
				marker := []byte("GUEST-WROTE-OK")
				if err := section.expect(markerOffset, marker); err != nil {
					return err
				}
				logrus.WithFields(logrus.Fields{
					"marker": string(marker),
					"offset": markerOffset,
				}).Info("observed guest shared-memory marker")
				markerVerified = true
			}
		}
		return lcowLifecycleResult(firstErr, section != nil, markerVerified,
			c.String(networkBenchmarkScriptArgName) != "" ||
				c.String(siblingBusGuestModuleArgName) != "")
	},
}

func lcowLifecycleResult(err error, sharedMemory, markerVerified, requireGuestSuccess bool) error {
	if err == nil || (!sharedMemory && !requireGuestSuccess) {
		return nil
	}
	if markerVerified && !requireGuestSuccess {
		logrus.WithError(err).Warn(
			"ignoring UVM lifecycle error after verified shared-memory marker",
		)
		return nil
	}
	return err
}

func loadExecCommand(c *cli.Context) (string, error) {
	if c.IsSet(execCommandLineArgName) && c.IsSet(execFileArgName) {
		return "", fmt.Errorf(
			"--%s and --%s are mutually exclusive",
			execCommandLineArgName,
			execFileArgName,
		)
	}
	if !c.IsSet(execFileArgName) {
		return c.String(execCommandLineArgName), nil
	}

	path := c.String(execFileArgName)
	command, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read UVM command file %q: %w", path, err)
	}
	return strings.ReplaceAll(string(command), "\r\n", "\n"), nil
}

func init() {
	lcowCommand.CustomHelpTemplate = cli.CommandHelpTemplate + "EXAMPLES:\n" +
		`.\uvmboot.exe -gcs lcow -boot-files-path "C:\ContainerPlat\LinuxBootFiles" -root-fs-type vhd -t -exec "/bin/bash"` +
		"\n" +
		`.\uvmboot.exe -count 2 -parallel 2 -gcs lcow -boot-files-path "C:\ContainerPlat\LinuxBootFiles" ` +
		`-root-fs-type vhd -shared-memory-size 1048576 -exec "sleep 300"`
}

func createLCOWOptions(ctx context.Context, c *cli.Context, id string) (*uvm.OptionsLCOW, error) {
	opt, err := oci.SpecToUVMCreateOpts(ctx,
		&specs.Spec{
			Linux:       &specs.Linux{},
			Annotations: parseAnnotations(ctx, c, annotationsArgName),
		},
		id, "",
	)
	if err != nil {
		return nil, err
	}
	options, ok := opt.(*uvm.OptionsLCOW)
	if !ok {
		return nil, fmt.Errorf("unexpect uVM create options type: %T", opt)
	}

	setGlobalOptions(c, options.Options)
	options.ConsolePipe = fmt.Sprintf(`\\.\pipe\uvmpipe-%s`, id)
	if !useGCS && c.Duration(sharedMemoryObserveArgName) > 0 {
		options.ConsolePipe = ""
	}

	// boot
	if c.IsSet(bootFilesPathArgName) {
		options.UpdateBootFilesPath(ctx, c.String(bootFilesPathArgName))
	}

	// kernel
	if c.IsSet(kernelDirectArgName) {
		options.KernelDirect = c.Bool(kernelDirectArgName)
	}
	if c.IsSet(kernelFileArgName) {
		switch strings.ToLower(c.String(kernelFileArgName)) {
		case vmutils.KernelFile:
			options.KernelFile = vmutils.KernelFile
		case vmutils.UncompressedKernelFile:
			options.KernelFile = vmutils.UncompressedKernelFile
		default:
			return nil, unrecognizedError(c.String(kernelFileArgName), kernelFileArgName)
		}
	}
	if c.IsSet(kernelArgsArgName) {
		options.KernelBootOptions = c.String(kernelArgsArgName)
	}
	if c.Bool(sharedMemoryTwoUVMArgName) {
		role, err := sharedMemoryProofRole(id)
		if err != nil {
			return nil, err
		}
		options.KernelBootOptions = strings.TrimSpace(
			options.KernelBootOptions + " hcs_shmem_diag.role=" + role,
		)
	}

	// rootfs
	if c.IsSet(rootFSTypeArgName) {
		switch strings.ToLower(c.String(rootFSTypeArgName)) {
		case "initrd":
			options.RootFSFile = vmutils.InitrdFile
			options.PreferredRootFSType = uvm.PreferredRootFSTypeInitRd
		case "vhd":
			options.RootFSFile = vmutils.VhdFile
			options.PreferredRootFSType = uvm.PreferredRootFSTypeVHD
		case "none":
			options.RootFSFile = ""
			options.PreferredRootFSType = uvm.PreferredRootFSTypeNA
		default:
			return nil, unrecognizedError(c.String(rootFSTypeArgName), rootFSTypeArgName)
		}
	}

	if c.IsSet(vpMemMaxCountArgName) {
		options.VPMemDeviceCount = uint32(c.Uint(vpMemMaxCountArgName))
	}
	if c.IsSet(vpMemMaxSizeArgName) {
		options.VPMemSizeBytes = c.Uint64(vpMemMaxSizeArgName) * memory.MiB // convert from MB to bytes
	}
	if size := c.Uint64(sharedMemorySizeArgName); size > math.MaxInt32 {
		return nil, fmt.Errorf(
			"shared-memory size %d exceeds HCS schema limit %d",
			size,
			math.MaxInt32,
		)
	}

	// GCS
	options.UseGuestConnection = useGCS
	if !useGCS {
		if c.IsSet(execCommandLineArgName) {
			options.ExecCommandLine = c.String(execCommandLineArgName)
		}
		if c.IsSet(forwardStdoutArgName) {
			options.ForwardStdout = c.Bool(forwardStdoutArgName)
		}
		if c.IsSet(forwardStderrArgName) {
			options.ForwardStderr = c.Bool(forwardStderrArgName)
		}
		if c.IsSet(outputHandlingArgName) {
			switch strings.ToLower(c.String(outputHandlingArgName)) {
			case "stdout":
				options.OutputHandlerCreator = func(string) vmutils.OutputHandler {
					return func(r io.Reader) {
						_, _ = io.Copy(os.Stdout, r)
					}
				}
			default:
				return nil, unrecognizedError(c.String(outputHandlingArgName), outputHandlingArgName)
			}
		}
	}
	if c.IsSet(consolePipeArgName) {
		options.ConsolePipe = c.String(consolePipeArgName)
	}

	// general settings
	if lcowDisableTimeSync {
		options.DisableTimeSyncService = true
	}

	// empty policy string defaults to open door
	if c.IsSet(securityPolicyArgName) {
		options.SecurityPolicy = c.String(securityPolicyArgName)
	}
	if c.IsSet(securityPolicyEnforcerArgName) {
		options.SecurityPolicyEnforcer = c.String(securityPolicyEnforcerArgName)
	}
	if c.IsSet(securityHardwareFlag) {
		options.GuestStateFilePath = vmutils.DefaultGuestStateFile
		hclEnabled := false
		options.HclEnabled = &hclEnabled
		options.SecurityPolicyEnabled = true
		bundleDirectory, err := os.MkdirTemp(
			"",
			fmt.Sprintf("uvmboot-snp-%s-", id),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"create temporary SNP bundle directory: %w",
				err,
			)
		}
		options.BundleDirectory = bundleDirectory
		options.AllowOvercommit = false

		if !c.IsSet(noVerityBoot) {
			options.DmVerityRootFsVhd = vmutils.DefaultDmVerityRootfsVhd
			options.DmVerityMode = true
		}
	}

	return options, nil
}

// parseAnnotations parses the annotations from the [cli.StringSliceFlag] specified by `name`.
func parseAnnotations(ctx context.Context, c *cli.Context, name string) map[string]string {
	ss := c.StringSlice(name)
	annots := map[string]string{}

	for _, s := range ss {
		entry := log.G(ctx).WithField("flag-value", s)
		k, v, found := strings.Cut(s, "=")

		if !found {
			entry.WithField(logrus.ErrorKey, "missing `=` in annotation").Warnf("invald %s flag value", name)
		} else if k == "" || v == "" {
			entry.WithField(logrus.ErrorKey, "empty annotation key or value").Warnf("invald %s flag value", name)
		} else {
			entry = entry.WithFields(logrus.Fields{
				logfields.Key:   k,
				logfields.Value: v,
			})
			entry.Debugf("parsed %s flag", name)

			if vv, ok := annots[k]; ok {
				entry.WithField(logfields.Value+"-existing", vv).Warn("overriding existing annotation")
			}

			annots[k] = v
		}
	}

	return annots
}

func runLCOW(
	ctx context.Context,
	options *uvm.OptionsLCOW,
	c *cli.Context,
	execCommand string,
	mappingObserver func(
		string,
		[]hcsschema.SharedMemoryRegionInfo,
	) error,
) (resultErr error) {
	vm, err := uvm.CreateLCOW(ctx, options)
	if err != nil {
		return err
	}
	defer func() {
		if c.String(networkBenchmarkScriptArgName) == "" {
			_ = vm.CloseCtx(ctx)
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := vm.CloseCtx(cleanupCtx); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close UVM %s: %w", vm.ID(), err))
		}
	}()

	var (
		preStartRegions []hcsschema.SharedMemoryRegionInfo
		preStartErr     error
		mappedRegions   []hcsschema.SharedMemoryRegionInfo
	)
	if len(options.SharedMemoryRegions) > 0 {
		preStartRegions, preStartErr = vm.SharedMemoryRegions(ctx)
		if preStartErr != nil {
			logrus.WithError(preStartErr).Debug(
				"shared-memory mapping not queryable before UVM start",
			)
		} else {
			logSharedMemoryRegions(vm.ID(), "before start", preStartRegions)
		}
	}

	if err := vm.Start(ctx); err != nil {
		return err
	}
	var stopSampling func() error
	if c.String(networkBenchmarkScriptArgName) != "" {
		if vm.ProcessorCount() != 2 {
			return fmt.Errorf("network benchmark requested two VPs, HCS assigned %d", vm.ProcessorCount())
		}
		stopSampling = sampleNetworkBenchmarkCPU(ctx, vm)
		defer func() {
			resultErr = errors.Join(resultErr, stopSampling())
		}()
		if err := shareNetworkBenchmark(ctx, c, vm); err != nil {
			return err
		}
	}

	if len(options.SharedMemoryRegions) > 0 {
		regions, err := vm.SharedMemoryRegions(ctx)
		phase := "after start"
		if err != nil {
			if c.Bool(sharedMemoryGuestInventoryArgName) {
				logrus.WithError(err).Warn(
					"continuing guest inventory without an HCS " +
						"shared-memory GPA",
				)
				regions = nil
			} else if len(preStartRegions) == 0 {
				return fmt.Errorf(
					"shared-memory mapping query failed before and after "+
						"UVM start: before: %v; after: %w",
					preStartErr,
					err,
				)
			}
			if len(preStartRegions) > 0 {
				logrus.WithError(err).Warn(
					"using pre-start shared-memory mapping because the " +
						"post-start query failed",
				)
				regions = preStartRegions
				phase = "before start (retained)"
			}
		}
		if len(regions) == 0 &&
			!c.Bool(sharedMemoryGuestInventoryArgName) {
			return fmt.Errorf("HCS returned no shared-memory region information")
		}

		if len(regions) > 0 {
			logSharedMemoryRegions(vm.ID(), phase, regions)
			mappedRegions = regions
		}
		if mappingObserver != nil && len(regions) > 0 {
			if err := mappingObserver(vm.ID(), regions); err != nil {
				return err
			}
		}
	}

	if err := mountSCSI(ctx, c, vm); err != nil {
		return err
	}

	if err := shareFiles(ctx, c, vm); err != nil {
		return err
	}

	if modulePath := c.String(sharedMemoryGuestModuleArgName); modulePath != "" {
		const guestModuleRoot = "/run/hcs-shmem-diag-module"

		if err := vm.Share(ctx, modulePath, guestModuleRoot, true); err != nil {
			return fmt.Errorf("share HCS shared-memory diagnostic module: %w", err)
		}
		if len(options.SharedMemoryRegions) != 1 || len(mappedRegions) != 1 {
			return fmt.Errorf(
				"guest module requires exactly one configured and one mapped " +
					"shared-memory region",
			)
		}
		guestModulePath := guestModuleRoot + "/" + filepath.Base(modulePath)
		role := "single"
		if c.Bool(sharedMemoryTwoUVMArgName) {
			role, err = sharedMemoryProofRole(vm.ID())
			if err != nil {
				return err
			}
		}
		eventArgs := ""
		if len(options.SiblingCommunicationEndpoints) == 1 {
			route, err := waitForSiblingCommunicationRoute(
				ctx,
				vm,
				options.SiblingCommunicationEndpoints[0],
			)
			if err != nil {
				return err
			}
			eventArgs = siblingEventModuleArgs(route)
		}
		execCommand, err = sharedMemoryGuestModuleCommand(
			guestModulePath,
			options.SharedMemoryRegions[0],
			mappedRegions[0],
			role,
			eventArgs,
		)
		if err != nil {
			return err
		}
		if busModulePath := c.String(siblingBusGuestModuleArgName); busModulePath != "" {
			const busModuleRoot = "/run/sibling-bus-module"

			if err := vm.Share(ctx, busModulePath, busModuleRoot, true); err != nil {
				return fmt.Errorf("share sibling-bus module: %w", err)
			}
			if bundle := c.String(siblingOpenShellBundleArgName); bundle != "" {
				if err := vm.Share(ctx, bundle, "/run/openshell-bundle", true); err != nil {
					return fmt.Errorf("share OpenShell bundle: %w", err)
				}
				var uplink *diodeUplink
				var dns []string
				if role == diodeRole {
					var cleanup func()
					uplink, cleanup, err = attachDiodeUplink(ctx, vm)
					if err != nil {
						return err
					}
					defer cleanup()
					dns, err = hostDNSServers()
					if err != nil {
						return fmt.Errorf("OpenShell diode DNS: %w", err)
					}
				}
				openShellCommand, commandErr := siblingOpenShellGuestCommand(
					busModuleRoot+"/"+filepath.Base(busModulePath),
					"/run/openshell-bundle/"+filepath.Base(bundle), role, uplink, dns)
				if commandErr != nil {
					return commandErr
				}
				execCommand += "; " + openShellCommand
			} else {
				// Plan9 file shares expose only the named file, so the role's
				// net module (next to sibling_bus.ko on the host) is shared too.
				const netModuleRoot = "/run/diode-net-module"
				netModuleName := siblingNetModuleName(role)
				netModuleGuestPath := ""
				if netModuleName != "" {
					netModulePath := filepath.Join(filepath.Dir(busModulePath), netModuleName)
					if err := vm.Share(ctx, netModulePath, netModuleRoot, true); err != nil {
						return fmt.Errorf("share diode net module: %w", err)
					}
					netModuleGuestPath = netModuleRoot + "/" + netModuleName
				}
				vsockTestPath := filepath.Join(filepath.Dir(busModulePath), "diode_vsock_test")
				if err := vm.Share(ctx, vsockTestPath, "/run/diode-vsock-test", true); err != nil {
					return fmt.Errorf("share diode_vsock_test: %w", err)
				}
				tcpBulkPath := filepath.Join(filepath.Dir(busModulePath), "diode_tcpbulk")
				if err := vm.Share(ctx, tcpBulkPath, "/run/diode-tcpbulk", true); err != nil {
					return fmt.Errorf("share diode_tcpbulk: %w", err)
				}
				// Interactive demo helpers, staged on both roles (the diode runs
				// capture/filter/smooth, the workload runs the covert client).
				for shareName, guestDir := range map[string]string{
					"demo.sh":       "/run/diode-demo",
					"covert_udp":    "/run/diode-covert",
					"diode_tcpdump": "/run/diode-tcpdump",
					"diode_tc":      "/run/diode-tc",
				} {
					hostPath := filepath.Join(filepath.Dir(busModulePath), shareName)
					if _, statErr := os.Stat(hostPath); statErr != nil {
						continue
					}
					if err := vm.Share(ctx, hostPath, guestDir, true); err != nil {
						return fmt.Errorf("share %s: %w", shareName, err)
					}
				}
				iperfPath := filepath.Join(filepath.Dir(busModulePath), iperfGuestName)
				if err := vm.Share(ctx, iperfPath, iperfGuestShare, true); err != nil {
					return fmt.Errorf("share %s: %w", iperfGuestName, err)
				}
				egress := c.Bool(siblingDiodeUplinkArgName)
				netCfg, err := siblingNetConfigFor(role, egress)
				if err != nil {
					return err
				}
				fmt.Printf("sibling net: role=%s if=%s addr=%s gw=%s dns=%s\n", role,
					netCfg.ifName, netCfg.address, netCfg.gateway, strings.Join(netCfg.dns, ","))
				var uplink *diodeUplink
				if egress && role == diodeRole {
					iptablesPath := filepath.Join(filepath.Dir(busModulePath), "diode_iptables")
					if err := vm.Share(ctx, iptablesPath, "/run/diode-iptables", true); err != nil {
						return fmt.Errorf("share diode_iptables: %w", err)
					}
					var cleanup func()
					uplink, cleanup, err = attachDiodeUplink(ctx, vm)
					if err != nil {
						return err
					}
					defer cleanup()
				}
				if c.String(networkBenchmarkScriptArgName) != "" {
					execCommand += "; " + networkBenchmarkSiblingCommand(c,
						busModuleRoot+"/"+filepath.Base(busModulePath),
						netModuleGuestPath, role, netCfg, uplink)
				} else {
					execCommand += "; " + siblingBusGuestModuleCommand(
						busModuleRoot+"/"+filepath.Base(busModulePath),
						netModuleGuestPath,
						role,
						netCfg,
						uplink,
					)
				}
			}
		}
	}

	if c.IsSet(baselineNICArgName) || c.IsSet(baselinePairArgName) {
		cmd, cleanup, err := baselineCommand(ctx, c, vm)
		if err != nil {
			return err
		}
		defer cleanup()
		execCommand = cmd
	}

	if err := mountVPMem(ctx, c, vm); err != nil {
		return err
	}

	if c.Bool(sharedMemoryMappingOnlyArgName) {
		return observeLCOW(
			ctx,
			vm,
			c.Duration(sharedMemoryObserveArgName),
		)
	}

	if options.UseGuestConnection {
		if err := execViaGCS(ctx, vm, c, execCommand); err != nil {
			return err
		}
		if stopSampling != nil {
			if err := stopSampling(); err != nil {
				return err
			}
		}
		if siblingInteractive {
			role, err := sharedMemoryProofRole(vm.ID())
			if err != nil {
				return err
			}
			if err := serveSiblingShells(ctx, vm, role); err != nil {
				return err
			}
		}
		_ = vm.Terminate(ctx)
		_ = vm.WaitCtx(ctx)

		return vm.ExitError()
	}

	if duration := c.Duration(sharedMemoryObserveArgName); duration > 0 {
		return observeLCOW(ctx, vm, duration)
	}

	return vm.WaitCtx(ctx)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// Proof role a is the diode (sibling backend, NetVSP); role b is the
// workload (sibling consumer, NetVSC).
const (
	diodeRole    = "a"
	workloadRole = "b"
)

func sharedMemoryProofRole(uvmID string) (string, error) {
	switch uvmID {
	case "uvmboot-0":
		return diodeRole, nil
	case "uvmboot-1":
		return workloadRole, nil
	default:
		return "", fmt.Errorf(
			"cannot assign shared-memory proof role to UVM %q",
			uvmID,
		)
	}
}

func siblingCommunicationEndpoint(
	uvmID string,
	groupID string,
) (hcsschema.SiblingCommunicationEndpoint, error) {
	const (
		targetSINT        = 3
		backendEventFlag  = 11
		workloadEventFlag = 12
	)

	switch uvmID {
	case "uvmboot-0":
		return hcsschema.SiblingCommunicationEndpoint{
			GroupID:         groupID,
			Role:            hcsschema.SiblingCommunicationEndpointRoleBackend,
			TargetVP:        0,
			TargetSINT:      targetSINT,
			EventFlagNumber: backendEventFlag,
		}, nil
	case "uvmboot-1":
		return hcsschema.SiblingCommunicationEndpoint{
			GroupID:         groupID,
			Role:            hcsschema.SiblingCommunicationEndpointRoleWorkload,
			TargetVP:        0,
			TargetSINT:      targetSINT,
			EventFlagNumber: workloadEventFlag,
		}, nil
	default:
		return hcsschema.SiblingCommunicationEndpoint{}, fmt.Errorf(
			"cannot assign sibling communication endpoint to UVM %q",
			uvmID,
		)
	}
}

// waitForSiblingCommunicationRoute polls until HCS reports the outbound
// connection ID for endpoint, which happens once the peer UVM has registered.
func waitForSiblingCommunicationRoute(
	ctx context.Context,
	vm *uvm.UtilityVM,
	endpoint hcsschema.SiblingCommunicationEndpoint,
) (hcsschema.SiblingCommunicationRouteInfo, error) {
	const (
		timeout  = 30 * time.Second
		interval = 100 * time.Millisecond
	)

	deadline := time.Now().Add(timeout)
	for {
		routes, err := vm.SiblingCommunicationRoutes(ctx)
		if err != nil {
			return hcsschema.SiblingCommunicationRouteInfo{}, err
		}
		for _, route := range routes {
			if strings.EqualFold(route.GroupID, endpoint.GroupID) &&
				route.OutboundConnectionID != 0 {
				logrus.WithFields(logrus.Fields{
					"uvm":                  vm.ID(),
					"groupId":              route.GroupID,
					"role":                 route.Role,
					"outboundConnectionId": fmt.Sprintf("%#x", route.OutboundConnectionID),
				}).Info("sibling communication route ready")
				return route, nil
			}
		}
		if time.Now().After(deadline) {
			return hcsschema.SiblingCommunicationRouteInfo{}, fmt.Errorf(
				"sibling communication group %s has no outbound connection after %v",
				endpoint.GroupID,
				timeout,
			)
		}
		select {
		case <-ctx.Done():
			return hcsschema.SiblingCommunicationRouteInfo{}, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func siblingEventModuleArgs(route hcsschema.SiblingCommunicationRouteInfo) string {
	return fmt.Sprintf(
		" signal_conn=%#x rx_vp=%d rx_sint=%d rx_flag=%d",
		route.OutboundConnectionID,
		route.TargetVP,
		route.TargetSINT,
		route.EventFlagNumber,
	)
}

func sharedMemoryGuestModuleCommand(
	modulePath string,
	configured hcsschema.SharedMemoryRegion,
	mapped hcsschema.SharedMemoryRegionInfo,
	role string,
	eventArgs string,
) (string, error) {
	if !strings.EqualFold(configured.SectionName, mapped.SectionName) {
		return "", fmt.Errorf(
			"HCS returned section %q, expected %q",
			mapped.SectionName,
			configured.SectionName,
		)
	}
	if configured.Length <= 0 {
		return "", fmt.Errorf(
			"shared-memory section %q has invalid length %d",
			configured.SectionName,
			configured.Length,
		)
	}

	byteGPA := uint64(uint32(mapped.GuestPhysicalAddress)) << 12
	return fmt.Sprintf(
		"set -eu; insmod %s gpa=%#x length=%#x decrypted=1 "+
			"read_only=0 role=%s%s; "+
			"dmesg | grep -F 'hcs-shmem-diag:'",
		shellSingleQuote(modulePath),
		byteGPA,
		uint64(configured.Length),
		shellSingleQuote(role),
		eventArgs,
	), nil
}

// siblingBusGuestModuleCommand loads sibling_bus.ko and the role's network
// module from the same directory, waits for the echo channel, then runs a
// ping from the workload to the diode over the sibling NetVSC.
// The backend stays up until the workload closes the network channel.
func siblingNetModuleName(role string) string {
	if role == workloadRole {
		return ""
	}
	return "diode_netvsp.ko"
}

// siblingTCPBulkStage copies diode_tcpbulk from its Plan9 share into an exec
// tmpfs (the guest /tmp is noexec). Plan9 runs over VMBus, so this must happen
// before the relay-check window. $dtb is the binary to run; iperfStage adds
// $ipf and ipbench.
const siblingTCPBulkStage = `dtb=/run/diode-tcpbulk/diode_tcpbulk; mkdir -p /run/dtb-exec && ` +
	`mount -t tmpfs -o exec,size=16m tmpfs /run/dtb-exec 2>/dev/null && ` +
	`cp $dtb /run/dtb-exec/dtb && chmod 755 /run/dtb-exec/dtb && dtb=/run/dtb-exec/dtb; ` +
	`for m in demo.sh:demo.sh:/run/diode-demo covert:covert_udp:/run/diode-covert ` +
	`tcpdump:diode_tcpdump:/run/diode-tcpdump tc:diode_tc:/run/diode-tc; do ` +
	`d=${m%%:*}; r=${m#*:}; s=${r#*:}/${r%%:*}; ` +
	`if [ -f "$s" ]; then cp "$s" /run/dtb-exec/$d && chmod 755 /run/dtb-exec/$d; fi; done; ` +
	iperfStage

const siblingVsockStage = `cp /run/diode-vsock-test/diode_vsock_test /run/dtb-exec/vsock-test && ` +
	`chmod 755 /run/dtb-exec/vsock-test || { echo 'diode_vsock: tool staging failed' >&2; exit 1; }; `

// siblingWorkloadStage stages $dtb and $ipf and defines snap, which reads
// the root VMBus channel interrupts, the sibling bus counters, uptime and
// dvsc0's byte counters.
const siblingWorkloadStage = `set +eu; ` + siblingTCPBulkStage + siblingVsockStage + `snap() { set -- $(grep HYP: /proc/interrupts); shift; h=0; ` +
	`for v; do case $v in *[!0-9]*) break;; esac; h=$((h+v)); done; c=0; ` +
	`for p in /sys/bus/vmbus/devices/*; do case ${p##*/} in bus*-relid*) continue;; esac; ` +
	`for f in "$p"/channels/*/interrupts; do [ -r "$f" ] && c=$((c+$(cat "$f"))); done; done; ` +
	`set -- $(cat /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_stats); d=${1#*=}; g=${2#*=}; m=${3#*=}; ` +
	`read u _ < /proc/uptime; t=${u%.*}${u#*.}; ` +
	`b=$(cat /sys/class/net/dvsc0/statistics/tx_bytes); r=$(cat /sys/class/net/dvsc0/statistics/rx_bytes); }; `

// siblingNetRelayCheck runs bulk traffic from the workload over dvsc0 and
// compares, over that window, the root VMBus channel interrupts with the
// sibling doorbells. Nothing is printed inside the window because guest
// output itself travels over VMBus (hvsock). It needs siblingWorkloadStage.
const siblingNetRelayCheck = `snap; h0=$h c0=$c d0=$d g0=$g t0=$t b0=$b r0=$r; ` +
	`ping -q -A -c 2000 -s 1400 10.200.0.1 >/tmp/dn-ping 2>&1 || ` +
	`ping -q -c 300 -i 0.01 -s 1400 10.200.0.1 >>/tmp/dn-ping 2>&1; ` +
	`snap; t1=$t b1=$b d1=$d m1=$m; ` +
	`"$dtb" send 10.200.0.1 5001 256 >/tmp/dn-tcp 2>&1; snap; ` +
	`echo "diode_net: ping-flood $(grep -E 'transmitted|round-trip' /tmp/dn-ping | tr '\n' ' ') cs=$((t1-t0))"; ` +
	`echo "diode_net: tcp-bulk $(tr '\n' ' ' </tmp/dn-tcp) cs=$((t-t1)) bytes=$((b-b1)) doorbells_rx=$((d-d1)) signals_masked=$((m-m1))"; ` +
	`echo "diode_net: relay check cs=$((t-t0)) vmbus_chan_irqs=$((c-c0)) hyp_irqs=$((h-h0)) ` +
	`doorbells_rx=$((d-d0)) signals_tx=$((g-g0)) tx_bytes=$((b-b0)) rx_bytes=$((r-r0))"; ` +
	`if [ $((d-d0)) -gt 100 ] && [ $(((c-c0)*100)) -lt $((d-d0)) ]; then echo 'diode_net: no-relay ok'; ` +
	`else echo 'diode_net: no-relay inconclusive'; fi; `

// siblingDiodeUplinkCommand configures the diode's uplink NIC (the only
// interface besides dvsp0 backed by a device). It needs the exec tmpfs from
// siblingTCPBulkStage.
func siblingDiodeUplinkCommand(uplink *diodeUplink, waitFor func(cond, what string) string) string {
	return "ipt=/run/dtb-exec/ipt; cp /run/diode-iptables/diode_iptables $ipt && chmod 755 $ipt; " +
		waitFor("up=; for n in /sys/class/net/*; do n=${n##*/}; [ $n != dvsp0 ] && "+
			"[ -e /sys/class/net/$n/device ] && up=$n; done; [ -n \"$up\" ]", "uplink nic") +
		"ip addr add " + uplink.address + " dev $up; ip link set $up up; " +
		"ip route add default via " + uplink.gateway + " dev $up; "
}

// siblingDiodeNATCommand forwards and masquerades the workload subnet out of
// the uplink NIC ($up). Installing the nat table enables conntrack for all
// traffic.
func siblingDiodeNATCommand(uplink *diodeUplink) string {
	cmd := "echo 1 >/proc/sys/net/ipv4/ip_forward; " +
		"if $ipt iptables -w -t nat -A POSTROUTING -s 10.200.0.0/30 -o $up -j MASQUERADE; " +
		"then echo \"diode_net: nat ok dev=$up addr=" + uplink.address + " gw=" + uplink.gateway + "\"; " +
		"else echo 'diode_net: nat failed'; fi; "
	if !siblingInteractive {
		cmd += "if ping -c 2 -W 2 " + uplink.gateway + " >/dev/null 2>&1; " +
			"then echo 'diode_net: uplink gateway ok'; else echo 'diode_net: uplink gateway no reply'; fi; "
	}
	return cmd
}

// siblingNetConfig is the host-chosen configuration of a sibling network
// interface. For the workload, gateway and dns make the diode its default
// route and the host's DNS servers its resolvers.
type siblingNetConfig struct {
	ifName  string
	address string // CIDR
	gateway string
	dns     []string
}

func siblingNetConfigFor(role string, egress bool) (siblingNetConfig, error) {
	if role == diodeRole {
		return siblingNetConfig{ifName: "dvsp0", address: "10.200.0.1/30"}, nil
	}
	cfg := siblingNetConfig{ifName: "dvsc0", address: "10.200.0.2/30"}
	if egress {
		dns, err := hostDNSServers()
		if err != nil {
			return cfg, err
		}
		cfg.gateway, cfg.dns = "10.200.0.1", dns
	}
	return cfg, nil
}

// command configures the interface once it exists. It prints nothing, so it
// can precede the relay check.
func (cfg siblingNetConfig) command() string {
	cmd := "ip addr add " + cfg.address + " dev " + cfg.ifName +
		" && ip link set " + cfg.ifName + " up; "
	if cfg.gateway != "" {
		cmd += "ip route replace default via " + cfg.gateway + " dev " + cfg.ifName + "; "
	}
	if len(cfg.dns) > 0 {
		cmd += cfg.commandDNS() + " || echo 'diode_net: resolv.conf not writable' >&2; "
	}
	return cmd
}

func (cfg siblingNetConfig) commandDNS() string {
	// The rootfs is read-only and may lack /etc/resolv.conf, so bind over
	// an existing file or overlay /etc with a tmpfs upper layer.
	return "printf 'nameserver %s\\n' " + strings.Join(cfg.dns, " ") + " >/run/resolv.conf; " +
		"if cp /run/resolv.conf /etc/resolv.conf 2>/dev/null; then :; " +
		"elif [ -e /etc/resolv.conf ]; then mount --bind /run/resolv.conf /etc/resolv.conf; " +
		"else o=/run/etc-overlay; mkdir -p $o && mount -t tmpfs tmpfs $o && " +
		"mkdir $o/up $o/work && mount -t overlay overlay " +
		"-o lowerdir=/etc,upperdir=$o/up,workdir=$o/work /etc && " +
		"cp /run/resolv.conf /etc/resolv.conf; fi"
}

// siblingWorkloadEgressCommand checks that the workload's only NIC is dvsc0
// and reports what ICMP, UDP (DNS) and TCP (HTTP HEAD) reach through the
// diode. It needs siblingWorkloadStage, which stages $dtb. The host may
// drop ICMP, so the diode's MASQUERADE counters are the definitive check.
func siblingWorkloadEgressCommand(dnsServers []string) string {
	return `root_nics=0; for n in /sys/class/net/*; do if [ -e "$n/device" ]; then ` +
		`d=$(readlink -f "$n/device"); case ${d##*/} in bus*-relid*) :;; *) root_nics=$((root_nics+1));; esac; fi; done; ` +
		"echo \"diode_net: workload interfaces $(ls /sys/class/net | tr '\\n' ' ')" +
		"nics=$root_nics\"; " +
		"echo \"diode_net: workload route $(ip route | grep default)\"; " +
		"echo \"diode_net: workload resolv $(grep nameserver /etc/resolv.conf | tr '\\n' ' ')\"; " +
		"for dst in " + diodeUplinkGateway + " 1.1.1.1; do " +
		"if ping -c 3 -W 2 $dst >/dev/null 2>&1; then echo \"diode_net: egress ping $dst ok\"; " +
		"else echo \"diode_net: egress ping $dst no reply\"; fi; done; " +
		"for ns in " + strings.Join(dnsServers, " ") + " 1.1.1.1; do r=$(\"$dtb\" dns $ns example.com); echo \"diode_net: egress $r\"; " +
		"case $r in *' ok addr='*) ip=${r#*addr=}; ip=${ip%% *};; esac; done; " +
		"for dst in 1.1.1.1:80 ${ip:+$ip:80}; do " +
		"echo \"diode_net: egress $(\"$dtb\" connect ${dst%:*} ${dst#*:})\"; done; "
}

func siblingFailureDiagnosticsCommand() string {
	return `echo 'sibling_vmbus: failure diagnostics' >&2; ` +
		`for p in /sys/class/net/*; do [ -e "$p" ] || continue; ` +
		`echo "sibling_vmbus: interface=${p##*/} device=$(readlink -f "$p/device" 2>/dev/null) driver=$(readlink "$p/device/driver" 2>/dev/null)" >&2; done; ` +
		`for p in /sys/bus/vmbus/devices/bus*-relid*; do [ -e "$p" ] || continue; ` +
		`echo "sibling_vmbus: device=${p##*/} driver=$(readlink "$p/driver" 2>/dev/null)" >&2; ` +
		`for a in state in_read_index in_write_index out_read_index out_write_index; do ` +
		`[ ! -r "$p/$a" ] || { echo "sibling_vmbus: $a=$(cat "$p/$a")" >&2; }; done; done; ` +
		`for p in /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_stats; do ` +
		`[ ! -r "$p" ] || { echo "$p" >&2; cat "$p" >&2; }; done; ` +
		`dmesg >&2 || true; `
}

// guestWaitFor polls cond once a second for up to 30s, then fails the guest
// command.
func guestWaitFor(cond, what string) string {
	return "i=0; until " + cond + "; do i=$((i+1)); [ $i -le 30 ] || " +
		"{ echo " + shellSingleQuote("diode_net: "+what+" timed out") + " >&2; " +
		siblingFailureDiagnosticsCommand() + "exit 1; }; " +
		"sleep 1; done; "
}

func siblingInstanceCommand() string {
	return `set -- /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance; ` +
		`[ "$#" -eq 1 ] || { echo 'sibling_vmbus: expected one configured link' >&2; exit 1; }; ` +
		`sb_instance=$1; ` +
		guestWaitFor(`[ -r "$sb_instance" ] && grep -q 'ready=1' "$sb_instance"`, "common peer instance") +
		`set -- $(cat "$sb_instance"); sb_bus=${1#*=}; sb_local=${2#*=}; sb_peer=${3#*=}; ` +
		`[ "${4#*=}" = 2 ] || { echo 'sibling_vmbus: protocol version mismatch' >&2; exit 1; }; `
}

func siblingStockNICCommand(name string) string {
	return guestWaitFor(`sb_net=; sb_count=0; for p in /sys/class/net/*; do `+
		`d=$(readlink -f "$p/device" 2>/dev/null); case ${d##*/} in bus${sb_bus}-relid*) `+
		`sb_net=${p##*/}; sb_count=$((sb_count+1));; esac; done; [ "$sb_count" -eq 1 ]`, "stock peer NIC") +
		`[ "$(basename "$(readlink /sys/class/net/$sb_net/device/driver)")" = hv_netvsc ] || ` +
		`{ echo 'diode_net: peer NIC is not stock hv_netvsc' >&2; exit 1; }; ` +
		`if [ "$sb_net" != ` + shellSingleQuote(name) + ` ]; then ip link set "$sb_net" name ` + shellSingleQuote(name) +
		` || { echo 'diode_net: peer NIC rename failed' >&2; exit 1; }; fi; ` +
		`echo "diode_net: stock hv_netvsc registered if=` + name + ` bus=$sb_bus mac=$(cat /sys/class/net/` + name + `/address)"; `
}

func siblingVsockReadyCommand(role string) string {
	cid, transportRole := 4, "diode"
	if role == workloadRole {
		cid, transportRole = 3, "workload"
	}
	ready := fmt.Sprintf("sibling_vmbus: stock hv_sock ready role=%s local_cid=%d", transportRole, cid)
	return guestWaitFor(`[ -d /sys/bus/vmbus/drivers/hv_sock ]`, "stock hv_sock") +
		fmt.Sprintf(`[ "$sb_local" = %d ] || { echo 'sibling_vmbus: local CID mismatch' >&2; exit 1; }; `, cid) +
		`echo "` + ready + ` peer_cid=$sb_peer bus=$sb_bus"; `
}

func siblingVsockProofCommand(role string) string {
	listenPort, peerPort := 6103, 6104
	name := siblingRoleName(role)
	if role == diodeRole {
		listenPort, peerPort = peerPort, listenPort
	}
	return fmt.Sprintf(`/run/dtb-exec/vsock-test listen %d "$sb_local" >/tmp/sibling-vsock-listen.log 2>&1 & sb_vsock_pid=$!; `, listenPort) +
		guestWaitFor(`grep -qF 'listening on vsock port' /tmp/sibling-vsock-listen.log`, "stock socket listener") +
		fmt.Sprintf(`i=0; until /run/dtb-exec/vsock-test connect "$sb_peer" %d stock-vmbus-%s >/tmp/sibling-vsock-connect.log 2>&1; `, peerPort, name) +
		`do i=$((i+1)); [ $i -le 30 ] || { cat /tmp/sibling-vsock-*.log >&2; ` +
		siblingFailureDiagnosticsCommand() + `exit 1; }; sleep 1; done; ` +
		`wait "$sb_vsock_pid" || { cat /tmp/sibling-vsock-listen.log >&2; ` +
		siblingFailureDiagnosticsCommand() + `exit 1; }; ` +
		`echo 'sibling_vmbus: stock hv_sock payload role=` + name + ` ok'; `
}

func siblingBusGuestModuleCommand(modulePath, netModulePath, role string,
	net siblingNetConfig, uplink *diodeUplink) string {
	ifName := net.ifName
	waitFor := guestWaitFor
	cmd := "insmod " + shellSingleQuote(modulePath) + " || exit 1; "
	if netModulePath != "" {
		cmd += "insmod " + shellSingleQuote(netModulePath) + " || exit 1; "
	}
	cmd += waitFor("dmesg | grep -qE 'sibling_bus: chan: relid=1 echo'",
		"echo") +
		"dmesg | grep -F 'sibling_bus:'; " +
		"echo \"diode_net: tools $(command -v ip ifconfig ping | tr '\\n' ' ')\"; " +
		siblingInstanceCommand() + siblingVsockReadyCommand(role)
	if role == workloadRole {
		cmd += siblingStockNICCommand(ifName)
	}
	cmd += waitFor("[ -e /sys/class/net/"+ifName+" ]", ifName) + net.command()
	if role == workloadRole {
		cmd += waitFor("[ \"$(cat /sys/class/net/"+ifName+"/carrier)\" = 1 ]", "stock packet filter")
		if !siblingInteractive {
			cmd += "if ping -c 8 -W 2 10.200.0.1; then echo 'diode_net: ping ok'; " +
				"else echo 'diode_net: ping failed'; fi; "
		}
		cmd += siblingWorkloadStage
		if siblingTests["checks"] {
			cmd += siblingVsockProofCommand(role) + siblingNetRelayCheck
		}
		if net.gateway != "" {
			// Benchmark the sibling link before NAT, like the VM-pair
			// reference, then signal the diode on 5004. The diode then
			// installs NAT and listens on 5002, so the next run measures
			// throughput under conntrack. Without that run, a 1 MB send
			// to 5002 waits for NAT before the egress tests.
			if siblingTests["link"] {
				cmd += ipbench("link", "10.200.0.1", iperfLinkPort)
			}
			cmd += "\"$dtb\" send 10.200.0.1 5004 1 >/dev/null 2>&1; "
			if siblingTests["nat"] {
				cmd += "snap; t1=$t d1=$d m1=$m; \"$dtb\" send 10.200.0.1 5002 256 >/tmp/dn-tcp2 2>&1; snap; " +
					"echo \"diode_net: tcp-bulk-nat $(tr '\\n' ' ' </tmp/dn-tcp2) cs=$((t-t1)) doorbells_rx=$((d-d1)) signals_masked=$((m-m1))\"; "
			} else {
				cmd += "\"$dtb\" send 10.200.0.1 5002 1 >/dev/null 2>&1; "
			}
			if siblingTests["checks"] {
				cmd += siblingWorkloadEgressCommand(net.dns)
			}
			if siblingTests["host"] {
				cmd += hostEndpointTests()
			}
		}
	} else {
		cmd += siblingTCPBulkStage + siblingVsockStage
		if siblingTests["checks"] {
			cmd += siblingVsockProofCommand(role)
		}
		cmd += "(\"$dtb\" sink 5001 >/tmp/dn-tcp 2>&1 &); " +
			fmt.Sprintf("(\"$ipf\" -s -p %d >/dev/null 2>&1 &); ", iperfLinkPort)
		if uplink != nil {
			// Install NAT once the workload has benchmarked the link (sink
			// 5004), then accept a second bulk run, to compare sibling
			// throughput without and with conntrack.
			cmd += "set +eu; " + siblingDiodeUplinkCommand(uplink, waitFor) +
				"(\"$dtb\" sink 5004 >/tmp/dn-go 2>&1 &); " +
				fmt.Sprintf("i=0; until grep -q sink /tmp/dn-go 2>/dev/null; do i=$((i+1)); [ $i -le %d ] || break; sleep 1; done; ",
					2*benchSeconds+180) +
				"s1=$(cat /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_stats); " +
				siblingDiodeNATCommand(uplink) +
				"(\"$dtb\" sink 5002 >/tmp/dn-tcp2 2>&1 &); " +
				"i=0; until grep -q sink /tmp/dn-tcp2 2>/dev/null; do i=$((i+1)); [ $i -le 120 ] || break; sleep 1; done; " +
				"s2=$(cat /sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_stats); "
		}
		// The workload benchmarks the host endpoint before closing. Each
		// second, report memory, swiotlb use, forwarding counters and new
		// kernel messages, so a diode that dies mid-run leaves a trail.
		mon := ":"
		if uplink != nil {
			cmd += "mount -t debugfs none /sys/kernel/debug 2>/dev/null; k=$(dmesg | wc -l); " +
				"mon() { n=/sys/class/net; echo \"diode_net: mon $(grep MemAvailable /proc/meminfo | tr -s ' ')" +
				" swiotlb=$(cat /sys/kernel/debug/swiotlb/io_tlb_used 2>/dev/null)" +
				" $up=$(cat $n/$up/statistics/tx_packets)/$(cat $n/$up/statistics/tx_dropped)/$(cat $n/$up/statistics/tx_errors)" +
				" dvsp0=$(cat $n/dvsp0/statistics/rx_packets)/$(cat $n/dvsp0/statistics/rx_errors)/$(cat $n/dvsp0/statistics/rx_dropped)\"; " +
				"dmesg | tail -n +$((k+1)); k=$(dmesg | wc -l); }; "
			mon = "mon"
		}
		if !siblingInteractive {
			cmd += fmt.Sprintf("i=0; until dmesg | grep -qF 'dvsp0: channel closed'; do "+
				"i=$((i+1)); [ $i -le %d ] || break; %s; sleep 1; done; ", 2*benchSeconds+300, mon) +
				"echo \"diode_net: listener $(tr '\\n' ' ' </tmp/dn-tcp 2>/dev/null)\"; "
		}
		if uplink != nil && !siblingInteractive {
			cmd += "echo \"diode_net: diode stats after-bulk $s1\"; echo \"diode_net: diode stats after-bulk-nat $s2\"; " +
				"echo \"diode_net: listener-nat $(tr '\\n' ' ' </tmp/dn-tcp2 2>/dev/null)\"; " +
				"echo \"diode_net: conntrack count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)\"; " +
				"echo \"diode_net: nat counters $($ipt iptables -t nat -L POSTROUTING -v -n -x | " +
				"grep MASQUERADE | tr -s ' ')\"; "
		}
	}
	cmd += "echo \"diode_net: " + ifName + " tx=$(cat /sys/class/net/" + ifName +
		"/statistics/tx_packets) rx=$(cat /sys/class/net/" + ifName +
		"/statistics/rx_packets)\"; " +
		`dmesg | grep -E 'diode_net|hv_netvsc' || [ "$?" -eq 1 ]`
	return cmd
}
func logSharedMemoryRegions(
	uvmID string,
	phase string,
	regions []hcsschema.SharedMemoryRegionInfo,
) {
	for _, region := range regions {
		rawAddress := uint32(region.GuestPhysicalAddress)
		fmt.Printf(
			"UVM %s: shared-memory section %q mapped %s at raw address %#x; "+
				"if page-based, byte GPA is %#x\n",
			uvmID,
			region.SectionName,
			phase,
			rawAddress,
			uint64(rawAddress)<<12,
		)
	}
}

func observeLCOW(
	ctx context.Context,
	vm *uvm.UtilityVM,
	duration time.Duration,
) error {
	exit := make(chan error, 1)
	go func() {
		exit <- vm.WaitCtx(ctx)
	}()

	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case err := <-exit:
		return fmt.Errorf(
			"UVM exited before the %s observation completed: %w",
			duration,
			err,
		)
	case <-timer.C:
		if err := vm.Terminate(ctx); err != nil {
			return fmt.Errorf(
				"terminate UVM after %s observation: %w",
				duration,
				err,
			)
		}
		<-exit
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func execViaGCS(
	ctx context.Context,
	vm *uvm.UtilityVM,
	cCtx *cli.Context,
	execCommand string,
) error {
	c := cmd.CommandContext(ctx, vm, "sh", "-c", execCommand)
	c.Log = log.L.Dup()
	if lcowUseTerminal {
		c.Spec.Terminal = true
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		con, err := console.ConsoleFromFile(os.Stdin)
		if err != nil {
			log.G(ctx).WithError(err).Warn("could not create console from stdin")
		} else {
			csz, err := con.Size()
			if err != nil {
				return fmt.Errorf("failed to get console size: %w", err)
			}
			c.Spec.ConsoleSize = &specs.Box{
				Height: uint(csz.Height),
				Width:  uint(csz.Width),
			}
			if err := con.SetRaw(); err != nil {
				return err
			}
			defer func() {
				_ = con.Reset()
			}()
		}
	} else if cCtx.String(outputHandlingArgName) == "stdout" {
		if cCtx.Bool(forwardStdoutArgName) {
			c.Stdout = os.Stdout
		}
		if cCtx.Bool(forwardStderrArgName) {
			c.Stderr = os.Stdout // match non-GCS behavior and forward to stdout
		}
	}

	return c.Run()
}
