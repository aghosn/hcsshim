//go:build windows

package main

import (
	"context"
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
)

var (
	lcowUseTerminal     bool
	lcowDisableTimeSync bool
)

var lcowCommand = cli.Command{
	Name:  "lcow",
	Usage: "Boot an LCOW UVM",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  protectedModeFlag,
			Usage: "Private CPU-only SNP manual lifecycle: m1 only. Creates two fresh owned VMs.",
		},
		cli.DurationFlag{
			Name:  protectedTimeoutFlag,
			Value: 3 * time.Minute,
			Usage: "Time budget for M1 creation, setup and guest exchange, not a VM lifetime limit " +
				"(greater than 0, at most 10m). In-flight native VID calls are not forcibly interrupted.",
		},
		cli.DurationFlag{
			Name:  protectedCleanupFlag,
			Value: 2 * time.Minute,
			Usage: "Fresh, independent budget for safe M1 cleanup after success, failure or forward timeout " +
				"(greater than 0, at most 10m). Expiry does not force backing release.",
		},
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
	},
	// The private proof has its own phase/cleanup ledger and must return before
	// any ordinary-mode host marker reads or success-overriding fallbacks.
	Action: func(c *cli.Context) error {
		if c.IsSet(protectedModeFlag) {
			return runProtectedSharedCLI(c)
		}
		execCommand, err := loadExecCommand(c)
		if err != nil {
			return err
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
		runMany(c, func(id string) error {
			ctx := context.Background()

			options, err := createLCOWOptions(ctx, c, id)
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return err
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
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
			}
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
		if section != nil && firstErr != nil {
			if markerVerified {
				logrus.WithError(firstErr).Warn(
					"ignoring UVM lifecycle error after verified " +
						"shared-memory marker",
				)
				return nil
			}
			return firstErr
		}
		return nil
	},
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
) error {
	vm, err := uvm.CreateLCOW(ctx, options)
	if err != nil {
		return err
	}
	defer func() {
		_ = vm.CloseCtx(ctx)
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

func sharedMemoryProofRole(uvmID string) (string, error) {
	switch uvmID {
	case "uvmboot-0":
		return "a", nil
	case "uvmboot-1":
		return "b", nil
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

// sharedMemoryGuestModuleCommand produces the ordinary diagnostic command with
// a checked signed page-index conversion. Protected mode uses a separate fresh
// post-seal command and cannot enter this host-seed protocol.
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

	byteGPA, err := uvm.SharedMemoryByteGPA(int64(mapped.GuestPhysicalAddress), int64(configured.Length))
	if err != nil {
		return "", err
	}
	if configured.ProtectedShared || mapped.ProtectedShared != nil {
		return "", fmt.Errorf("ordinary guest command cannot consume protected backing")
	}
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
