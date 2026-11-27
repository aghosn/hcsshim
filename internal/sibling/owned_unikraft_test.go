//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/Microsoft/go-winio/pkg/guid"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/vm/vmutils"
)

func ownedUnikraftParameters() string {
	return "libukbus_vmbus.storage_controller=" + guestrequest.ScsiControllerGuids[0] +
		" libukbus_vmbus.storage_luns=0:0:ro libukbus_vmbus.live_storage=1 libukbus_vmbus.uplink_device=0" +
		" libukbus_vmbus.uplink_address=172.31.250.2 libukbus_vmbus.uplink_gateway=172.31.250.1" +
		" libukbus_vmbus.provider_address=10.200.0.1 libukbus_vmbus.peer_address=10.200.0.2" +
		" libukbus_vmbus.provider_mac=02:00:00:00:00:01 libukbus_vmbus.peer_mac=02:00:00:00:00:02"
}

func ownedUnikraftFixture(t *testing.T, parameters string, pages uint64) *Config {
	t.Helper()
	config := testConfig()
	config.SharedMemoryBytes, config.UnikraftPackage = 32<<20, t.TempDir()
	data, err := json.Marshal(map[string]any{
		"guest_arch": "x64",
		"guest_configs": []any{map[string]any{
			"image": map[string]any{"snp_linux_direct": map[string]any{
				"processor_count": 1, "memory_page_count": pages,
				"linux": map[string]string{"command_line": parameters},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{"launch-manifest.json": data, "guest.vmgs": []byte("fixture")} {
		if err := os.WriteFile(filepath.Join(config.UnikraftPackage, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return config
}

func TestOwnedUnikraftPrebootRootAndNoDiodeGCS(t *testing.T) {
	config := ownedUnikraftFixture(t, ownedUnikraftParameters(), 32768)
	cfg, err := loadOwnedUnikraft(config)
	if err != nil {
		t.Fatal(err)
	}
	base := testOptions()
	base.ProcessorCount, base.MemorySizeInMB = 1, 2048
	workload, diode, err := pairOptions(base, config, "group", &Section{HCSName: "owned", Size: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := configureOwnedUnikraft(workload, diode, config, cfg, "unique-pair", ""); err != nil {
		t.Fatal(err)
	}
	if diode.UseGuestConnection || diode.ForwardStdout || diode.ForwardStderr ||
		diode.DmVerityMode || diode.KernelBootOptions != "" || diode.DmVerityRootFsVhd != "" ||
		diode.Appliance == nil || !diode.Appliance.NativeStorageControl ||
		diode.MemorySizeInMB != 130 || diode.ProcessorCount != 1 || diode.VPMemDeviceCount != 0 ||
		diode.SCSIControllerCount != 1 || diode.GuestStateFilePath != "guest.vmgs" ||
		diode.BootFilesPath != config.UnikraftPackage {
		t.Fatalf("native provider retained Linux services or changed its resource layout: %+v", diode)
	}
	root := diode.Appliance.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments["0"]
	if root.Path != filepath.Join(workload.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd) ||
		!root.ReadOnly || root.Type_ != "VirtualDisk" {
		t.Fatalf("permanent boot root is not the workload's copied verified VHD: %+v", root)
	}
	if !workload.UseGuestConnection || !workload.DmVerityMode || !workload.SiblingRoot ||
		workload.MemorySizeInMB != base.MemorySizeInMB || !workload.SecurityPolicyEnabled ||
		workload.SecurityPolicy != base.SecurityPolicy || diode.SecurityPolicy != base.SecurityPolicy ||
		base.Appliance != nil || base.SiblingRoot || base.MemorySizeInMB != 2048 {
		t.Fatal("native provider selection altered workload security, memory or caller options")
	}
	guests := pairShellGuests(&Pair{Workload: new(uvm.UtilityVM), Diode: new(uvm.UtilityVM), unikraft: true})
	if len(guests) != 1 || guests[0].name != "workload" {
		t.Fatal("native appliance attempted to expose a GCS shell")
	}
}

func TestOwnedUnikraftIndependentWorkloadResources(t *testing.T) {
	config := ownedUnikraftFixture(t, ownedUnikraftParameters(), 32768)
	for _, resources := range [][]VMResources{
		nil,
		{{ProcessorCount: 1, MemoryMB: 130}, {ProcessorCount: 1, MemoryMB: 4096}},
		{{ProcessorCount: 1, MemoryMB: 130}, {ProcessorCount: 2, MemoryMB: 8192}},
		{{ProcessorCount: 1, MemoryMB: 130}, {ProcessorCount: 8, MemoryMB: 4096}},
	} {
		config.VMResources = resources
		cfg, err := loadOwnedUnikraft(config)
		if err != nil {
			t.Fatal(err)
		}
		base := testOptions()
		base.ProcessorCount, base.MemorySizeInMB = 4, 2048
		workload, diode, err := pairOptions(base, config, "group", &Section{HCSName: "owned", Size: 32 << 20})
		if err != nil {
			t.Fatal(err)
		}
		expected := VMResources{ProcessorCount: base.ProcessorCount, MemoryMB: base.MemorySizeInMB}
		if resources != nil {
			expected = resources[1]
		}
		if err := configureOwnedUnikraft(workload, diode, config, cfg, "group", ""); err != nil {
			t.Fatal(err)
		}
		if workload.ProcessorCount != expected.ProcessorCount || workload.MemorySizeInMB != expected.MemoryMB ||
			diode.ProcessorCount != 1 || diode.MemorySizeInMB != 130 ||
			base.ProcessorCount != 4 || base.MemorySizeInMB != 2048 {
			t.Fatal("Unikraft image capability changed or constrained independent workload resources")
		}
	}
	for _, resource := range []VMResources{
		{ProcessorCount: 2, MemoryMB: 130},
		{ProcessorCount: 1, MemoryMB: 128},
		{ProcessorCount: 1, MemoryMB: 132},
	} {
		config.VMResources = []VMResources{resource, {ProcessorCount: 8, MemoryMB: 4096}}
		if _, err := loadOwnedUnikraft(config); err == nil || !strings.Contains(err.Error(), "image capability") {
			t.Fatalf("incompatible image allocation accepted: %+v %v", resource, err)
		}
		workload, diode, err := pairOptions(testOptions(), config, "group", &Section{HCSName: "owned", Size: 32 << 20})
		if err != nil {
			t.Fatal(err)
		}
		cfg := &UnikraftConfig{MemoryMB: 128}
		if err := configureOwnedUnikraft(workload, diode, config, cfg, "group", ""); err == nil {
			t.Fatal("programmatic native configuration silently discarded incompatible resources")
		}
	}
}

func TestOwnedUnikraftRejectsWrongBootGeometry(t *testing.T) {
	parameters := ownedUnikraftParameters()
	for name, command := range map[string]string{
		"root-not-zero":   strings.Replace(parameters, "0:0:ro", "3:0:ro", 1),
		"root-writable":   strings.Replace(parameters, "0:0:ro", "0:0:rw", 1),
		"extra-boot-disk": strings.Replace(parameters, "0:0:ro", "0:0:ro,1:1:ro", 1),
		"controller":      strings.Replace(parameters, guestrequest.ScsiControllerGuids[0], guestrequest.ScsiControllerGuids[1], 1),
		"no-network":      strings.Split(parameters, " libukbus_vmbus.uplink_device=")[0],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadOwnedUnikraft(ownedUnikraftFixture(t, command, 32768)); err == nil {
				t.Fatal("accepted firmware incompatible with the native owned pair")
			}
		})
	}
	if _, err := loadOwnedUnikraft(ownedUnikraftFixture(t, parameters, 24576)); err == nil {
		t.Fatal("silently changed the deferred 128 MiB memory configuration")
	}
	config := ownedUnikraftFixture(t, parameters, 32768)
	if err := os.Remove(filepath.Join(config.UnikraftPackage, "guest.vmgs")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOwnedUnikraft(config); err == nil {
		t.Fatal("accepted a missing firmware image")
	}
}

func TestOwnedUnikraftSelectionIsExplicitAndRejectsRelayFallback(t *testing.T) {
	config := ownedUnikraftFixture(t, ownedUnikraftParameters(), 32768)
	for _, change := range []func(*Config){
		func(c *Config) { c.UnikraftPackage = "relative" },
		func(c *Config) { c.SharedMemoryBytes = 16 << 20 },
	} {
		invalid := *config
		change(&invalid)
		data, err := json.Marshal(&invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeConfig(strings.NewReader(string(data))); err == nil {
			t.Fatal("accepted ambiguous native provider or silent direct-GCS fallback")
		}
	}
	data, _ := json.Marshal(config)
	decoded, err := decodeConfig(strings.NewReader(string(data)))
	if err != nil || !reflect.DeepEqual(config, decoded) {
		t.Fatalf("native provider selection did not round-trip: %+v, %v", decoded, err)
	}
	cfg, err := loadOwnedUnikraft(config)
	if err != nil {
		t.Fatal(err)
	}
	config.MediateGCS = true
	if _, err := loadOwnedUnikraft(config); err == nil {
		t.Fatal("accepted mediation with direct-mode firmware")
	}
	for _, change := range []func(*uvm.OptionsLCOW){
		func(o *uvm.OptionsLCOW) { hcl := true; o.HclEnabled = &hcl },
		func(o *uvm.OptionsLCOW) { o.Appliance = &uvm.LCOWApplianceOptions{} },
	} {
		base := testOptions()
		base.ProcessorCount = 1
		change(base)
		workload, diode, err := pairOptions(base, config, "group", &Section{HCSName: "owned", Size: 32 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if err := configureOwnedUnikraft(workload, diode, config, cfg, "group", ""); err == nil {
			t.Fatal("accepted incompatible workload boot options")
		}
	}
}

func TestOwnedUnikraftMediatedFirmwareSelection(t *testing.T) {
	config := ownedUnikraftFixture(t, ownedUnikraftParameters()+" libukbus_vmbus.gcs_relay=1", 32768)
	if _, err := loadOwnedUnikraft(config); err == nil {
		t.Fatal("accepted relay firmware with a direct workload GCS route")
	}
	config.MediateGCS = true
	cfg, err := loadOwnedUnikraft(config)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GCSRelay || !cfg.LiveStorage {
		t.Fatal("lost authored native services")
	}
	var output strings.Builder
	ready := make(chan time.Time, 1)
	err = CaptureUnikraftConsole(strings.NewReader("diode-gcs: session failed: -104; no fallback\n"),
		&output, ready, "halt")
	if err == nil || !strings.Contains(err.Error(), "management relay failed") {
		t.Fatalf("native relay failure did not reach provider supervision: %v", err)
	}
	detail := "diode-gcs: IO port 1610612738 root->workload failed: -107; buffered=0 eof=1 fin=0"
	err = CaptureUnikraftConsole(strings.NewReader(detail+"\ndiode-gcs: session failed: -107; no fallback\n"),
		&output, ready, "halt")
	if err == nil || !strings.Contains(err.Error(), detail) {
		t.Fatalf("native stream failure details were lost: %v", err)
	}
}

func TestOwnedProviderCleanupRetainsCause(t *testing.T) {
	cause := errors.New("native control lost")
	cleanupErr := errors.New("workload close failed")
	var calls []string
	pair := &Pair{
		done:           make(chan struct{}),
		workloadCloser: closeFunc(func() error { calls = append(calls, "workload"); return cleanupErr }),
		diodeCloser:    closeFunc(func() error { calls = append(calls, "diode"); return nil }),
		uplinkCleanup:  func() error { calls = append(calls, "uplink"); return nil },
		sectionCloser:  closeFunc(func() error { calls = append(calls, "section"); return nil }),
	}
	if err := pair.close(cause); !errors.Is(err, cause) || !errors.Is(err, cleanupErr) {
		t.Fatalf("provider or cleanup failure was lost: %v", err)
	}
	if err := pair.Close(); !errors.Is(err, cause) {
		t.Fatalf("owner could not observe the original provider failure: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"workload", "diode", "uplink", "section"}) {
		t.Fatalf("native failure cleanup broke consumer-before-provider ownership: %v", calls)
	}
	select {
	case <-pair.done:
	default:
		t.Fatal("pair shutdown did not stop its watchers")
	}
}

func TestOwnedUnikraftConsoleCloseCancelsPrebootAccept(t *testing.T) {
	id, err := guid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	console, err := newOwnedUnikraftConsole(`\\.\pipe\hcsshim-unikraft-test-`+id.String(), t.TempDir(), "halt", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := console.waitReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("console ignored startup cancellation: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- console.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("normal preboot cancellation failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("console accept survived pair shutdown")
	}
}

func TestOwnedUnikraftConsoleCapturesAndCancelsReader(t *testing.T) {
	id, err := guid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	pipe, directory := `\\.\pipe\hcsshim-unikraft-test-`+id.String(), t.TempDir()
	console, err := newOwnedUnikraftConsole(pipe, directory, "halt", false)
	if err != nil {
		t.Fatal(err)
	}
	defer console.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, pipe)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	early := "hyperv: isolation type 2 (SNP), paravisor absent\n"
	markers := "vmbus: all offers delivered\nvmbus: idle=halt\nsibling: provider ready protocol=4;\n"
	if _, err := io.WriteString(conn, early); err != nil {
		t.Fatal(err)
	}
	// A persisted SNP marker proves execution only; it cannot open the gate.
	select {
	case <-console.boot:
	case <-ctx.Done():
		t.Fatal("no early guest execution evidence")
	}
	select {
	case <-console.ready:
		t.Fatal("early guest output was incorrectly accepted as provider readiness")
	default:
	}
	written := make(chan error, 1)
	go func() { _, err := io.WriteString(conn, markers); written <- err }()
	if err := console.waitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := console.Close(); err != nil {
		t.Fatalf("normal active console shutdown failed: %v", err)
	}
	log, err := os.ReadFile(filepath.Join(directory, "unikraft-console.log"))
	if err != nil || string(log) != early+markers {
		t.Fatalf("boot evidence was not persisted: %q, %v", log, err)
	}
}

// TestProtectedSharedOwnedUnikraftConsoleCollision preserves a retained log
// even if it appeared after preflight. Ordinary console startup still truncates.
func TestProtectedSharedOwnedUnikraftConsoleCollision(t *testing.T) {
	id, err := guid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "unikraft-console.log")
	pipe := `\\.\pipe\hcsshim-unikraft-test-` + id.String()
	const retained = "evidence from another attempt\n"
	if err := os.WriteFile(path, []byte(retained), 0600); err != nil {
		t.Fatal(err)
	}
	console, err := newOwnedUnikraftConsole(pipe, dir, "halt", true)
	if console != nil {
		_ = console.Close()
	}
	if console != nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive console did not fail on collision: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != retained {
		t.Fatalf("exclusive console changed retained bytes: %q, %v", data, err)
	}
	console, err = newOwnedUnikraftConsole(pipe, dir, "halt", false)
	if err != nil {
		t.Fatalf("collision leaked the pipe or changed ordinary open: %v", err)
	}
	if err := console.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || len(data) != 0 {
		t.Fatalf("ordinary console did not truncate: %q, %v", data, err)
	}
}

// TestProtectedSharedOwnedUnikraftRoot checks that preflight needs the same
// verified workload template, but the appliance attaches a distinct copy
// before workload Create. Neither source nor the workload copy is overwritten.
func TestProtectedSharedOwnedUnikraftRoot(t *testing.T) {
	config := ownedUnikraftFixture(t, ownedUnikraftParameters()+" libukbus_vmbus.gcs_relay=1", 32768)
	config.ProtectedShared, config.MediateGCS, config.Interactive, config.WorkloadVmbusNoRp = true, true, true, true
	config.RunID = "root-fixture"
	config.CleanupReceiptPath = filepath.Join(t.TempDir(), "protected-cleanup-result.json")
	base := testOptions()
	base.BundleDirectory, base.BootFilesPath = t.TempDir(), t.TempDir()
	hcl := false
	base.HclEnabled = &hcl
	base.AllowOvercommit, base.EnableDeferredCommit = false, false
	base.PreferredRootFSType = uvm.PreferredRootFSTypeNA
	workload, diode, err := commonPairOptions(base, config, "group")
	if err != nil {
		t.Fatal(err)
	}
	native, err := loadOwnedUnikraft(config)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(diode.BundleDirectory, protectedUnikraftRootName)
	if err := configureOwnedUnikraft(workload, diode, config, native, "group", root); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	source := filepath.Join(workload.BootFilesPath, workload.DmVerityRootFsVhd)
	workloadCopy := filepath.Join(workload.BundleDirectory, vmutils.DefaultDmVerityRootfsVhd)
	for path, content := range map[string]string{
		source: "verified", workloadCopy: "workload",
		filepath.Join(workload.BootFilesPath, workload.GuestStateFilePath): "workload vmgs",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := preflightProtectedPair(ctx, config, workload, diode); err != nil {
		t.Fatalf("valid appliance preflight depends on Linux diode inputs: %v", err)
	}
	if err := os.Mkdir(diode.BundleDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := stageProtectedUnikraftRoot(ctx, workload, diode); err != nil {
		t.Fatal(err)
	}
	if err := stageProtectedUnikraftRoot(ctx, workload, diode); err == nil {
		t.Fatal("permanent appliance root could be overwritten")
	}
	attachment := diode.Appliance.SCSI[guestrequest.ScsiControllerGuids[0]].Attachments["0"]
	if attachment.Path != root || !attachment.ReadOnly {
		t.Fatalf("wrong permanent root attachment: %+v", attachment)
	}
	for path, want := range map[string]string{source: "verified", workloadCopy: "workload", root: "verified"} {
		if data, err := os.ReadFile(path); err != nil || string(data) != want {
			t.Fatalf("boot input %s: got %q (%v), want %q", path, data, err, want)
		}
	}
}

// TestProtectedSharedOwnedUnikraftProbe exercises the real startup sequencing
// with modeled native results and the existing console gate. Partial startup,
// invalid receipts and timeout/cancellation stop forward work; neither Start
// result can publish a sandbox.
func TestProtectedSharedOwnedUnikraftProbe(t *testing.T) {
	injected := errors.New("fixture failure")
	for _, tc := range []struct {
		name string
		stop string
		want error
	}{
		{"partial-prepare", "diode_prepare", injected},
		{"partial-create", "diode_create", injected},
		{"bad-receipt", "diode_start_and_storage_handshake", nil},
		{"storage-handshake", "diode_start_and_storage_handshake", injected},
		{"workload-create", "workload_create", injected},
		{"relay-setup", "workload_gcs_relay", injected},
		{"readiness-timeout", "provider_readiness", context.DeadlineExceeded},
		{"canceled-after-ready", "workload_start_not_dispatched", context.Canceled},
		{"start-failure", "workload_start_result", injected},
		{"bring-up-only", "workload_start_result", errProtectedUnikraftBringUpOnly},
	} {
		// Isolate each attempt's lease, phase history and cancellation.
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backing := &ProtectedBacking{size: 32 << 20, pages: 8192}
			// Model an operation failure without modeling native ownership.
			failAt := func(phase string) error {
				if tc.stop == phase && tc.want == injected {
					return injected
				}
				return nil
			}
			console := &ownedUnikraftConsole{ready: make(chan time.Time, 1), done: make(chan struct{})}
			started := false
			steps := protectedUnikraftSteps{
				// Pre-create and relay failures may leave partial host resources.
				prepare:     func(context.Context) error { return failAt("diode_prepare") },
				createDiode: func(context.Context) error { return failAt("diode_create") },
				// Import is based on the real receipt validation, not a phase flag.
				startDiode: func(context.Context) error {
					receipt := &hcsschema.ProtectedSharedRegionInfo{
						Version: 2, LeaseId: 7, PageCount: 8192, InitializedPages: 8192, Prepared: true, Installed: true,
					}
					receipt.Installed = tc.name != "bad-receipt"
					if err := backing.ObserveStartup(receipt); err != nil {
						return err
					}
					return failAt("diode_start_and_storage_handshake")
				},
				// Check the owner issues Import with the observed lease only.
				createWorkload: func(context.Context) error {
					r, err := backing.Region(hcsschema.ProtectedSharedBackingImport)
					if err != nil || r.ProtectedSharedLeaseId != 7 {
						t.Fatalf("Import dispatched without validated lease: %+v %v", r, err)
					}
					return failAt("workload_create")
				},
				configureRelay: func(context.Context) error { return failAt("workload_gcs_relay") },
				// A timeout leaves the real gate unsatisfied; other cases have all markers.
				waitReady: func(ctx context.Context) error {
					if tc.name == "readiness-timeout" {
						ctx, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
						defer cancel()
						return console.waitReady(ctx)
					}
					console.ready <- time.Now()
					return console.waitReady(ctx)
				},
				// Dispatch is separate from the Start result.
				startWorkload: func(context.Context) protectedStartOutcome {
					started = true
					return protectedStartOutcome{called: true, err: failAt("workload_start_result")}
				},
			}
			var phases []string
			// Cancel after a successful gate to exercise the Start dispatch boundary.
			err := steps.run(ctx, func(phase string, _ error) error {
				phases = append(phases, phase)
				if tc.name == "canceled-after-ready" && phase == "provider_readiness" {
					cancel()
				}
				return nil
			})
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) ||
				tc.name == "bad-receipt" && !strings.Contains(err.Error(), "installation receipt") {
				t.Fatalf("wrong probe result: %v", err)
			}
			all := []string{"diode_prepare", "diode_create", "diode_start_and_storage_handshake",
				"workload_create", "workload_gcs_relay", "provider_readiness"}
			if tc.stop == "workload_start_not_dispatched" || tc.stop == "workload_start_result" {
				if !reflect.DeepEqual(phases, append(all, tc.stop)) || started != (tc.stop == "workload_start_result") {
					t.Fatalf("out-of-order or premature dispatch: %v start=%t", phases, started)
				}
				return
			}
			for i, phase := range all {
				if phase == tc.stop {
					if !reflect.DeepEqual(phases, all[:i+1]) || started {
						t.Fatalf("out-of-order or premature dispatch: %v start=%t", phases, started)
					}
					break
				}
			}
		})
	}
}

// TestProtectedSharedOwnedUnikraftEntropy closes the listener on successful
// Create, even if cancellation or a failed relay bind prevents Start. A close
// failure is preserved and leaves the listener owned for a housekeeping retry.
func TestProtectedSharedOwnedUnikraftEntropy(t *testing.T) {
	relayFailure := errors.New("fixture relay bind failed")
	closeFailure := errors.New("fixture entropy close failed")
	for _, tc := range []struct {
		name        string
		wantErr     error
		wantRelay   bool
		wantPending bool
	}{
		{"cancel-after-create", context.Canceled, false, false},
		{"relay-bind-failure", relayFailure, true, false},
		{"entropy-close-failure", closeFailure, false, true},
	} {
		// Isolate each startup's listener and cancellation.
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &protectedPair{}
			listening, relay := false, false
			closes := 0
			// Model only the listener that a successful Create publishes.
			create := func(context.Context) error {
				listening = true
				if tc.wantErr == context.Canceled {
					cancel()
				}
				return nil
			}
			// Verify disable runs even when forward startup is canceled.
			disable := func(ctx context.Context) error {
				closes++
				if !listening || ctx.Err() != nil {
					t.Fatal("entropy close required live startup or reused a closed listener")
				}
				if tc.wantPending && closes == 1 {
					return closeFailure
				}
				listening = false
				return nil
			}
			// Use inert earlier phases to test the actual forward sequence.
			noop := func(context.Context) error { return nil }
			steps := protectedUnikraftSteps{
				prepare: noop, createDiode: noop, startDiode: noop,
				// Invoke the same successful-Create continuation as production.
				createWorkload: func(ctx context.Context) error { return p.createUnikraftWorkload(ctx, create, disable) },
				// A failing bind must see entropy already disabled.
				configureRelay: func(context.Context) error {
					relay = true
					if listening {
						t.Error("relay setup ran with entropy still open")
					}
					return relayFailure
				},
			}
			// No persisted phase diagnostics are needed for this fixture.
			err := steps.run(ctx, func(string, error) error { return nil })
			if !errors.Is(err, tc.wantErr) || relay != tc.wantRelay || listening != tc.wantPending || closes != 1 {
				t.Fatalf("err=%v relay=%t listening=%t close attempts=%d", err, relay, listening, closes)
			}
			if err := p.disableUnikraftEntropy(context.Background()); err != nil || listening || p.probeEntropyClose != nil {
				t.Fatalf("housekeeping leaked the entropy listener: %v", err)
			}
		})
	}
}

// TestProtectedSharedOwnedUnikraftStartAttempt checks the run log while Start
// is blocked before its native callback. An owner attempt must be visible
// then, but cannot claim native installation or a final Start result. A
// blocked attempt writer must not delay cleanup or admit Start after stop.
func TestProtectedSharedOwnedUnikraftStartAttempt(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), protectedPairLogName))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	p := &protectedPair{
		unikraft: &UnikraftConfig{}, config: &Config{RunID: "attempt-fixture"},
		workload: protectedVMAttempt{options: testOptions()}, log: file, ctx: context.Background(),
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-resume:
		default:
			close(resume)
		}
	}()
	injected := errors.New("fixture Start did not reach native completion")
	// Hold Start before any callback to inspect only the owner's evidence.
	start := func(context.Context, time.Duration, func(context.Context, error) error) error {
		close(entered)
		<-resume
		return injected
	}
	canceled, cancel := context.WithCancel(p.ctx)
	cancel()
	if outcome := p.startWithNativeCompletion(canceled, &p.workload, file, start); outcome.called || !errors.Is(outcome.err, context.Canceled) {
		t.Fatalf("canceled workload attempt was admitted: %+v", outcome)
	}
	if data, err := os.ReadFile(file.Name()); err != nil || len(data) != 0 {
		t.Fatalf("unadmitted attempt wrote evidence: %q, %v", data, err)
	}
	done := make(chan protectedStartOutcome, 1)
	// Dispatch through the real owner's admission checks.
	go func() { done <- p.startWithNativeCompletion(p.ctx, &p.workload, file, start) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("workload Start was not invoked")
	}
	data, err := os.ReadFile(file.Name())
	text := string(data)
	if err != nil || !strings.Contains(text, "phase=workload_start_attempt run=attempt-fixture vm="+p.workload.options.ID) ||
		strings.Contains(text, "installed=true") || strings.Contains(text, "workload_start_result") {
		t.Fatalf("wrong evidence before native completion: %q, %v", data, err)
	}
	// Release the blocked Start and verify the admitted call keeps its error.
	close(resume)
	select {
	case outcome := <-done:
		if !outcome.called || !errors.Is(outcome.err, injected) {
			t.Fatalf("Start error was not retained: %+v", outcome)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fixture Start did not return after release")
	}

	// Block only the attempt writer while the real owner makes and publishes
	// its cleanup decision. No HCS VM or backing is needed for this boundary.
	t.Run("blocked-attempt-writer", func(t *testing.T) {
		config := workloadVmbusNoRpConfigFixture()
		config.CleanupReceiptPath = filepath.Join(t.TempDir(), "protected-cleanup-result.json")
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		_, stopWatch := context.WithCancel(context.Background())
		defer stopWatch()
		pair := &Pair{done: make(chan struct{})}
		p := &protectedPair{
			pair: pair, config: config, unikraft: &UnikraftConfig{}, ctx: ctx, cancel: cancel,
			stopWatch: stopWatch, startupDone: make(chan struct{}),
			workload: protectedVMAttempt{options: testOptions()}, diode: protectedVMAttempt{options: testOptions()},
		}
		pair.protected = p
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		dispatched, returned := make(chan struct{}), make(chan error, 1)
		// Any call to Start after stop is a regression, even without HCS.
		start := func(context.Context, time.Duration, func(context.Context, error) error) error {
			close(dispatched)
			return nil
		}
		// Use the real sequencing classification after the blocked attempt.
		go func() {
			defer close(p.startupDone)
			steps := testProtectedUnikraftStartSteps(p, writer, start)
			returned <- steps.run(context.Background(), func(phase string, err error) error {
				if phase == "workload_start_result" || phase == "workload_start_not_dispatched" && err == nil {
					t.Error("blocked and canceled attempt was recorded as a Start result")
				}
				return nil
			})
		}()
		writing := make(chan error, 1)
		// Read one byte to prove Write has entered. It cannot finish until the
		// rest of the line is consumed or the reader is closed.
		go func() {
			var b [1]byte
			_, err := io.ReadFull(reader, b[:])
			writing <- err
		}()
		select {
		case err := <-writing:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("attempt writer was never entered")
		}
		stopErr := errors.New("fixture owner stopped")
		decision := make(chan error, 1)
		// Request the actual owner shutdown while diagnostic I/O is blocked.
		go func() { decision <- pair.close(stopErr) }()
		select {
		case err := <-decision:
			if err != nil {
				t.Fatalf("protected cleanup failed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("native cleanup waited for the diagnostic writer")
		}
		if data, err := os.ReadFile(config.CleanupReceiptPath); err != nil || !strings.Contains(string(data), `"result":"released"`) {
			t.Fatalf("release receipt missing while the writer was blocked: %q, %v", data, err)
		}
		writeErr := errors.New("fixture attempt log write failed")
		if err := reader.CloseWithError(writeErr); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-returned:
			if !errors.Is(err, stopErr) || !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "workload_start_not_dispatched") {
				t.Fatalf("owner stop cause or diagnostic error was lost: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("startup did not return after the writer resumed")
		}
		select {
		case <-dispatched:
			t.Fatal("workload Start dispatched after protected cleanup")
		default:
		}
	})

	// A diagnostic error must not turn a successful call into a Start failure,
	// or erase the real error when Start fails.
	t.Run("start-result-with-log-failure", func(t *testing.T) {
		writeErr := errors.New("fixture attempt log failed")
		resultLogErr := errors.New("fixture result log failed")
		for _, startErr := range []error{nil, injected} {
			reader, writer := io.Pipe()
			_ = reader.CloseWithError(writeErr)
			// Return the modeled UVM Start outcome without native evidence.
			start := func(context.Context, time.Duration, func(context.Context, error) error) error { return startErr }
			resultLogged := false
			steps := testProtectedUnikraftStartSteps(p, writer, start)
			err := steps.run(p.ctx, func(phase string, result error) error {
				if phase != "workload_start_result" {
					return nil
				}
				resultLogged = true
				if result != startErr {
					t.Errorf("logged Start result %v, want %v", result, startErr)
				}
				return resultLogErr
			})
			_ = writer.Close()
			want := startErr
			if want == nil {
				want = errProtectedUnikraftBringUpOnly
			}
			if !resultLogged || !errors.Is(err, want) || !errors.Is(err, writeErr) || !errors.Is(err, resultLogErr) {
				t.Fatalf("Start outcome or diagnostic failure lost: %v", err)
			}
		}
	})
}

// testProtectedUnikraftStartSteps isolates final Start admission and result
// reporting from earlier phases already exercised by the sequencing fixture.
func testProtectedUnikraftStartSteps(p *protectedPair, writer io.Writer,
	start func(context.Context, time.Duration, func(context.Context, error) error) error,
) protectedUnikraftSteps {
	// Treat each earlier milestone as already satisfied.
	noop := func(context.Context) error { return nil }
	return protectedUnikraftSteps{
		prepare: noop, createDiode: noop, startDiode: noop, createWorkload: noop, configureRelay: noop, waitReady: noop,
		// Use the production dispatch boundary and diagnostic writer.
		startWorkload: func(ctx context.Context) protectedStartOutcome {
			return p.startWithNativeCompletion(ctx, &p.workload, writer, start)
		},
	}
}

// TestProtectedSharedOwnedUnikraftBootCopyCleanup models the housekeeping
// state after release and an appliance Create. It removes only the staged
// root and VMGS, not Linux-named or otherwise unexpected files.
func TestProtectedSharedOwnedUnikraftBootCopyCleanup(t *testing.T) {
	opts := testOptions()
	opts.BundleDirectory = t.TempDir()
	opts.Appliance = &uvm.LCOWApplianceOptions{NativeStorageControl: true}
	for _, name := range []string{opts.GuestStateFilePath, protectedUnikraftRootName, vmutils.DefaultDmVerityRootfsVhd, "unrelated.txt"} {
		if err := os.WriteFile(filepath.Join(opts.BundleDirectory, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := &protectedPair{pair: &Pair{}, applianceRootOwned: true, unikraft: &UnikraftConfig{},
		diode: protectedVMAttempt{options: opts, bundleOwned: true, createAttempt: true},
	}
	p.cleanup()
	for _, name := range []string{opts.GuestStateFilePath, protectedUnikraftRootName} {
		if _, err := os.Stat(filepath.Join(opts.BundleDirectory, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("owned copy %s was not removed: %v", name, err)
		}
	}
	for _, name := range []string{vmutils.DefaultDmVerityRootfsVhd, "unrelated.txt"} {
		if data, err := os.ReadFile(filepath.Join(opts.BundleDirectory, name)); err != nil || string(data) != name {
			t.Errorf("unexpected file %s was not retained: %q, %v", name, data, err)
		}
	}
}

// TestProtectedSharedOwnedUnikraftCleanup uses the real protected close path
// without HCS. Pending housekeeping cannot gate a truthful release but must
// prevent orderly shim exit. An unobservable Create still denies release.
func TestProtectedSharedOwnedUnikraftCleanup(t *testing.T) {
	for _, unobservable := range []bool{false, true} {
		dir := t.TempDir()
		base := testOptions()
		base.BundleDirectory = dir
		base.Appliance = &uvm.LCOWApplianceOptions{NativeStorageControl: true}
		root := filepath.Join(dir, protectedUnikraftRootName)
		if unobservable {
			if err := os.WriteFile(root, []byte("staged root"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		config := workloadVmbusNoRpConfigFixture()
		config.CleanupReceiptPath = filepath.Join(dir, "protected-cleanup-result.json")
		ctx, cancel := context.WithCancelCause(context.Background())
		watch, stopWatch := context.WithCancel(context.Background())
		// Keep the modeled console reader open past the native decision.
		consoleDone, housekeeping := make(chan struct{}), make(chan struct{})
		resumeHousekeeping := make(chan struct{})
		defer func() {
			// Always release any waiting cleanup if the fixture fails early.
			select {
			case <-resumeHousekeeping:
			default:
				close(resumeHousekeeping)
			}
		}()
		file, err := os.Create(filepath.Join(dir, "unikraft-console.log"))
		if err != nil {
			t.Fatal(err)
		}
		// Hold drainage independently of cancellation, and signal uplink
		// cleanup only when housekeeping reaches it.
		console := &ownedUnikraftConsole{done: consoleDone, cancel: func() {}, log: file}
		pair := &Pair{done: make(chan struct{}), unikraftConsole: console,
			// Simulate an uplink delete still outstanding after console drainage.
			uplinkCleanup: func() error {
				close(housekeeping)
				<-resumeHousekeeping
				return nil
			}}
		p := &protectedPair{pair: pair, config: config, unikraft: &UnikraftConfig{}, applianceRootOwned: unobservable, ctx: ctx, cancel: cancel,
			watchCtx: watch, stopWatch: stopWatch, startupDone: make(chan struct{}),
			diode: protectedVMAttempt{options: base, createAttempt: unobservable, bundleOwned: unobservable}, workload: protectedVMAttempt{options: base},
		}
		pair.protected = p
		if !unobservable {
			if err := registerProtectedPair(p); err != nil {
				t.Fatal(err)
			}
		}
		// Model a control call still keeping startup open. The receipt must
		// not wait for that call or for subsequent console drainage.
		decision := make(chan error, 1)
		go func() { decision <- pair.Close() }()
		select {
		case err := <-decision:
			if (err != nil) != unobservable {
				t.Errorf("unobservable=%t: wrong native cleanup decision: %v", unobservable, err)
			}
		case <-time.After(3 * time.Second):
			close(p.startupDone)
			close(consoleDone)
			t.Fatal("protected close waited for control or console drainage")
		}
		data, err := os.ReadFile(config.CleanupReceiptPath)
		close(p.startupDone)
		close(consoleDone)
		if unobservable {
			if !errors.Is(err, os.ErrNotExist) {
				t.Errorf("unobservable native ownership yielded a receipt: %q, %v", data, err)
			}
			if data, err := os.ReadFile(root); err != nil || string(data) != "staged root" {
				t.Errorf("unobservable native ownership lost the staged root: %q, %v", data, err)
			}
			if err := console.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			if err != nil || !strings.Contains(string(data), `"result":"released"`) {
				t.Errorf("receipt not published before housekeeping: %s %v", data, err)
			}
			select {
			case <-housekeeping:
			case <-time.After(3 * time.Second):
				t.Fatal("ordinary housekeeping did not reach uplink cleanup after console drainage")
			}
			protectedOwners.Lock()
			_, nativeOwner := protectedOwners.pairs[p]
			blocker := protectedShutdownBlocker()
			protectedOwners.Unlock()
			if nativeOwner {
				t.Error("native ownership remained registered after release")
			}
			if blocker == nil {
				t.Fatal("probe housekeeping did not retain an orderly shutdown hold")
			}
			if err := PrepareProtectedShutdown(); err == nil || !strings.Contains(err.Error(), "probes still publishing receipts or cleaning up") {
				t.Errorf("orderly shutdown was not refused by probe housekeeping: %v", err)
			}
			close(resumeHousekeeping)
			// Check the same shutdown guard without committing process-wide
			// shutdown in this fixture.
			deadline := time.Now().Add(3 * time.Second)
			for {
				protectedOwners.Lock()
				blocker = protectedShutdownBlocker()
				protectedOwners.Unlock()
				if blocker == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("orderly shutdown still refused after housekeeping: %v", blocker)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}
