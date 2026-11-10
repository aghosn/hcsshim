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
	if err := configureOwnedUnikraft(workload, diode, config, cfg, "unique-pair"); err != nil {
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
		func(o *uvm.OptionsLCOW) { o.ProcessorCount = 2 },
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
		if err := configureOwnedUnikraft(workload, diode, config, cfg, "group"); err == nil {
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
	console, err := newOwnedUnikraftConsole(`\\.\pipe\hcsshim-unikraft-test-`+id.String(), t.TempDir(), "halt")
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
	console, err := newOwnedUnikraftConsole(pipe, directory, "halt")
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
	markers := "hyperv: isolation type 2 (SNP), paravisor absent\nvmbus: all offers delivered\n" +
		"vmbus: idle=halt\nsibling: provider ready protocol=4;\n"
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
	if err != nil || string(log) != markers {
		t.Fatalf("boot evidence was not persisted: %q, %v", log, err)
	}
}
