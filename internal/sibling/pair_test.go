//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	"github.com/Microsoft/hcsshim/internal/uvm"
)

func testConfig() *Config {
	return &Config{Version: 1, ModuleDirectory: `C:\modules`, SharedMemoryBytes: 16 << 20, WorkloadGuestStateFile: "sibling-root.vmgs"}
}

func testOptions() *uvm.OptionsLCOW {
	opts := uvm.NewDefaultOptionsLCOW("sandbox@vm", "shim")
	opts.SecurityPolicyEnabled = true
	opts.SecurityPolicy = "existing-policy"
	opts.SecurityPolicyEnforcer = "existing-enforcer"
	opts.DmVerityMode = true
	opts.DmVerityRootFsVhd = "verified-root.vhd"
	opts.GuestStateFilePath = "kernel.vmgs"
	opts.BundleDirectory = `C:\bundle`
	return opts
}

func TestPairOptionsKeepSecurityAndSeparateOwnership(t *testing.T) {
	base := testOptions()
	section := &Section{HCSName: `\Sessions\0\BaseNamedObjects\test`, Size: 16 << 20}
	workload, diode, err := pairOptions(base, testConfig(), "unique-group", section)
	if err != nil {
		t.Fatal(err)
	}
	if workload.ID != base.ID || diode.ID != base.ID+"-diode" ||
		workload.BundleDirectory == diode.BundleDirectory || !workload.SiblingRoot || diode.SiblingRoot ||
		workload.GuestStateFilePath != "sibling-root.vmgs" || diode.GuestStateFilePath != "kernel.vmgs" ||
		workload.VPMemDeviceCount != 0 {
		t.Fatalf("invalid pair topology: workload=%+v diode=%+v", workload, diode)
	}
	for _, options := range []*uvm.OptionsLCOW{workload, diode} {
		if options.SecurityPolicy != base.SecurityPolicy || options.SecurityPolicyEnforcer != base.SecurityPolicyEnforcer ||
			!options.SecurityPolicyEnabled || !options.DmVerityMode ||
			options.DmVerityRootFsVhd != base.DmVerityRootFsVhd || options.HclEnabled != base.HclEnabled {
			t.Fatal("pair altered guest security or integrity options")
		}
		if options.SharedMemoryRegions[0].SectionName != section.HCSName ||
			options.SiblingCommunicationEndpoints[0].SharedMemorySectionName != section.HCSName {
			t.Fatal("guests did not share the owned section")
		}
	}
	if workload.SiblingCommunicationEndpoints[0].Role != hcsschema.SiblingCommunicationEndpointRoleWorkload ||
		diode.SiblingCommunicationEndpoints[0].Role != hcsschema.SiblingCommunicationEndpointRoleBackend {
		t.Fatal("roles still depend on uvmboot IDs")
	}
	workload.SecurityPolicy = "mutated"
	workload.MemorySizeInMB++
	if base.SecurityPolicy != "existing-policy" || diode.SecurityPolicy != "existing-policy" ||
		base.MemorySizeInMB != diode.MemorySizeInMB || base.SiblingRoot {
		t.Fatal("pair options aliased the caller or each other")
	}
}

func TestPairRejectsIncompatibleBaseBeforeCreatingVMs(t *testing.T) {
	for _, change := range []func(*uvm.OptionsLCOW){
		func(o *uvm.OptionsLCOW) { o.UseGuestConnection = false },
		func(o *uvm.OptionsLCOW) { o.SecurityPolicyEnabled = false },
		func(o *uvm.OptionsLCOW) { o.DmVerityMode = false },
		func(o *uvm.OptionsLCOW) { o.GuestStateFilePath = "" },
		func(o *uvm.OptionsLCOW) { o.SCSIControllerCount = 0 },
		func(o *uvm.OptionsLCOW) { o.SiblingRoot = true },
		func(o *uvm.OptionsLCOW) { o.GuestStateFilePath = "sibling-root.vmgs" },
		func(o *uvm.OptionsLCOW) { o.ID = "" },
		func(o *uvm.OptionsLCOW) { o.BundleDirectory = "relative" },
		func(o *uvm.OptionsLCOW) {
			o.SharedMemoryRegions = []uvm.LCOWSharedMemoryRegion{{SectionName: "another-owner"}}
		},
	} {
		base := testOptions()
		change(base)
		if _, _, err := pairOptions(base, testConfig(), "group", &Section{Size: 1 << 20}); err == nil {
			t.Fatalf("accepted incompatible pair options: %+v", base)
		}
	}
}

// TestPairConfigStrictOptIn checks pure version-1 opt-in decoding, including exact
// protected mask presence/bits and excluded profiles. Invalid or ambiguous input
// must fail before acquisition, rather than silently changing native policy.
func TestPairConfigStrictOptIn(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.Version = 0 },
		func(c *Config) { c.ModuleDirectory = "relative" },
		func(c *Config) { c.SharedMemoryBytes = 1 },
		func(c *Config) { c.SharedMemoryBytes++ },
		func(c *Config) { c.SharedMemoryBytes = 1 << 31 },
		func(c *Config) { c.WorkloadGuestStateFile = `..\kernel.vmgs` },
		func(c *Config) { c.WorkloadGuestStateFile = `C:\kernel.vmgs` },
		func(c *Config) { c.WorkloadGuestStateFile = "kernel.vhd" },
	} {
		config := testConfig()
		change(config)
		data, _ := json.Marshal(config)
		if _, err := decodeConfig(strings.NewReader(string(data))); err == nil {
			t.Fatalf("accepted invalid opt-in: %s", data)
		}
	}
	data, _ := json.Marshal(testConfig())
	if config, err := decodeConfig(strings.NewReader(string(data))); err != nil || !reflect.DeepEqual(config, testConfig()) {
		t.Fatalf("valid opt-in rejected: %+v %v", config, err)
	}
	for _, text := range []string{
		string(data) + "{}", strings.TrimSuffix(string(data), "}") + `,"existing_hcs_id":"borrowed"}`,
		string(data) + strings.Repeat(" ", 64<<10) + "{}",
	} {
		if _, err := decodeConfig(strings.NewReader(text)); err == nil {
			t.Fatalf("accepted competing/ambiguous ownership config: %s", text)
		}
	}
	if _, err := LoadConfig("relative"); err == nil {
		t.Fatal("accepted relative config-file path")
	}

	protected := testConfig()
	protected.ProtectedShared, protected.MediateGCS = true, true
	protected.Interactive = true
	protected.SharedMemoryBytes = 32 << 20
	protected.RunID = "fresh-session"
	protected.CleanupReceiptPath = `C:\session\protected-cleanup-result.json`
	data, _ = json.Marshal(protected)
	prefix := strings.TrimSuffix(string(data), "}")
	zero, maximum := uint64(0), ^uint64(0)
	for _, test := range []struct {
		fields          string
		diode, workload *uint64
		reject          bool
	}{
		{"", nil, nil, false},
		{`,"diode_partition_seal_mask":"0"`, &zero, nil, false},
		{`,"workload_partition_seal_mask":"0"`, nil, &zero, false},
		{`,"diode_partition_seal_mask":"18446744073709551615","workload_partition_seal_mask":"18446744073709551615"`, &maximum, &maximum, false},
		{`,"diode_partition_seal_mask":null`, nil, nil, true},
		{`,"workload_partition_seal_mask":null`, nil, nil, true},
		{`,"diode_partition_seal_mask":0`, nil, nil, true},
		{`,"diode_partition_seal_mask":""`, nil, nil, true},
		{`,"diode_partition_seal_mask":"-1"`, nil, nil, true},
		{`,"diode_partition_seal_mask":"+1"`, nil, nil, true},
		{`,"diode_partition_seal_mask":"0x1"`, nil, nil, true},
		{`,"diode_partition_seal_mask":"1.0"`, nil, nil, true},
		{`,"workload_partition_seal_mask":"1e2"`, nil, nil, true},
		{`,"workload_partition_seal_mask":" 1"`, nil, nil, true},
		{`,"workload_partition_seal_mask":"18446744073709551616"`, nil, nil, true},
		{`,"diode_partition_seal_mask":"1","diode_partition_seal_mask":"1"`, nil, nil, true},
		{`,"workload_partition_seal_mask":"1","WORKLOAD_PARTITION_SEAL_MASK":"2"`, nil, nil, true},
		{`,"mediate_gcs":false`, nil, nil, true},
		{`,"interactive":false`, nil, nil, true},
		{`,"shared_memory_bytes":16777216`, nil, nil, true},
		{`,"unikraft_package":"C:\\unikraft"`, nil, nil, true},
		{`,"run_id":""`, nil, nil, true},
		{`,"cleanup_receipt_path":"relative.json"`, nil, nil, true},
		{`,"partition_seal_pause_prefix":"C:\\pause"`, nil, nil, true},
		{`,"static_exports":[]`, nil, nil, true},
		{`,"cpu_group_id":"tuning"`, nil, nil, true},
		{`,"late_ahv_attestation":true`, nil, nil, true},
		{`,"protected_shared":false`, nil, nil, true},
	} {
		text := prefix + test.fields + "}"
		config, err := decodeConfig(strings.NewReader(text))
		if test.reject {
			if err == nil {
				t.Fatalf("accepted incompatible protected input: %s", text)
			}
		} else if err != nil || !reflect.DeepEqual(config.DiodePartitionSealMask, test.diode) ||
			!reflect.DeepEqual(config.WorkloadPartitionSealMask, test.workload) {
			t.Fatalf("protected mask selection/bits changed: %s: %+v %v", text, config, err)
		}
	}
	for _, fields := range []string{
		`,"diode_partition_seal_mask":"0"`, `,"workload_partition_seal_mask":"1"`,
	} {
		data, _ := json.Marshal(testConfig())
		if _, err := decodeConfig(strings.NewReader(strings.TrimSuffix(string(data), "}") + fields + "}")); err == nil {
			t.Fatalf("accepted protected mask without opt-in: %s", fields)
		}
	}
}

func TestPairBootstrapOverlapsWorkloadRootAndDiodeStartup(t *testing.T) {
	waitingForRoot := make(chan struct{})
	rootReady := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := bootstrap(ctx, func(ctx context.Context) error {
		close(waitingForRoot)
		select {
		case <-rootReady:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func(ctx context.Context) error {
		select {
		case <-waitingForRoot:
			close(rootReady)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		t.Fatalf("root-dependent startup deadlocked: %v", err)
	}
	failure := errors.New("diode bootstrap failed")
	err = bootstrap(ctx, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		func(context.Context) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("bootstrap did not cancel its waiting peer: %v", err)
	}
}

func TestPairGCSRelayOptIn(t *testing.T) {
	uplink := &Uplink{Address: "172.31.250.2/24", Gateway: UplinkGateway}
	for _, enabled := range []bool{false, true} {
		config := testConfig()
		config.MediateGCS = enabled
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeConfig(strings.NewReader(string(data)))
		if err != nil || decoded.MediateGCS != enabled {
			t.Fatalf("relay opt-in did not survive config decoding: %+v %v", decoded, err)
		}
		command := diodeBootstrapCommand(uplink, decoded.MediateGCS)
		if enabled {
			if command != diodeNetworkCommand(uplink)+"; "+GCSRelayCommand() {
				t.Fatal("owned bootstrap did not use the shared relay after network setup")
			}
		} else if command != diodeNetworkCommand(uplink) {
			t.Fatal("default bootstrap changed or launched a relay")
		}
	}
}

func TestPairGCSRelayReadiness(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell unavailable")
	}
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprint(ready), func(t *testing.T) {
			mock := `echo 'synthetic relay startup failure'; return 7`
			if ready {
				mock = `touch "$fixture/gcs-relay.ready"`
			}
			script := `fixture=$(mktemp -d); trap 'rm -f "$fixture/gcs-relay.ready" "$fixture/gcs-relay.pid" "$fixture/gcs-relay.log"; rmdir "$fixture"' EXIT; ` +
				`mock_gcs() { ` + mock + `; }; ` +
				strings.ReplaceAll(strings.ReplaceAll(GCSRelayCommand(), "/bin/gcs", "mock_gcs"), "/run/gcs-relay", "$fixture/gcs-relay")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, shell, "--exec", "/bin/sh", "-ec", script).CombinedOutput()
			if ready {
				if err != nil || !strings.Contains(string(output), "GCS_RELAY_READY") {
					t.Fatalf("relay readiness was not reported: %v %s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), "synthetic relay startup failure") {
				t.Fatalf("relay failure was not propagated: %v %s", err, output)
			}
		})
	}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestPairCloseIsOrderedAndIdempotentAfterFailures(t *testing.T) {
	var calls []string
	failure := errors.New("workload close error")
	pair := &Pair{
		interactiveCloser: closeFunc(func() error { calls = append(calls, "interactive"); return nil }),
		workloadCloser:    closeFunc(func() error { calls = append(calls, "workload"); return failure }),
		diodeCloser:       closeFunc(func() error { calls = append(calls, "diode"); return nil }),
		uplinkCleanup:     func() error { calls = append(calls, "uplink"); return nil },
		sectionCloser:     closeFunc(func() error { calls = append(calls, "section"); return nil }),
	}
	for range 2 {
		if err := pair.Close(); !errors.Is(err, failure) {
			t.Fatalf("lost close error: %v", err)
		}
	}
	if !reflect.DeepEqual(calls, []string{"interactive", "workload", "diode", "uplink", "section"}) {
		t.Fatalf("invalid provider/consumer lifetime: %v", calls)
	}
}

func TestPairBootstrapShellSyntax(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell unavailable")
	}
	resolve, err := RPDeviceCommand(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		diodeNetworkCommand(&Uplink{Address: "172.31.250.2/24", Gateway: UplinkGateway}),
		diodeBootstrapCommand(&Uplink{Address: "172.31.250.2/24", Gateway: UplinkGateway}, true),
		demoToolsStage + workloadNICCommand(),
		workloadNICCommand(),
		resolve + `printf '%s\n' "1 0 42 $storage_dev" >` + exportParameters + "export_add",
	} {
		if out, err := exec.Command(shell, "--exec", "/bin/sh", "-n", "-c", script).CombinedOutput(); err != nil {
			t.Fatalf("invalid guest bootstrap syntax: %v\n%s\n%s", err, out, script)
		}
	}

	t.Run("PeerNetworkDiscovery", func(t *testing.T) {
		shell, err := exec.LookPath("wsl.exe")
		if err != nil {
			t.Skip("WSL shell unavailable")
		}
		for _, test := range []struct {
			name     string
			instance string
			device   string
			driver   string
			nics     string
			wantErr  bool
		}{
			{"stock-peer", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", false},
			{"direct-RP", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "root-rp-guid", "hv_netvsc", "peer", true},
			{"other-bus", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus2-relid2", "hv_netvsc", "peer", true},
			{"custom-driver", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "diode_netvsc", "peer", true},
			{"multiple-NICs", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer extra", true},
			{"old-transport", "bus_id=1 local_cid=3 peer_cid=4 version=3 ready=1", "bus1-relid2", "hv_netvsc", "peer", true},
			{"wrong-role", "bus_id=1 local_cid=4 peer_cid=3 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", true},
		} {
			t.Run(test.name, func(t *testing.T) {
				script := strings.Replace(workloadNICCommand(),
					BusLoadCommand("/run/sibling/sibling_bus.ko/sibling_bus.ko"), "", 1)
				script = strings.ReplaceAll(script, "/sys/class/net/*", test.nics)
				script = strings.ReplaceAll(script, `[ -e "$p/device" ]`, "true")
				fixture := `grep() { return 0; }; cat() { printf '%s\n' ` + Quote(test.instance) + `; }; ` +
					`readlink() { case "$*" in *driver) printf '%s\n' /drivers/` + test.driver + `;; ` +
					`*) printf '%s\n' /devices/` + test.device + `;; esac; }; `
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				output, err := exec.CommandContext(ctx, shell, "--exec", "/bin/sh", "-ec", fixture+script).CombinedOutput()
				if (err != nil) != test.wantErr {
					t.Fatalf("NIC bootstrap=%v expectedFailure=%v output=%s", err, test.wantErr, output)
				}
				if !test.wantErr && strings.TrimSpace(string(output)) != test.device {
					t.Fatalf("wrong discovered peer identity: %q", output)
				}
			})
		}
	})
}
