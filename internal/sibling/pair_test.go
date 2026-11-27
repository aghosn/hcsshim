//go:build windows

package sibling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// workloadVmbusNoRpConfigFixture selects the protected owned Linux profile
// without acquiring backing or starting either participant.
func workloadVmbusNoRpConfigFixture() *Config {
	config := testConfig()
	config.ProtectedShared, config.MediateGCS, config.Interactive = true, true, true
	config.WorkloadVmbusNoRp = true
	config.SharedMemoryBytes = 32 << 20
	config.RunID = "no-rp-fixture"
	config.CleanupReceiptPath = `C:\session\protected-cleanup-result.json`
	return config
}

// TestWorkloadVmbusNoRpRoleIsolation proves only an explicit workload request
// reaches its clone, without leaking into base/diode or breaking pre-acquisition
// VerifyOptions. Image names do not select the mode.
func TestWorkloadVmbusNoRpRoleIsolation(t *testing.T) {
	for _, selected := range []bool{false, true} {
		base := testOptions()
		config := workloadVmbusNoRpConfigFixture()
		config.WorkloadVmbusNoRp = selected
		config.WorkloadGuestStateFile = "unrelated-name.vmgs"
		workload, diode, err := commonPairOptions(base, config, "group")
		if err != nil {
			t.Fatal(err)
		}
		if workload.WorkloadVmbusNoRp != selected || diode.WorkloadVmbusNoRp || base.WorkloadVmbusNoRp {
			t.Fatal("native opt-in escaped the selected workload clone")
		}
		for _, options := range []*uvm.OptionsLCOW{workload, diode} {
			if err := uvm.VerifyOptions(context.Background(), options); err != nil {
				t.Fatalf("pre-acquisition validation demanded final resources: %v", err)
			}
			if len(options.SharedMemoryRegions) != 0 || len(options.ProtectedSharedResources) != 0 {
				t.Fatal("role selection acquired backing")
			}
		}
		workload.WorkloadVmbusNoRp = !selected
		workload.SiblingCommunicationEndpoints[0].SharedMemorySectionName = "changed"
		workload.SecurityPolicy = "changed"
		if diode.WorkloadVmbusNoRp || base.WorkloadVmbusNoRp ||
			diode.SiblingCommunicationEndpoints[0].SharedMemorySectionName != "" ||
			len(base.SiblingCommunicationEndpoints) != 0 ||
			diode.SecurityPolicy != base.SecurityPolicy {
			t.Fatal("workload mutation changed base/diode options")
		}
	}
}

// TestWorkloadVmbusNoRpConfig checks strict optional boolean decoding and rejects
// incompatible true selections through both JSON and direct Config construction.
// Invalid requests must fail before pair backing or native VM acquisition.
func TestWorkloadVmbusNoRpConfig(t *testing.T) {
	for _, fields := range []string{"", `,"workload_vmbus_no_rp":false`} {
		data, _ := json.Marshal(testConfig())
		text := strings.TrimSuffix(string(data), "}") + fields + "}"
		config, err := decodeConfig(strings.NewReader(text))
		if err != nil || config.WorkloadVmbusNoRp {
			t.Fatalf("omitted/false mode changed: %+v %v", config, err)
		}
	}
	data, _ := json.Marshal(workloadVmbusNoRpConfigFixture())
	if config, err := decodeConfig(strings.NewReader(string(data))); err != nil || !config.WorkloadVmbusNoRp {
		t.Fatalf("selected config rejected: %+v %v", config, err)
	}
	for _, fields := range []string{
		`,"workload_vmbus_no_rp":false`, `,"WORKLOAD_VMBUS_NO_RP":true`,
	} {
		if _, err := decodeConfig(strings.NewReader(strings.TrimSuffix(string(data), "}") + fields + "}")); err == nil {
			t.Fatal("accepted duplicate native selection")
		}
	}
	for _, value := range []string{`null`, `"true"`, `1`, `{}`, `[]`} {
		text := strings.Replace(string(data), `"workload_vmbus_no_rp":true`, `"workload_vmbus_no_rp":`+value, 1)
		if _, err := decodeConfig(strings.NewReader(text)); err == nil {
			t.Fatalf("accepted non-boolean %s", value)
		}
	}
	for name, change := range map[string]func(*Config){
		"ordinary":   func(c *Config) { c.ProtectedShared = false },
		"direct-gcs": func(c *Config) { c.MediateGCS = false },
		"unowned":    func(c *Config) { c.Interactive = false },
		"size":       func(c *Config) { c.SharedMemoryBytes = 16 << 20 },
	} {
		t.Run(name, func(t *testing.T) {
			config := workloadVmbusNoRpConfigFixture()
			change(config)
			data, _ := json.Marshal(config)
			if _, err := decodeConfig(strings.NewReader(string(data))); err == nil {
				t.Fatal("decoded incompatible true selection")
			}
			if _, _, err := commonPairOptions(testOptions(), config, "group"); err == nil {
				t.Fatal("direct Config bypassed selection scope")
			}
		})
	}
}

// TestProtectedSharedOwnedUnikraftSelection checks that only an explicit
// protected mediated probe selects the appliance without weakening its Linux
// workload. Unsupported options must fail before entering the protected owner.
func TestProtectedSharedOwnedUnikraftSelection(t *testing.T) {
	config := workloadVmbusNoRpConfigFixture()
	config.UnikraftPackage = `C:\unikraft`
	selected, err := config.validatedCopy()
	if err != nil {
		t.Fatal(err)
	}
	base := testOptions()
	workload, diode, err := commonPairOptions(base, selected, "group")
	if err != nil {
		t.Fatal(err)
	}
	if !workload.WorkloadVmbusNoRp || !workload.SiblingRoot || !workload.DmVerityMode ||
		!workload.SecurityPolicyEnabled || workload.Appliance != nil || diode.WorkloadVmbusNoRp || base.WorkloadVmbusNoRp {
		t.Fatal("protected appliance selection changed workload hardening or leaked no-RP")
	}
	base.Appliance = &uvm.LCOWApplianceOptions{}
	if _, _, err := commonPairOptions(base, selected, "group"); err == nil {
		t.Fatal("protected workload inherited appliance boot")
	}
	zero := uint64(0)
	for name, change := range map[string]func(*Config){
		"no-rp-off":     func(c *Config) { c.WorkloadVmbusNoRp = false },
		"unowned":       func(c *Config) { c.Interactive = false },
		"standalone":    func(c *Config) { c.Standalone = true },
		"direct-gcs":    func(c *Config) { c.MediateGCS = false },
		"storage-io":    func(c *Config) { c.StorageDirectIO = true },
		"page-export":   func(c *Config) { c.PageMetadataOutputPath = `C:\export` },
		"diode-mask":    func(c *Config) { c.DiodePartitionSealMask = &zero },
		"workload-mask": func(c *Config) { c.WorkloadPartitionSealMask = &zero },
	} {
		bad := *config
		change(&bad)
		if _, err := bad.validatedCopy(); err == nil {
			t.Errorf("%s: accepted excluded protected appliance selection", name)
		}
	}
	data, _ := json.Marshal(config)
	if _, err := decodeConfig(strings.NewReader(strings.TrimSuffix(string(data), "}") + `,"diode_snp_transport":true}`)); err == nil {
		t.Fatal("accepted a diode SNP transport override")
	}
}

// TestWorkloadVmbusNoRpRejectsInherited rejects native selection in base options
// even when pair selection is off, preventing accidental diode/global activation.
func TestWorkloadVmbusNoRpRejectsInherited(t *testing.T) {
	for _, selected := range []bool{false, true} {
		base := testOptions()
		base.WorkloadVmbusNoRp = true
		config := workloadVmbusNoRpConfigFixture()
		config.WorkloadVmbusNoRp = selected
		if _, _, err := commonPairOptions(base, config, "group"); err == nil {
			t.Fatal("inherited native opt-in accepted")
		}
	}
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
	directory := t.TempDir()
	path := filepath.Join(directory, "sibling-pair.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.directory != directory {
		t.Fatalf("console directory does not follow the retained config: %q", config.directory)
	}
	config.directory = ""
	if !reflect.DeepEqual(config, testConfig()) {
		t.Fatalf("loading the config changed its VM settings: %+v", config)
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
		{`,"storage_direct_io":true,"published_tcp_ports":[11211],"vm_resources":[{"processor_count":1,"memory_mb":512},{"processor_count":4,"memory_mb":2048}]`, nil, nil, false},
		{`,"standalone":true`, nil, nil, true},
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

func TestPairStorageDirectIOOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		config := testConfig()
		config.StorageDirectIO = enabled
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeConfig(strings.NewReader(string(data)))
		if err != nil || decoded.StorageDirectIO != enabled {
			t.Fatalf("direct I/O opt-in did not survive decoding: %+v %v", decoded, err)
		}
	}
	for _, config := range []*Config{
		{Version: 1, Standalone: true, StorageDirectIO: true},
		{Version: 1, ModuleDirectory: `C:\modules`, SharedMemoryBytes: 32 << 20,
			WorkloadGuestStateFile: "sibling-root.vmgs", UnikraftPackage: `C:\unikraft`, StorageDirectIO: true},
	} {
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeConfig(strings.NewReader(string(data))); err == nil {
			t.Fatalf("accepted Linux provider setting for another backend: %s", data)
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
				mock = `touch "$fixture/gcs-relay.ready"; exec /bin/sleep 1`
			}
			command := strings.ReplaceAll(GCSRelayCommand(),
				"/sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance", `"$fixture/sibling_instance"`)
			script := `fixture=$(mktemp -d); relay_pid=; trap 'rc=$?; trap - EXIT; ` +
				`if [ -n "$relay_pid" ]; then kill "$relay_pid" 2>/dev/null || :; wait "$relay_pid" 2>/dev/null || :; fi; ` +
				`rm -f "$fixture/sibling_instance" "$fixture/gcs-relay.ready" "$fixture/gcs-relay.pid" "$fixture/gcs-relay.log"; rmdir "$fixture"; exit "$rc"' EXIT; ` +
				`printf '%s\n' 'bus_id=1 local_cid=4 peer_cid=3 version=4 ready=1' >"$fixture/sibling_instance"; ` +
				`mock_gcs() { ` + mock + `; }; ` +
				strings.ReplaceAll(strings.ReplaceAll(command, "/bin/gcs", "mock_gcs"), "/run/gcs-relay", "$fixture/gcs-relay")
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

func TestGCSRelayWaitsForSiblingInstanceBeforeBinding(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Skip("WSL shell unavailable")
	}
	for _, test := range []struct {
		name, mode, instance, wantError string
	}{
		{"delayed-offer-and-enumeration", "delayed", "bus_id=1 local_cid=4 peer_cid=3 version=4", ""},
		{"missing-bus", "missing", "", "Timed out waiting for ready sibling bus"},
		{"wrong-role", "ready", "bus_id=1 local_cid=3 peer_cid=4 version=4", "Invalid sibling bus identity"},
		{"old-protocol", "ready", "bus_id=1 local_cid=4 peer_cid=3 version=3", "Invalid sibling bus identity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := strings.ReplaceAll(GCSRelayCommand(),
				"/sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance", `"$fixture"/*/sibling_instance`)
			script = strings.ReplaceAll(script, "/run/gcs-relay", "$fixture/relay")
			script = strings.ReplaceAll(script, "/bin/gcs", "fixture_gcs")
			fixture := `fixture=$(mktemp -d); relay_pid=; sleeps=0; ` +
				`trap 'rc=$?; trap - EXIT; if [ -n "$relay_pid" ]; then kill "$relay_pid" 2>/dev/null || :; wait "$relay_pid" 2>/dev/null || :; fi; ` +
				`if [ -f "$fixture/launched" ]; then echo RELAY_INVOKED; fi; ` +
				`rm -f "$fixture/bus-1/sibling_instance" "$fixture/relay.ready" "$fixture/relay.log" "$fixture/relay.pid" "$fixture/launched"; ` +
				`rmdir "$fixture/bus-1" 2>/dev/null || :; rmdir "$fixture"; exit "$rc"' EXIT; ` +
				`mode=` + Quote(test.mode) + `; instance=` + Quote(test.instance) + `; ` +
				`publish() { mkdir -p "$fixture/bus-1"; printf '%s ready=%s\n' "$instance" "$1" >"$fixture/bus-1/sibling_instance"; }; ` +
				`if [ "$mode" = ready ]; then publish 1; fi; ` +
				`sleep() { sleeps=$((sleeps+1)); if [ "$mode" = delayed ]; then ` +
				`if [ "$sleeps" -eq 1 ]; then publish 0; elif [ "$sleeps" -eq 2 ]; then publish 1; fi; ` +
				`if [ "$sleeps" -ge 2 ]; then /bin/sleep 0.01; fi; fi; }; ` +
				`fixture_gcs() { grep -q 'ready=1' "$fixture/bus-1/sibling_instance" || return 99; ` +
				`echo launched >"$fixture/launched"; touch "$fixture/relay.ready"; exec /bin/sleep 1; }; `
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, shell, "--exec", "/bin/sh", "-ec",
				fixture+script+`; [ "$sleeps" -ge 2 ]`).CombinedOutput()
			if test.wantError == "" {
				if err != nil || !strings.Contains(string(output), "GCS_RELAY_READY:") ||
					!strings.Contains(string(output), "RELAY_INVOKED") {
					t.Fatalf("relay did not wait for delayed readiness: %v\n%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), test.wantError) ||
				strings.Contains(string(output), "RELAY_INVOKED") {
				t.Fatalf("unready or invalid bus reached relay bind: %v\n%s", err, output)
			}
		})
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
			mode     string
		}{
			{"stock-peer", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", false, ""},
			{"direct-RP", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "root-rp-guid", "hv_netvsc", "peer", true, ""},
			{"other-bus", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus2-relid2", "hv_netvsc", "peer", true, ""},
			{"custom-driver", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "diode_netvsc", "peer", true, ""},
			{"multiple-NICs", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer extra", true, ""},
			{"old-transport", "bus_id=1 local_cid=3 peer_cid=4 version=3 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, ""},
			{"wrong-role", "bus_id=1 local_cid=4 peer_cid=3 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, ""},
			{"ACPI-stock-peer", "bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", false, "Y"},
			{"ACPI-old-transport", "bus_id=1 local_cid=3 peer_cid=4 version=3 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, "Y"},
			{"ACPI-wrong-local", "bus_id=1 local_cid=4 peer_cid=4 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, "Y"},
			{"ACPI-wrong-peer", "bus_id=1 local_cid=3 peer_cid=3 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, "Y"},
			{"RP-wrong-peer", "bus_id=1 local_cid=3 peer_cid=3 version=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, "N"},
			{"RP-short-instance", "bus_id=1 local_cid=3 peer_cid=4 ready=1", "bus1-relid2", "hv_netvsc", "peer", true, "N"},
		} {
			t.Run(test.name, func(t *testing.T) {
				script := workloadNICDiscoveryCommand("", test.mode != "")
				script = strings.ReplaceAll(script, "/sys/class/net/*", test.nics)
				script = strings.ReplaceAll(script, `[ -e "$p/device" ]`, "true")
				script = strings.ReplaceAll(script, "/sys/module/hv_vmbus/parameters/no_rp", `"$fixture/missing-mode"`)
				script = strings.ReplaceAll(script, "/sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance", `"$fixture/link-1/sibling_instance"`)
				script = strings.ReplaceAll(script, "/sys/devices/sibling_bus_acpi/sibling_instance", `"$fixture/link-1/sibling_instance"`)
				fixture := `fixture=$(mktemp -d); trap 'rm -rf "$fixture"' EXIT; mkdir -p "$fixture/link-1"; ` +
					`printf '%s\n' ` + Quote(test.instance) + ` >"$fixture/link-1/sibling_instance"; ` +
					`readlink() { case "$*" in *driver) printf '%s\n' /drivers/` + test.driver + `;; ` +
					`*) printf '%s\n' /devices/` + test.device + `;; esac; }; `
				if test.mode != "" {
					fixture += `echo ` + Quote(test.mode) + ` >"$fixture/missing-mode"; `
				}
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

// TestSiblingModeOwnerAndLoading runs the production shell against both owners.
// It protects strict mode selection, legacy compatibility, readiness, consistent
// identity/statistics ownership and the prohibition on no-RP module loading.
func TestSiblingModeOwnerAndLoading(t *testing.T) {
	shell, err := exec.LookPath("wsl.exe")
	if err != nil {
		t.Fatal("WSL is required for mode-aware discovery fixtures")
	}
	for _, test := range []struct {
		name, mode, owner                                          string
		strict, missingACPI, unreadable, delayed, loadRP, multiple bool
		wantFail                                                   bool
	}{
		{name: "Y-both-owners", mode: "Y", owner: "acpi"},
		{name: "N-both-owners", mode: "N", owner: "rp/link-1"},
		{name: "Y-no-fallback", mode: "Y", missingACPI: true, wantFail: true},
		{name: "invalid", mode: "invalid", wantFail: true},
		{name: "empty", mode: "empty", wantFail: true},
		{name: "unreadable", mode: "Y", unreadable: true, wantFail: true},
		{name: "legacy", owner: "rp/link-1"},
		{name: "protected-missing", strict: true, wantFail: true},
		{name: "protected-Y", mode: "Y", owner: "acpi", strict: true},
		{name: "protected-N", mode: "N", owner: "rp/link-1", strict: true},
		{name: "Y-delayed-ready", mode: "Y", owner: "acpi", delayed: true},
		{name: "N-delayed-ready", mode: "N", owner: "rp/link-1", delayed: true},
		{name: "legacy-load", owner: "rp/link-1", loadRP: true},
		{name: "N-load", mode: "N", owner: "rp/link-1", loadRP: true},
		{name: "N-multiple", mode: "N", multiple: true, wantFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setup := `set -eu; fixture=$(mktemp -d); trap 'rm -rf "$fixture"' EXIT; ` +
				`mkdir -p "$fixture/rp/link-1" "$fixture/acpi"; ` +
				`printf '%s\n' 'bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1' >"$fixture/rp/link-1/sibling_instance"; ` +
				`printf '%s\n' 'bus_id=2 local_cid=3 peer_cid=4 version=4 ready=1' >"$fixture/acpi/sibling_instance"; ` +
				`echo rp >"$fixture/rp/link-1/sibling_stats"; echo acpi >"$fixture/acpi/sibling_stats"; loaded=0; polls=0; ` +
				`insmod() { loaded=$((loaded+1)); mkdir -p "$fixture/rp/link-1"; ` +
				`printf '%s\n' 'bus_id=1 local_cid=3 peer_cid=4 version=4 ready=1' >"$fixture/rp/link-1/sibling_instance"; ` +
				`echo rp >"$fixture/rp/link-1/sibling_stats"; }; ` +
				`sleep() { polls=$((polls+1)); [ "$polls" -le 2 ] || exit 1; ` +
				`sed -i 's/ready=0/ready=1/' "$fixture/acpi/sibling_instance" "$fixture/rp/link-1/sibling_instance"; }; `
			if test.mode != "" {
				mode := test.mode
				if mode == "empty" {
					mode = ""
				}
				setup += `printf '%s\n' ` + Quote(mode) + ` >"$fixture/mode"; `
			}
			if test.unreadable {
				// A directory exists and is readable but cannot be read as a
				// parameter; cat must fail instead of selecting legacy RP.
				setup += `rm "$fixture/mode"; mkdir "$fixture/mode"; `
			}
			if test.missingACPI {
				setup += `rm -rf "$fixture/acpi"; `
			}
			if test.loadRP {
				setup += `rm -rf "$fixture/rp"; `
			}
			if test.multiple {
				setup += `cp -r "$fixture/rp/link-1" "$fixture/rp/link-2"; `
			}
			if test.delayed {
				setup += `sed -i 's/ready=1/ready=0/' "$fixture/acpi/sibling_instance" "$fixture/rp/link-1/sibling_instance"; `
			}
			command := BusLoadCommand("/bus.ko") + `until ` + OwnerReadyCommand(test.strict) + `; do sleep 0.1; done; ` +
				`printf 'OWNER=%s STATS=%s LOADED=%s POLLS=%s\n' "${sb_owner#"$fixture/"}" "$(cat "$sb_owner/sibling_stats")" "$loaded" "$polls"`
			command = strings.ReplaceAll(command, "/sys/module/hv_vmbus/parameters/no_rp", `"$fixture/mode"`)
			command = strings.ReplaceAll(command, "/sys/devices/sibling_bus_acpi", `"$fixture/acpi"`)
			command = strings.ReplaceAll(command, "/sys/bus/vmbus/drivers/sibling_bus", `"$fixture/rp"`)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, shell, "--distribution", "Ubuntu", "--exec", "/bin/sh", "-c", setup+command).CombinedOutput()
			if (err != nil) != test.wantFail {
				t.Fatalf("discovery failure=%v want=%v:\n%s", err, test.wantFail, output)
			}
			if test.wantFail {
				if strings.Contains(string(output), "OWNER=") {
					t.Fatalf("failed mode published an owner:\n%s", output)
				}
				return
			}
			stats, loaded, polls := "rp", 0, 0
			if test.mode == "Y" {
				stats = "acpi"
			}
			if test.loadRP {
				loaded = 1
			}
			if test.delayed {
				polls = 1
			}
			want := fmt.Sprintf("OWNER=%s STATS=%s LOADED=%d POLLS=%d", test.owner, stats, loaded, polls)
			if !strings.Contains(string(output), want) {
				t.Fatalf("mode selected wrong owner/loading/readiness: want %q:\n%s", want, output)
			}
		})
	}
}
