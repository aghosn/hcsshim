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
				script = strings.ReplaceAll(script, "/sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance", `"$sb_fixture"`)
				script = strings.ReplaceAll(script, "/sys/class/net/*", test.nics)
				script = strings.ReplaceAll(script, `[ -e "$p/device" ]`, "true")
				fixture := `sb_fixture=$(mktemp); trap 'rm -f "$sb_fixture"' EXIT; ` +
					`printf '%s\n' ` + Quote(test.instance) + ` >"$sb_fixture"; ` +
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
