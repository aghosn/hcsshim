//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli"
)

type pageMetadataTestShare struct {
	fail bool
	path string
}

func (s *pageMetadataTestShare) Share(_ context.Context, host, _ string, readOnly bool) error {
	if !readOnly {
		s.path = host
		if s.fail {
			return errors.New("fixture export failure")
		}
	}
	return nil
}

func TestPageMetadataRequestedShareFailureAndRoleIsolation(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct {
		role string
		name string
		fail bool
	}{
		{diodeRole, "diode", false},
		{workloadRole, "workload", false},
		{workloadRole, "workload", true},
	} {
		local := flag.NewFlagSet("lcow", flag.ContinueOnError)
		local.String(pageMetadataOutputArgName, root, "")
		local.String(siblingBusGuestModuleArgName, "sibling_bus.ko", "")
		c := cli.NewContext(nil, local, nil)
		share := &pageMetadataTestShare{fail: test.fail}
		stage, err := stagePageMetadata(context.Background(), c, share, test.role)
		if (err != nil) != test.fail || share.path != filepath.Join(root, test.name) {
			t.Fatalf("incorrect export role/failure: %q %v", share.path, err)
		}
		if test.fail && stage != "" {
			t.Fatal("requested-share failure returned usable staging")
		}
	}
}

func TestPageMetadataOutputIsolatedAndPersistent(t *testing.T) {
	root := t.TempDir()
	first, err := newPageMetadataOutput(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newPageMetadataOutput(root)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || filepath.Dir(first) != root || filepath.Dir(second) != root {
		t.Fatal("runs are not isolated below the selected directory")
	}
	for _, role := range []string{"diode", "workload"} {
		path := filepath.Join(first, role)
		data, err := os.ReadFile(filepath.Join(path, "run.txt"))
		if err != nil || !strings.Contains(string(data), "role="+role+"\n") {
			t.Fatalf("missing role metadata: %s: %v", role, err)
		}
		if err := os.WriteFile(filepath.Join(path, "result.bin"), []byte{0, 255, 13, 10}, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(second, role, "result.bin")); !os.IsNotExist(err) {
			t.Fatal("second run reused earlier results")
		}
	}
}

func TestPageMetadataOutputRejectsInvalidRoots(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"", "relative", `\\server\share`, filepath.Join(root, "missing"), file} {
		if _, err := newPageMetadataOutput(path); err == nil {
			t.Fatalf("accepted invalid output %q", path)
		}
	}
}

// TestPageMetadataCLIOptInAndForwarding allows ordinary direct/relayed Linux
// diagnostics only on request, preserving isolated output and omission behavior.
func TestPageMetadataCLIOptInAndForwarding(t *testing.T) {
	previousGCS := useGCS
	useGCS = true
	defer func() { useGCS = previousGCS }()
	for _, test := range []struct {
		selected bool
		relay    bool
		wantFail bool
	}{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{true, true, false},
	} {
		root := t.TempDir()
		global := flag.NewFlagSet("global", flag.ContinueOnError)
		global.Int(countArgName, 2, "")
		global.Int(parallelArgName, 2, "")
		local := flag.NewFlagSet("lcow", flag.ContinueOnError)
		local.String(pageMetadataOutputArgName, "", "")
		local.Bool(siblingInteractiveArgName, true, "")
		local.Bool(siblingDiodeUplinkArgName, true, "")
		local.Bool(siblingGCSRelayArgName, test.relay, "")
		local.String(siblingBusGuestModuleArgName, "sibling_bus.ko", "")
		if test.selected {
			if err := local.Set(pageMetadataOutputArgName, root); err != nil {
				t.Fatal(err)
			}
		}
		c := cli.NewContext(nil, local, cli.NewContext(nil, global, nil))
		err := preparePageMetadataOutput(c)
		if (err != nil) != test.wantFail {
			t.Fatalf("selected=%t relay=%t: %v", test.selected, test.relay, err)
		}
		share := &pageMetadataTestShare{}
		if _, err := stagePageMetadata(context.Background(), c, share, diodeRole); err != nil {
			t.Fatal(err)
		}
		if !test.selected && share.path != "" {
			t.Fatal("omitted ordinary output created a writable share")
		}
		if test.selected && !test.wantFail {
			run := c.String(pageMetadataOutputArgName)
			if run == root || filepath.Dir(run) != root {
				t.Fatal("collector did not receive the isolated run directory")
			}
		} else if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
			t.Fatal("omitted or rejected option created output directories")
		}
	}
}

// TestPageMetadataProtectedRelay admits explicit output at both the diagnostic
// and protected-profile layers without native authority or simulated seals.
func TestPageMetadataProtectedRelay(t *testing.T) {
	previousGCS := useGCS
	useGCS = true
	// Restore the serial CLI fixture's process-wide GCS selection.
	defer func() { useGCS = previousGCS }()
	for _, selected := range []bool{false, true} {
		root := t.TempDir()
		args := protectedSiblingTestArgs(t, true)
		if selected {
			args = append(args, "--"+pageMetadataOutputArgName, root)
		}
		c := storageTestContext(t, args...)
		if err := preparePageMetadataOutput(c); err != nil {
			t.Fatal(err)
		}
		if _, err := preflightProtectedSiblingProfile(c); err != nil {
			t.Fatalf("diagnostic export changed protected admission: %v", err)
		}
		share := &pageMetadataTestShare{}
		if _, err := stagePageMetadata(context.Background(), c, share, workloadRole); err != nil {
			t.Fatal(err)
		}
		if selected {
			run := c.String(pageMetadataOutputArgName)
			if filepath.Dir(run) != root || share.path != filepath.Join(run, "workload") {
				t.Fatal("protected relay lost per-run/per-role export")
			}
		} else if share.path != "" {
			t.Fatal("omitted output created a writable share")
		}
	}
}

// TestPageMetadataUnsupportedProfiles keeps requested output out of appliances,
// OpenShell and benchmarks even when their other interactive settings match.
func TestPageMetadataUnsupportedProfiles(t *testing.T) {
	previousGCS := useGCS
	useGCS = true
	// Restore the serial CLI fixture's process-wide GCS selection.
	defer func() { useGCS = previousGCS }()
	for _, option := range []string{
		unikraftPackageArgName, siblingOpenShellBundleArgName,
		networkBenchmarkScriptArgName, storageBenchmarkScriptArgName,
	} {
		root := t.TempDir()
		c := storageTestContext(t, "--"+siblingInteractiveArgName, "--"+siblingDiodeUplinkArgName,
			"--"+siblingBusGuestModuleArgName, "sibling_bus.ko",
			"--"+pageMetadataOutputArgName, root, "--"+option, "fixture")
		if err := preparePageMetadataOutput(c); err == nil {
			t.Fatalf("accepted output for %s", option)
		}
		if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
			t.Fatal("rejected profile created output directories")
		}
	}
}
