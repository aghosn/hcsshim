//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/urfave/cli"
)

func storageTestPlan(t *testing.T) *siblingStoragePlan {
	t.Helper()
	dir := t.TempDir()
	disks := []siblingStorageDisk{
		{ID: "workload-root", Role: "root", HostPath: filepath.Join(dir, "root.vhd"), Access: "read-only"},
		{ID: "workload-data", Role: "data", HostPath: filepath.Join(dir, "data.vhdx"), Access: "read-write"},
	}
	for i := range disks {
		lun := uint8(i)
		disks[i].ExportLUN = &lun
		if err := os.WriteFile(disks[i].HostPath, []byte("attachment test fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return &siblingStoragePlan{Version: 1, Disks: disks}
}

func storagePlanJSON(t *testing.T, plan *siblingStoragePlan) string {
	t.Helper()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSiblingStoragePlanValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*siblingStoragePlan)
		want   string
	}{
		{"version", func(p *siblingStoragePlan) { p.Version = 0 }, "version 1"},
		{"empty", func(p *siblingStoragePlan) { p.Disks = nil }, "at least one disk"},
		{"id", func(p *siblingStoragePlan) { p.Disks[0].ID = "bad/id" }, "lowercase ASCII"},
		{"duplicate-id", func(p *siblingStoragePlan) { p.Disks[1].ID = p.Disks[0].ID }, "duplicate storage disk id"},
		{"role", func(p *siblingStoragePlan) { p.Disks[0].Role = "" }, "role must"},
		{"access", func(p *siblingStoragePlan) { p.Disks[1].Access = "" }, "access must"},
		{"writable-root", func(p *siblingStoragePlan) { p.Disks[0].Access = "read-write" }, "read-only dm-verity root"},
		{"two-roots", func(p *siblingStoragePlan) {
			p.Disks[1].Role, p.Disks[1].Access = "root", "read-only"
		}, "one read-only"},
		{"missing-lun", func(p *siblingStoragePlan) { p.Disks[0].ExportLUN = nil }, "export_lun is required"},
		{"unreachable-lun", func(p *siblingStoragePlan) { *p.Disks[0].ExportLUN = 255 }, "between 0 and 254"},
		{"too-many-disks", func(p *siblingStoragePlan) {
			p.Disks = append(p.Disks, make([]siblingStorageDisk, 15)...)
		}, "maximum 16"},
		{"duplicate-lun", func(p *siblingStoragePlan) { p.Disks[1].ExportLUN = p.Disks[0].ExportLUN }, "duplicate storage export LUN"},
		{"relative-path", func(p *siblingStoragePlan) { p.Disks[0].HostPath = "root.vhd" }, "must be absolute"},
		{"missing-file", func(p *siblingStoragePlan) { p.Disks[0].HostPath += ".missing.vhd" }, "inspect disk"},
		{"file-type", func(p *siblingStoragePlan) { p.Disks[0].HostPath += ".txt" }, "VHD or VHDX"},
		{"duplicate-path", func(p *siblingStoragePlan) { p.Disks[1].HostPath = p.Disks[0].HostPath }, "aliases"},
		{"case-alias", func(p *siblingStoragePlan) { p.Disks[1].HostPath = strings.ToUpper(p.Disks[0].HostPath) }, "aliases"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := storageTestPlan(t)
			tt.change(plan)
			_, err := decodeSiblingStoragePlan(strings.NewReader(storagePlanJSON(t, plan)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
	plan := storageTestPlan(t)
	decoded, err := decodeSiblingStoragePlan(strings.NewReader(storagePlanJSON(t, plan)))
	if err != nil || !reflect.DeepEqual(decoded, plan) {
		t.Fatalf("valid disk identities/access modes changed: %+v, %v", decoded, err)
	}
	for _, input := range []string{
		`null`, `{}`, `{"version":1,"disks":[]}`, `{"version":1,"typo":[]}`,
		storagePlanJSON(t, plan) + `{}`,
		storagePlanJSON(t, plan) + `garbage`,
		strings.Replace(storagePlanJSON(t, plan), `"export_lun":0`, `"export_lun":256`, 1),
		strings.Replace(storagePlanJSON(t, plan), `"access":`, `"typo":`, 1),
	} {
		if _, err := decodeSiblingStoragePlan(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted malformed plan: %s", input)
		}
	}
}

func TestSiblingStoragePlanRejectsDirectoryAndHardlink(t *testing.T) {
	plan := storageTestPlan(t)
	dir := filepath.Join(t.TempDir(), "directory.vhd")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	plan.Disks[1].HostPath = dir
	if _, err := decodeSiblingStoragePlan(strings.NewReader(storagePlanJSON(t, plan))); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("accepted a directory: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "alias.vhd")
	if err := os.Link(plan.Disks[0].HostPath, alias); err != nil {
		t.Fatal(err)
	}
	plan.Disks[1].HostPath = alias
	if _, err := decodeSiblingStoragePlan(strings.NewReader(storagePlanJSON(t, plan))); err == nil ||
		!strings.Contains(err.Error(), "aliases") {
		t.Fatalf("accepted an aliased backing file: %v", err)
	}
}

func storageTestContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	global := flag.NewFlagSet("global", flag.ContinueOnError)
	global.Int(countArgName, 2, "")
	global.Int(parallelArgName, 2, "")
	parent := cli.NewContext(cli.NewApp(), global, nil)
	set := flag.NewFlagSet("lcow", flag.ContinueOnError)
	for _, f := range lcowCommand.Flags {
		f.Apply(set)
	}
	if set.Lookup("unikraft-diode-package") == nil {
		set.String("unikraft-diode-package", "", "")
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return cli.NewContext(cli.NewApp(), set, parent)
}

func TestSiblingStorageCLIRejectsInvalidModesBeforeHostWork(t *testing.T) {
	oldGCS := useGCS
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = true
	plan := storageTestPlan(t)
	path := filepath.Join(t.TempDir(), "backends.json")
	if err := os.WriteFile(path, []byte(storagePlanJSON(t, plan)), 0600); err != nil {
		t.Fatal(err)
	}
	valid := []string{"--" + siblingStorageBackendsArgName, path,
		"--" + sharedMemoryTwoUVMArgName, "--" + siblingBusGuestModuleArgName, "sibling_bus.ko"}
	if loaded, err := loadSiblingStoragePlan(storageTestContext(t, valid...)); err != nil || loaded == nil {
		t.Fatalf("valid backend plan: %+v, %v", loaded, err)
	}
	for _, args := range [][]string{
		{"--" + siblingStorageBackendsArgName, ""},
		{"--" + siblingStorageBackendsArgName, path},
		append(append([]string{}, valid...), "--"+scsiMountsArgName, "extra.vhd"),
		append(append([]string{}, valid...), "--"+vpmemMountsArgName, "extra.vhd"),
		append(append([]string{}, valid...), "--"+sharedMemoryMappingOnlyArgName),
		append(append([]string{}, valid...), "--"+sharedMemoryGuestInventoryArgName),
		append(append([]string{}, valid...), "--unikraft-diode-package", "optional-package"),
	} {
		if _, err := loadSiblingStoragePlan(storageTestContext(t, args...)); err == nil {
			t.Fatalf("accepted invalid backend configuration: %v", args)
		}
	}
	wrongCount := storageTestContext(t, valid...)
	if err := wrongCount.GlobalSet(countArgName, "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSiblingStoragePlan(wrongCount); err == nil {
		t.Fatal("accepted a one-VM backend setup")
	}
	useGCS = false
	if _, err := loadSiblingStoragePlan(storageTestContext(t, valid...)); err == nil {
		t.Fatal("accepted backend preparation without GCS")
	}
	if loaded, err := loadSiblingStoragePlan(storageTestContext(t)); err != nil || loaded != nil {
		t.Fatalf("changed default without backend option: %+v, %v", loaded, err)
	}
}

func TestSiblingStorageValidateOnlyDoesNotStartVMs(t *testing.T) {
	oldGCS := useGCS
	t.Cleanup(func() { useGCS = oldGCS })
	useGCS = false
	path := filepath.Join(t.TempDir(), "backends.json")
	if err := os.WriteFile(path, []byte(storagePlanJSON(t, storageTestPlan(t))), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := storageTestContext(t, "--"+siblingStorageBackendsArgName, path, "--"+validateStorageBackendsArgName)
	if err := lcowCommand.Action.(func(*cli.Context) error)(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSiblingStoragePlan(storageTestContext(t, "--"+validateStorageBackendsArgName)); err == nil {
		t.Fatal("accepted validation without a plan")
	}
}

func TestSiblingStorageBackendsAttachOnlyToDiode(t *testing.T) {
	plan := storageTestPlan(t)
	calls := []string{}
	released := []string{}
	attach := func(_ context.Context, disk siblingStorageDisk) (siblingStorageAttachment, error) {
		calls = append(calls, disk.ID)
		return siblingStorageAttachment{
			controller: 0, lun: uint(len(calls)),
			release: func(ctx context.Context) error {
				if ctx.Err() != nil {
					t.Fatal("cleanup inherited canceled context")
				}

				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("cleanup has no deadline")
				}
				released = append(released, disk.ID)
				return nil
			},
		}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	backends, err := prepareSiblingStorageBackends(ctx, "uvmboot-1", plan, attach)
	if err != nil || len(calls) != 0 || len(backends.reports) != 0 {
		t.Fatalf("workload received backend disks: %+v, %v", calls, err)
	}
	if _, err := prepareSiblingStorageBackends(ctx, "uvmboot-0", nil, attach); err != nil || len(calls) != 0 {
		t.Fatalf("default received backend disks: %+v, %v", calls, err)
	}
	if _, err := prepareSiblingStorageBackends(ctx, "unknown", plan, attach); err == nil {
		t.Fatal("accepted unknown VM role")
	}
	backends, err = prepareSiblingStorageBackends(ctx, "uvmboot-0", plan, attach)
	if err != nil {
		t.Fatal(err)
	}
	for i, report := range backends.reports {
		disk := plan.Disks[i]
		if report.DiskID != disk.ID || report.HostPath != disk.HostPath ||
			report.Role != disk.Role || report.ReadOnly != (disk.Access == "read-only") ||
			report.ExportLUN != *disk.ExportLUN || report.DiodeVM != "uvmboot-0" ||
			report.WorkloadVM != "uvmboot-1" || report.LUN != uint(i+1) ||
			report.ControllerID == "" || report.State != "attached-only" {
			t.Fatalf("incorrect backend identity/report: %+v", report)
		}
	}
	if len(backends.reports) != 2 {
		t.Fatal("missing backend mappings")
	}
	cancel()
	if err := backends.close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := backends.close(ctx); err != nil ||
		!reflect.DeepEqual(released, []string{"workload-data", "workload-root"}) {
		t.Fatalf("cleanup must be reverse-order and once-only: %v, %v", released, err)
	}
}

func TestSiblingStorageBackendFailureRollsBackAndReportsCleanup(t *testing.T) {
	plan := storageTestPlan(t)
	attachErr, releaseErr := errors.New("attach failed"), errors.New("release failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, releases := 0, 0
	_, err := prepareSiblingStorageBackends(ctx, "uvmboot-0", plan,
		func(_ context.Context, _ siblingStorageDisk) (siblingStorageAttachment, error) {
			calls++
			if calls == 2 {
				cancel()
				return siblingStorageAttachment{}, attachErr
			}
			return siblingStorageAttachment{controller: 0, lun: 1,
				release: func(ctx context.Context) error {
					releases++
					if ctx.Err() != nil {
						t.Fatal("rollback inherited canceled context")
					}
					return releaseErr
				}}, nil
		})
	if !errors.Is(err, attachErr) || !errors.Is(err, releaseErr) || releases != 1 {
		t.Fatalf("lost attachment/rollback failure: %v; releases=%d", err, releases)
	}
}

func TestSiblingStorageBackendsRejectDuplicateSlots(t *testing.T) {
	releases := 0
	_, err := prepareSiblingStorageBackends(context.Background(), "uvmboot-0", storageTestPlan(t),
		func(context.Context, siblingStorageDisk) (siblingStorageAttachment, error) {
			return siblingStorageAttachment{controller: 0, lun: 1,
				release: func(context.Context) error { releases++; return nil }}, nil
		})
	if err == nil || !strings.Contains(err.Error(), "duplicate") || releases != 2 {
		t.Fatalf("accepted duplicate attachment slot or leaked handles: %v; releases=%d", err, releases)
	}
}

func TestSiblingStorageGuestCommandsPreserveDiskIdentity(t *testing.T) {
	plan := storageTestPlan(t)
	reports := []siblingStorageBackendReport{
		{DiskID: "workload-root", ControllerID: "controller-a", LUN: 3, ExportLUN: 0, ReadOnly: true},
		{DiskID: "workload-data", ControllerID: "controller-b", LUN: 7, ExportLUN: 1},
	}
	diode, err := siblingStorageGuestCommand("/run/provider.ko", diodeRole, plan, reports)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"*/controller-a/host*/target*/*:0:0:3)", "*/controller-b/host*/target*/*:0:0:7)",
		`"backends=$storage_backends"`, "'luns=0,1'", "'read_only=true,false'",
		`[ "$storage_count" -eq 1 ] && [ -b "$storage_dev" ]`, "insmod '/run/provider.ko'",
	} {
		if !strings.Contains(diode, expected) {
			t.Errorf("diode mapping missing %q: %s", expected, diode)
		}
	}
	workload, err := siblingStorageGuestCommand("", workloadRole, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`*/bus"${sb_bus}"-relid*/host*/target*/*:0:0:0)`,
		`*/bus"${sb_bus}"-relid*/host*/target*/*:0:0:1)`,
		`/run/diode-storage/workload-root`, `/run/diode-storage/workload-data`,
		`'read-only'`, `'read-write'`,
	} {
		if !strings.Contains(workload, expected) {
			t.Errorf("workload mapping missing %q: %s", expected, workload)
		}
	}
	if strings.Contains(workload, "insmod") || strings.Contains(workload, "dd ") ||
		strings.Contains(diode, "/dev/sda") || strings.Contains(workload, "/dev/sda") {
		t.Fatal("startup writes disks or assumes disk enumeration order")
	}
	if _, err := siblingStorageGuestCommand("", diodeRole, plan, reports[:1]); err == nil {
		t.Fatal("accepted incomplete backend mappings")
	}
	if _, err := siblingStorageGuestCommand("", "unknown", plan, nil); err == nil {
		t.Fatal("accepted an unknown storage role")
	}
	if command, err := siblingStorageGuestCommand("", diodeRole, nil, nil); command != "" || err != nil {
		t.Fatalf("storage changed default startup: %q, %v", command, err)
	}
}
