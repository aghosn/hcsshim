//go:build windows

package scsi

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

type siblingControlTest struct {
	addErr, removeErr error
	adds, removes     int
	controller, lun   uint
	exportLUN         uint8
	token             uint64
	readOnly          bool
	events            *[]string
}

func (c *siblingControlTest) Add(_ context.Context, controller, lun uint, exportLUN uint8, token uint64, readOnly bool) error {
	c.adds++
	c.controller, c.lun, c.exportLUN, c.token, c.readOnly = controller, lun, exportLUN, token, readOnly
	*c.events = append(*c.events, "export")
	return c.addErr
}

func (c *siblingControlTest) Remove(_ context.Context, lun uint8, token uint64) error {
	if lun != c.exportLUN || token == 0 || token != c.token {
		return errors.New("wrong export identity")
	}
	c.removes++
	*c.events = append(*c.events, "withdraw")
	return c.removeErr
}

type siblingGuestTest struct {
	guestBackend
	events *[]string
}

func (g *siblingGuestTest) unplug(context.Context, uint, uint) error {
	*g.events = append(*g.events, "unplug")
	return nil
}

func siblingTestManager(t *testing.T) (*Manager, *hostBackend, *siblingControlTest, *[]string) {
	t.Helper()
	events := &[]string{}
	diodeHost := &hostBackend{}
	diode, err := NewManager(diodeHost, &guestBackend{}, 1, 64, "/diode/%d",
		[]Slot{{LUN: 0}, {LUN: 1}, {LUN: 2}, {LUN: 3}, {LUN: 4}})
	if err != nil {
		t.Fatal(err)
	}
	diode.grantVMAccess = func(_ context.Context, vmID, path string) error {
		if vmID != "diode-id" || path != "layer.vhd" {
			t.Fatalf("unexpected ACL grant %q %q", vmID, path)
		}
		*events = append(*events, "diode-acl")
		return nil
	}
	control := &siblingControlTest{events: events}
	backend, err := NewSiblingHostBackend(diode, "diode-id", control)
	if err != nil {
		t.Fatal(err)
	}
	workload, err := NewManager(&hostBackend{}, &guestBackend{}, 4, 64, "/workload/%d", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := workload.ConfigureSibling(backend, &siblingGuestTest{events: events}); err != nil {
		t.Fatal(err)
	}
	workload.grantVMAccess = func(context.Context, string, string) error {
		t.Fatal("granted backing-file access to workload")
		return nil
	}
	return workload, diodeHost, control, events
}

func TestSiblingStorageSharesReadOnlyLayer(t *testing.T) {
	mgr, diodeHost, control, events := siblingTestManager(t)
	ctx := context.Background()
	var mounts []*Mount
	for range 2 {
		mount, err := mgr.AddVirtualDisk(ctx, "layer.vhd", true, "workload-id", "", &MountConfig{Options: []string{"ro"}})
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, mount)
	}
	if len(diodeHost.attachments) != 1 || control.adds != 1 ||
		control.controller != 0 || control.lun != 5 || control.exportLUN != 1 ||
		!control.readOnly || control.token == 0 {
		t.Fatalf("incorrect mediated mapping: %+v, attachments=%v", control, diodeHost.attachments)
	}
	if err := mounts[0].Release(ctx); err != nil {
		t.Fatal(err)
	}
	if control.removes != 0 || len(diodeHost.attachments) != 1 {
		t.Fatal("removed a shared layer while still referenced")
	}
	if err := mounts[1].Release(ctx); err != nil {
		t.Fatal(err)
	}
	if len(diodeHost.attachments) != 0 || !reflect.DeepEqual(*events, []string{"diode-acl", "export", "withdraw", "unplug"}) {
		t.Fatalf("unexpected removal order: %v, attachments=%v", *events, diodeHost.attachments)
	}
	if err := mounts[1].Release(ctx); !errors.Is(err, ErrAlreadyReleased) {
		t.Fatalf("second release: %v", err)
	}
}

func TestSiblingReleaseRetainsBackingAndCanRetry(t *testing.T) {
	mgr, diodeHost, control, events := siblingTestManager(t)
	ctx := context.Background()
	mount, err := mgr.AddVirtualDisk(ctx, "layer.vhd", false, "workload-id", "", &MountConfig{Encrypted: true})
	if err != nil {
		t.Fatal(err)
	}
	control.removeErr = errors.New("provider still draining")
	if err := mount.Release(ctx); !errors.Is(err, control.removeErr) {
		t.Fatalf("release error: %v", err)
	}
	if len(diodeHost.attachments) != 1 || !reflect.DeepEqual(*events, []string{"diode-acl", "export", "withdraw"}) {
		t.Fatalf("released backing before withdrawal: %v", *events)
	}
	if _, err := mgr.AddVirtualDisk(ctx, "layer.vhd", false, "", "", nil); err == nil {
		t.Fatal("reused an attachment awaiting removal")
	}
	control.removeErr = nil
	if err := mount.Release(ctx); err != nil {
		t.Fatalf("retry release: %v", err)
	}
	if len(diodeHost.attachments) != 0 {
		t.Fatal("backing retained after successful retry")
	}
}

func TestSiblingFailedPublishRollback(t *testing.T) {
	for _, unresolved := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed withdrawal", true: "uncertain withdrawal"}[unresolved], func(t *testing.T) {
			mgr, diodeHost, control, _ := siblingTestManager(t)
			control.addErr = errors.New("publish reply lost")
			if unresolved {
				control.removeErr = errors.New("withdrawal unconfirmed")
			}
			_, err := mgr.AddVirtualDisk(context.Background(), "layer.vhd", true, "", "", nil)
			if !errors.Is(err, control.addErr) || control.removes != 1 {
				t.Fatalf("publish rollback: %v", err)
			}
			if unresolved {
				if len(diodeHost.attachments) != 1 || !errors.Is(err, control.removeErr) {
					t.Fatal("uncertain export lost its backing or error")
				}
				control.addErr = nil
				if _, err := mgr.AddVirtualDisk(context.Background(), "layer.vhd", true, "", "", nil); err == nil {
					t.Fatal("reused unresolved export slot")
				}
			} else if len(diodeHost.attachments) != 0 {
				t.Fatal("confirmed withdrawn export leaked its backing")
			}
		})
	}
}

func TestSiblingRequestsPreserveMountSettings(t *testing.T) {
	req, err := mountRequest(0, 7, "/layers/test", &mountConfig{
		readOnly: true, encrypted: true, options: []string{"ro"}, partition: 1,
	}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	original := req.Settings.(guestresource.LCOWMappedVirtualDisk)
	if original.Sibling {
		t.Fatal("ordinary LCOW request opted into sibling storage")
	}
	marked, err := siblingRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	want := original
	want.Sibling = true
	if !reflect.DeepEqual(marked.Settings, want) {
		t.Fatalf("changed mount settings: %#v", marked.Settings)
	}
	for _, settings := range []any{
		guestresource.LCOWMappedVirtualDisk{Lun: 0},
		guestresource.LCOWMappedVirtualDisk{Controller: 1, Lun: 7},
		guestresource.SCSIDevice{Lun: 0},
		guestresource.SCSIDevice{Controller: 1, Lun: 7},
		guestresource.LCOWMappedDirectory{},
	} {
		if _, err := siblingRequest(guestrequest.ModificationRequest{Settings: settings}); err == nil {
			t.Fatalf("accepted unsafe sibling request: %#v", settings)
		}
	}
	for _, makeRequest := range []func() (guestrequest.ModificationRequest, error){
		func() (guestrequest.ModificationRequest, error) {
			return unmountRequest(0, 7, "/layers/test", &mountConfig{readOnly: true}, "linux")
		},
		func() (guestrequest.ModificationRequest, error) { return unplugRequest(0, 7, "linux") },
	} {
		req, err := makeRequest()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := siblingRequest(req); err != nil {
			t.Fatal(err)
		}
	}
}
