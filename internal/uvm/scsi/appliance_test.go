//go:build windows

package scsi

import (
	"context"
	"errors"
	"testing"
)

type quiescenceTest struct {
	calls int
	err   error
}

func (q *quiescenceTest) Quiesce(_ context.Context, controller, lun uint) error {
	if controller != 0 || lun != 1 {
		return errors.New("quiesced wrong backing")
	}
	q.calls++
	return q.err
}

func TestApplianceSharedAttachmentWaitsForQuiescence(t *testing.T) {
	ctx := context.Background()
	host := &hostBackend{}
	control := &quiescenceTest{err: errors.New("root DMA remains owned")}
	guest, err := NewApplianceGuestBackend(control)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(host, guest, 1, 64, "/unused/%d",
		[]Slot{{LUN: 0}, {LUN: 3}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.AddVirtualDisk(ctx, "layer.vhd", true, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.AddVirtualDisk(ctx, "layer.vhd", true, "", "", nil)
	if err != nil || first.LUN() != 1 || second.LUN() != 1 || len(host.attachments) != 1 {
		t.Fatalf("boot reservation or sharing failed: %+v, %v", host.attachments, err)
	}
	if err := first.Release(ctx); err != nil || control.calls != 0 {
		t.Fatalf("quiesced a still-shared attachment: %v", err)
	}
	if err := second.Release(ctx); !errors.Is(err, control.err) || len(host.attachments) != 1 {
		t.Fatalf("detached root-owned backing: %v, %v", err, host.attachments)
	}
	if _, err := manager.AddVirtualDisk(ctx, "layer.vhd", true, "", "", nil); err == nil {
		t.Fatal("reused a backing awaiting removal")
	}
	control.err = nil
	if err := second.Release(ctx); err != nil || len(host.attachments) != 0 || control.calls != 2 {
		t.Fatalf("quiescence retry did not detach exactly once: %v, %v", err, host.attachments)
	}
	if err := guest.mount(ctx, 0, 1, "/container", &mountConfig{}); err == nil {
		t.Fatal("appliance accepted a filesystem mount")
	}
}
