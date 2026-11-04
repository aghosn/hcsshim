//go:build windows

package uvm

import (
	"context"
	"errors"
	"testing"

	hcs "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
)

func TestSiblingNetworkNamespaceOwnership(t *testing.T) {
	var added, removed int
	failRemove := true
	setup := &siblingNetworkSetup{
		adapter: guestresource.LCOWNetworkAdapter{ID: "bus1-relid2-00000001-0000-0000-0000-000000000000"},
		add: func(_ context.Context, adapter *guestresource.LCOWNetworkAdapter) error {
			added++
			if adapter.NamespaceID != "sandbox" || adapter.ID != "bus1-relid2-00000001-0000-0000-0000-000000000000" {
				t.Fatalf("unexpected guest-only adapter: %+v", adapter)
			}
			return nil
		},
		remove: func(_ context.Context, adapter *guestresource.LCOWNetworkAdapter) error {
			removed++
			if failRemove {
				return errors.New("GCS unavailable")
			}
			return nil
		},
	}
	ctx := context.Background()
	for range 2 {
		if err := setup.ConfigureNetworking(ctx, "sandbox", NetworkRequestSetup); err != nil {
			t.Fatal(err)
		}
	}
	if added != 1 {
		t.Fatal("duplicate guest NIC registration")
	}
	if err := setup.ConfigureNetworking(ctx, "other", NetworkRequestSetup); err == nil {
		t.Fatal("allowed another sandbox to claim the peer NIC")
	}
	if err := setup.ConfigureNetworking(ctx, "other", NetworkRequestTearDown); err == nil {
		t.Fatal("allowed another sandbox to remove the peer NIC")
	}
	if err := setup.ConfigureNetworking(ctx, "sandbox", NetworkRequestTearDown); err == nil || setup.namespace == "" {
		t.Fatal("failed teardown lost ownership")
	}
	failRemove = false
	for range 2 {
		if err := setup.ConfigureNetworking(ctx, "sandbox", NetworkRequestTearDown); err != nil {
			t.Fatal(err)
		}
	}
	if removed != 2 || setup.namespace != "" {
		t.Fatal("teardown was not retryable and idempotent")
	}
}

func TestSiblingNetworkFailureNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	failure := errors.New("guest failure")
	setup := &siblingNetworkSetup{add: func(context.Context, *guestresource.LCOWNetworkAdapter) error { return failure }}
	vm := &UtilityVM{operatingSystem: "linux", hcsSystem: &hcs.System{}, networkSetup: setup}
	if err := vm.ConfigureNetworking(ctx, "sandbox"); !errors.Is(err, failure) || errors.Is(err, ErrNoNetworkSetup) {
		t.Fatalf("failed GCS setup permitted HNS fallback: %v", err)
	}
	if err := vm.CreateAndAssignNetworkSetup(ctx, "", ""); err == nil {
		t.Fatal("replaced diode-only setup with standard HNS")
	}
	if err := vm.addNIC(ctx, "direct", nil); err == nil {
		t.Fatal("attached an RP NIC to the workload")
	}
	if vm.networkSetup != setup {
		t.Fatal("lost fail-closed networking marker")
	}
	for _, id := range []string{"", "some-guid", "../bus1-relid2", "bus0-relid1", "bus1-relid0", "bus1-relid2",
		"bus1-relid2-not-a-guid", "bus0-relid2-00000001-0000-0000-0000-000000000000"} {
		fresh := &UtilityVM{operatingSystem: "linux"}
		if err := fresh.ConfigureSiblingNetworking(guestresource.LCOWNetworkAdapter{ID: id}); err == nil {
			t.Fatalf("accepted non-peer NIC identity %q", id)
		}
	}
	fresh := &UtilityVM{operatingSystem: "linux"}
	if err := fresh.ConfigureSiblingNetworking(guestresource.LCOWNetworkAdapter{
		ID: "bus1-relid2-00000001-0000-0000-0000-000000000000",
	}); err != nil {
		t.Fatalf("rejected canonical kernel peer device name: %v", err)
	}
}
