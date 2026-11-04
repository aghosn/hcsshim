//go:build linux

package hcsv2

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

func TestSiblingRootCannotBeManagedAsContainerDisk(t *testing.T) {
	host := NewHost(nil, nil, &securitypolicy.OpenDoorSecurityPolicyEnforcer{}, io.Discard)
	ctx := context.Background()
	for _, rt := range []guestrequest.RequestType{guestrequest.RequestTypeAdd, guestrequest.RequestTypeRemove} {
		err := host.modifyHostSettings(ctx, "", &guestrequest.ModificationRequest{
			ResourceType: guestresource.ResourceTypeMappedVirtualDisk,
			RequestType:  rt,
			Settings:     &guestresource.LCOWMappedVirtualDisk{Sibling: true, Lun: 0},
		})
		if err == nil || !strings.Contains(err.Error(), "root LUN 0") {
			t.Fatalf("root mount modification %s: %v", rt, err)
		}
	}
	err := modifySCSIDevice(ctx, guestrequest.RequestTypeRemove, &guestresource.SCSIDevice{Sibling: true, Lun: 0})
	if err == nil || !strings.Contains(err.Error(), "root LUN 0") {
		t.Fatalf("root unplug: %v", err)
	}
}
