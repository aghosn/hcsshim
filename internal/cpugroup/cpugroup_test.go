//go:build windows

package cpugroup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

func TestSchedulingPriorityOperationJSON(t *testing.T) {
	for _, priority := range []uint64{0, 2, 7, 1 << 32} {
		details := setPropertyOperation{
			GroupId: NullGroupID, PropertyCode: hcsschema.CPUSchedulingPriorityProperty,
			PropertyValue: priority,
		}
		data, err := json.Marshal(details)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		var actual uint64
		if err := json.Unmarshal(decoded["PropertyValue"], &actual); err != nil || actual != priority {
			t.Fatalf("priority wire value: %s, %v", data, err)
		}
		if string(decoded["PropertyCode"]) != "131072" || string(decoded["GroupId"]) != `"`+NullGroupID+`"` {
			t.Fatalf("unexpected SetProperty details: %s", data)
		}
	}
}

func TestSetSchedulingPriorityRejectsOutOfRange(t *testing.T) {
	for _, priority := range []uint32{8, ^uint32(0)} {
		err := SetSchedulingPriority(context.Background(), NullGroupID, priority)
		if err == nil || !strings.Contains(err.Error(), "exceeds 7") {
			t.Fatalf("expected validation before HCS call for %d, got %v", priority, err)
		}
	}
}

// Unit tests for creating and deleting a CPU group on the host
func TestCPUGroupCreateWithIDAndDelete(t *testing.T) {
	t.Skip("only works on classic/core scheduler, skipping as we can't check this dynamically right now")

	lps := []uint32{0, 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	id, err := guid.NewV4()
	if err != nil {
		t.Fatalf("failed to create cpugroup guid with: %v", err)
	}

	err = Create(ctx, id.String(), lps)
	if err != nil {
		t.Fatalf("failed to create cpugroup %s with: %v", id.String(), err)
	}

	defer func() {
		if err := Delete(ctx, id.String()); err != nil {
			t.Fatalf("failed to delete cpugroup %s with: %v", id.String(), err)
		}
	}()

	_, err = GetCPUGroupConfig(ctx, id.String())
	if err != nil {
		t.Fatalf("failed to find cpugroup on host with: %v", err)
	}
}
