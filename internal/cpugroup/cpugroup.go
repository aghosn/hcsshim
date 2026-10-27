//go:build windows

package cpugroup

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
	hcs "github.com/Microsoft/hcsshim/internal/hcs/v2"
	"github.com/pkg/errors"
)

const NullGroupID = "00000000-0000-0000-0000-000000000000"

// MaxSchedulingPriority is the highest Hyper-V CPU group scheduling priority.
const MaxSchedulingPriority uint32 = 7

type setPropertyOperation struct {
	GroupId       string
	PropertyCode  uint32
	PropertyValue uint64
}

// SetSchedulingPriority sets a CPU group's scheduling priority (0 through 7).
func SetSchedulingPriority(ctx context.Context, id string, priority uint32) error {
	if priority > MaxSchedulingPriority {
		return fmt.Errorf("CPU group scheduling priority %d exceeds %d", priority, MaxSchedulingPriority)
	}
	details := &setPropertyOperation{
		GroupId:       strings.ToLower(id),
		PropertyCode:  hcsschema.CPUSchedulingPriorityProperty,
		PropertyValue: uint64(priority),
	}
	if err := modifyCPUGroupRequest(ctx, hcsschema.SetProperty, details); err != nil {
		return errors.Wrapf(err, "failed to set CPU group %s scheduling priority to %d", id, priority)
	}
	return nil
}

// ErrHVStatusInvalidCPUGroupState corresponds to the internal error code for HV_STATUS_INVALID_CPU_GROUP_STATE
var ErrHVStatusInvalidCPUGroupState = errors.New("The hypervisor could not perform the operation because the CPU group is entering or in an invalid state.")

// Delete deletes the cpugroup from the host
func Delete(ctx context.Context, id string) error {
	operation := hcsschema.DeleteGroup
	details := hcsschema.DeleteGroupOperation{
		GroupId: id,
	}

	return modifyCPUGroupRequest(ctx, operation, details)
}

// modifyCPUGroupRequest is a helper function for making modify calls to a cpugroup
func modifyCPUGroupRequest(ctx context.Context, operation hcsschema.CPUGroupOperation, details interface{}) error {
	req := hcsschema.ModificationRequest{
		PropertyType: hcsschema.PTCPUGroup,
		Settings: &hcsschema.HostProcessorModificationRequest{
			Operation:        operation,
			OperationDetails: details,
		},
	}

	return hcs.ModifyServiceSettings(ctx, req)
}

// Create creates a new cpugroup on the host with a prespecified id
func Create(ctx context.Context, id string, logicalProcessors []uint32) error {
	operation := hcsschema.CreateGroup
	details := &hcsschema.CreateGroupOperation{
		GroupId:               strings.ToLower(id),
		LogicalProcessors:     logicalProcessors,
		LogicalProcessorCount: uint32(len(logicalProcessors)),
	}
	if err := modifyCPUGroupRequest(ctx, operation, details); err != nil {
		return errors.Wrapf(err, "failed to make cpugroups CreateGroup request for details %+v", details)
	}
	return nil
}

// GetCPUGroupConfig finds the cpugroup config information for group with `id`
func GetCPUGroupConfig(ctx context.Context, id string) (*hcsschema.CpuGroupConfig, error) {
	query := hcsschema.PropertyQuery{
		PropertyTypes: []hcsschema.PropertyType{hcsschema.PTCPUGroup},
	}
	cpuGroupsPresent, err := hcs.GetServiceProperties(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(cpuGroupsPresent.Properties) != 1 {
		return nil, fmt.Errorf("expected one CPU group configuration property, got %d", len(cpuGroupsPresent.Properties))
	}
	groupConfigs := &hcsschema.CpuGroupConfigurations{}
	if err := json.Unmarshal(cpuGroupsPresent.Properties[0], groupConfigs); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal host cpugroups")
	}

	for _, c := range groupConfigs.CpuGroups {
		if strings.EqualFold(c.GroupId, id) {
			return &c, nil
		}
	}
	return nil, fmt.Errorf("no cpugroup exists with id %v", id)
}
