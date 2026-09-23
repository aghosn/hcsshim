//go:build windows

package uvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/hcs"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

const sharedMemoryRegionProperty = "SharedMemoryRegion"

// SharedMemoryRegions returns the configured shared-memory mappings for the
// utility VM.
func (uvm *UtilityVM) SharedMemoryRegions(ctx context.Context) ([]hcsschema.SharedMemoryRegionInfo, error) {
	if uvm.hcsSystem == nil {
		return nil, fmt.Errorf("utility VM has no HCS compute system")
	}

	props, err := uvm.hcsSystem.PropertiesV2(ctx, hcsschema.PTSharedMemoryRegion)
	if err == nil {
		return props.SharedMemoryRegionInfo, nil
	}
	if !errors.Is(err, hcs.ErrElementNotFound) {
		return nil, fmt.Errorf("query shared-memory regions: %w", err)
	}

	props, queryErr := uvm.hcsSystem.PropertiesV3(
		ctx,
		&hcsschema.PropertyQuery{
			Queries: map[string]interface{}{
				sharedMemoryRegionProperty: nil,
			},
		},
	)
	if queryErr != nil {
		return nil, fmt.Errorf(
			"query shared-memory regions with legacy and named properties: "+
				"legacy: %v; named: %w",
			err,
			queryErr,
		)
	}
	if len(props.SharedMemoryRegionInfo) > 0 {
		return props.SharedMemoryRegionInfo, nil
	}

	response, ok := props.PropertyResponses[sharedMemoryRegionProperty]
	if !ok || len(response.Response) == 0 {
		return nil, fmt.Errorf(
			"named shared-memory property returned no response",
		)
	}

	regions, parseErr := parseSharedMemoryRegionResponse(response.Response)
	if parseErr != nil {
		return nil, fmt.Errorf(
			"decode named shared-memory property response %s: %w",
			response.Response,
			parseErr,
		)
	}
	return regions, nil
}

func parseSharedMemoryRegionResponse(
	response json.RawMessage,
) ([]hcsschema.SharedMemoryRegionInfo, error) {
	var regions []hcsschema.SharedMemoryRegionInfo
	if err := json.Unmarshal(response, &regions); err == nil {
		return regions, nil
	}

	var wrapped struct {
		SharedMemoryRegionInfo []hcsschema.SharedMemoryRegionInfo `json:"SharedMemoryRegionInfo"`
		Regions                []hcsschema.SharedMemoryRegionInfo `json:"Regions"`
	}
	if err := json.Unmarshal(response, &wrapped); err != nil {
		return nil, err
	}
	if len(wrapped.SharedMemoryRegionInfo) > 0 {
		return wrapped.SharedMemoryRegionInfo, nil
	}
	if len(wrapped.Regions) > 0 {
		return wrapped.Regions, nil
	}
	return nil, fmt.Errorf("response contains no shared-memory regions")
}
