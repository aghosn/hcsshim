//go:build windows

package uvm

import (
	"context"
	"encoding/json"
	"fmt"

	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"
)

const siblingCommunicationProperty = "SiblingCommunication"

// SiblingCommunicationRoutes returns the sibling communication routes of the
// utility VM, including the connection ID it uses to signal each peer.
func (uvm *UtilityVM) SiblingCommunicationRoutes(ctx context.Context) ([]hcsschema.SiblingCommunicationRouteInfo, error) {
	if uvm.hcsSystem == nil {
		return nil, fmt.Errorf("utility VM has no HCS compute system")
	}

	props, err := uvm.hcsSystem.PropertiesV3(
		ctx,
		&hcsschema.PropertyQuery{
			Queries: map[string]interface{}{
				siblingCommunicationProperty: nil,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("query sibling communication routes: %w", err)
	}

	response, ok := props.PropertyResponses[siblingCommunicationProperty]
	if !ok || len(response.Response) == 0 {
		return nil, fmt.Errorf("sibling communication property returned no response")
	}

	var routes []hcsschema.SiblingCommunicationRouteInfo
	if err := json.Unmarshal(response.Response, &routes); err != nil {
		return nil, fmt.Errorf(
			"decode sibling communication property response %s: %w",
			response.Response,
			err,
		)
	}
	return routes, nil
}
