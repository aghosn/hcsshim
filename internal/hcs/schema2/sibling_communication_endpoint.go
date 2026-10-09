/*
 * HCS API
 *
 * Private prototype schema for direct sibling communication.
 */

package hcsschema

type SiblingCommunicationEndpointRole string

const (
	SiblingCommunicationEndpointRoleWorkload SiblingCommunicationEndpointRole = "Workload"
	SiblingCommunicationEndpointRoleBackend  SiblingCommunicationEndpointRole = "Backend"
)

type SiblingCommunicationEndpoint struct {
	GroupID         string                           `json:"GroupId"`
	Role            SiblingCommunicationEndpointRole `json:"Role"`
	TargetVP        uint32                           `json:"TargetVp,omitempty"`
	TargetSINT      uint16                           `json:"TargetSint"`
	EventFlagNumber uint16                           `json:"EventFlagNumber"`
}

// SiblingCommunicationRouteInfo is returned by the "SiblingCommunication"
// property query. OutboundConnectionId is zero until the peer has registered.
type SiblingCommunicationRouteInfo struct {
	GroupID              string                           `json:"GroupId,omitempty"`
	Role                 SiblingCommunicationEndpointRole `json:"Role,omitempty"`
	TargetVP             uint32                           `json:"TargetVp,omitempty"`
	TargetSINT           uint16                           `json:"TargetSint,omitempty"`
	EventFlagNumber      uint16                           `json:"EventFlagNumber,omitempty"`
	OutboundConnectionID uint32                           `json:"OutboundConnectionId,omitempty"`
}
