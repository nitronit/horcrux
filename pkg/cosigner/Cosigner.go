package cosigner

import (
	"github.com/strangelove-ventures/horcrux/pkg/state"
)

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// GetID gets the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// GetAddress gets the P2P URL (GRPC and Raft)
	GetAddress() string

	// GetEphemeralSecretParts gets ephemeral secret part for all peers
	GetEphemeralSecretParts(hrst state.HRSTKey) (*state.CosignerEphemeralSecretPartsResponse, error)

	// SetEphemeralSecretPartsAndSign sign the requested bytes
	SetEphemeralSecretPartsAndSign(req state.CosignerSetEphemeralSecretPartsAndSignRequest) (*state.CosignerSignResponse, error)
}
