package thresholdsigner

import (
	"sync"

	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const (
	SignerTypeSoftSign = "SoftSign"
	SignerTypeHSM      = "HSM"
)

// Interface for the local signer whether it's a soft sign or HSM
type ThresholdSigner interface {
	Type() string

	DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error)

	GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest, m *LastSignStateWrapper,
		peers map[int]CosignerPeer) (CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest, m *LastSignStateWrapper,
		peers map[int]CosignerPeer) error

	Sign(req CosignerSignRequest, m *LastSignStateWrapper) (CosignerSignResponse, error)

	GetID() (int, error)
}
type LastSignStateWrapper struct {
	// Signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	lastSignStateMutex sync.Mutex

	// lastSignState stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState
}

// PeerMetadata holds the share and the ephermeral secret public key
// Moved from Local cosigner to threshold_ed25519
type PeerMetadata struct {
	Share                    []byte
	EphemeralSecretPublicKey []byte
}

// HrsMetadata holds the ephemeral nonces from cosigner peers
// for a given height, round, step.
type HrsMetadata struct {
	// need to be _total_ entries per player
	Secret      []byte
	DealtShares []tsed25519.Scalar
	Peers       []PeerMetadata
}
