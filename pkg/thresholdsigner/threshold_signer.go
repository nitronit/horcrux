package thresholdsigner

import (
	"sync"

	"github.com/strangelove-ventures/horcrux/pkg/types"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

const (
	SignerTypeSoftSign = "SoftSign"
	SignerTypeHSM      = "HSM"
)

type LastSignStateWrapper struct {
	// Signing is thread safe - LastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	LastSignStateMutex sync.Mutex

	// lastSignState stores the last sign types for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *types.SignState
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
