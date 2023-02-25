// Interface for the local signer whether it's a soft sign or HSM
package cosigner

import (
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/state"
	"github.com/strangelove-ventures/horcrux/pkg/thresholdsigner"
)

type ThresholdSigner interface {
	Type() string

	DealShares(height int64, round int64, step int8, timestamp time.Time) (thresholdsigner.HrsMetadata, error)

	GetEphemeralSecretPart(req state.CosignerGetEphemeralSecretPartRequest, m *thresholdsigner.LastSignStateWrapper,
		peers map[int]state.CosignerPeer) (state.CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req state.CosignerSetEphemeralSecretPartRequest, m *thresholdsigner.LastSignStateWrapper,
		peers map[int]state.CosignerPeer) error

	Sign(signBytes []byte, m *thresholdsigner.LastSignStateWrapper) (state.CosignerSignResponse, error)

	GetID() (int, error)
}
