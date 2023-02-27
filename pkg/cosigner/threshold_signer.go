// Interface for the local signer whether it's a soft sign or HSM
package cosigner

import (
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/thresholdsigner"
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

type ThresholdSigner interface {
	Type() string

	DealShares(height int64, round int64, step int8, timestamp time.Time) (thresholdsigner.HrsMetadata, error)

	GetEphemeralSecretPart(req types.CosignerGetEphemeralSecretPartRequest, m *thresholdsigner.LastSignStateWrapper,
		peers map[int]types.CosignerPeer) (types.CosignerEphemeralSecretPart, error)

	SetEphemeralSecretPart(req types.CosignerSetEphemeralSecretPartRequest, m *thresholdsigner.LastSignStateWrapper,
		peers map[int]types.CosignerPeer) error

	Sign(signBytes []byte, m *thresholdsigner.LastSignStateWrapper) (types.CosignerSignResponse, error)

	GetID() (int, error)
}
