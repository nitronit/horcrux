package cosigner

import (
	"time"

	metrics "github.com/strangelove-ventures/horcrux/pkg/metrics"
	"github.com/strangelove-ventures/horcrux/pkg/state"
	"github.com/strangelove-ventures/horcrux/pkg/thresholdsigner"
)

// LocalCosigner responds to sign requests using their share key
// LocalCosigner "embeds" the Threshold signer.
// LocalCosigner maintains a watermark to avoid double-signing via the embedded LastSignStateWrapper.
// LocalCosigner signing is thread safe by embedding *LastSignStateWrapper which contains LastSignStateMutex sync.Mutex.
type LocalCosigner struct {
	LastSignStateWrapper *thresholdsigner.LastSignStateWrapper
	address              string
	Peers                map[int]state.CosignerPeer
	thresholdSigner      ThresholdSigner // Interface
}

// Initialize a Local Cosigner
func NewLocalCosigner(
	address string,
	peers []state.CosignerPeer,
	signState *state.SignState,
	thresholdSigner ThresholdSigner) *LocalCosigner {

	LastSignStateWrapper := thresholdsigner.LastSignStateWrapper{
		// LastSignStateMutex  doesnt need to be initialized. i.e LastSignStateMutex: sync.Mutex{},
		LastSignState: signState,
	}

	cosigner := &LocalCosigner{
		LastSignStateWrapper: &LastSignStateWrapper,
		address:              address,
		thresholdSigner:      thresholdSigner,
		Peers:                make(map[int]state.CosignerPeer),
	}

	for _, peer := range peers {
		cosigner.Peers[peer.ID] = peer
	}
	return cosigner
}

func (cosigner *LocalCosigner) SaveLastSignedState(signState state.SignStateConsensus) error {
	return cosigner.LastSignStateWrapper.LastSignState.Save(
		signState, &cosigner.LastSignStateWrapper.LastSignStateMutex, true)
}

// GetID returns the id of the cosigner, via the thresholdSigner getter
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetID() int {
	id, _ := cosigner.thresholdSigner.GetID()
	return id
}

// GetAddress returns the GRPC URL of the cosigner
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetAddress() string {
	return cosigner.address
}

// GetEphemeralSecretParts
// // Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	hrst state.HRSTKey) (*state.CosignerEphemeralSecretPartsResponse, error) {
	metrics.MetricsTimeKeeper.SetPreviousLocalEphemeralShare(time.Now())

	res := &state.CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]state.CosignerEphemeralSecretPart, 0, len(cosigner.Peers)-1),
	}
	for _, peer := range cosigner.Peers {
		if peer.ID == cosigner.GetID() {
			continue
		}
		secretPart, err := cosigner.thresholdSigner.GetEphemeralSecretPart(state.CosignerGetEphemeralSecretPartRequest{
			ID:        peer.ID,
			Height:    hrst.Height,
			Round:     hrst.Round,
			Step:      hrst.Step,
			Timestamp: time.Unix(0, hrst.Timestamp),
		}, cosigner.LastSignStateWrapper,
			cosigner.Peers)

		if err != nil {
			return nil, err
		}

		res.EncryptedSecrets = append(res.EncryptedSecrets, secretPart)
	}
	return res, nil
}

// SetEphemeralSecretPartsAndSign
// Implements the Cosigner interface from Cosigner.go
func (cosigner *LocalCosigner) SetEphemeralSecretPartsAndSign(
	req state.CosignerSetEphemeralSecretPartsAndSignRequest) (*state.CosignerSignResponse, error) {
	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.thresholdSigner.SetEphemeralSecretPart(state.CosignerSetEphemeralSecretPartRequest{
			SourceID:                       secretPart.SourceID,
			SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             secretPart.EncryptedSharePart,
			SourceSig:                      secretPart.SourceSig,
			Height:                         req.HRST.Height,
			Round:                          req.HRST.Round,
			Step:                           req.HRST.Step,
			Timestamp:                      time.Unix(0, req.HRST.Timestamp),
		}, cosigner.LastSignStateWrapper, cosigner.Peers)
		if err != nil {
			return nil, err
		}
	}
	// TODO change this to return individual fields
	res, err := cosigner.thresholdSigner.Sign(req.SignBytes, cosigner.LastSignStateWrapper)
	return &res, err
}

// _ is a type assertion to ensure that LocalCosigner implements the Cosigner interface
var _ Cosigner = (*LocalCosigner)(nil)
