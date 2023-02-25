package thresholdsigner

import (
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/state"
)

func NewThresholdSignerHSM() *ThresholdSignerHSM {
	panic("Not Implemented")
}

type ThresholdSignerHSM struct {
	// TODO: Implement HSM Signer
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) Type() string {
	return "hsm"
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) DealShares(
	height int64, round int64, step int8, timestamp time.Time) (HrsMetadata, error) {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) SetEphemeralSecretPart(
	req state.CosignerSetEphemeralSecretPartRequest, m *LastSignStateWrapper, peers map[int]state.CosignerPeer) error {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) GetEphemeralSecretPart(
	req state.CosignerGetEphemeralSecretPartRequest, m *LastSignStateWrapper, peers map[int]state.CosignerPeer) (
	state.CosignerEphemeralSecretPart, error) {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) Sign(
	signBytes []byte, m *LastSignStateWrapper) (state.CosignerSignResponse, error) {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) GetID() (int, error) {
	panic("Not implemented")
}

// _ is a type assertion to ensure that ThresholdSignerHSM implements ThresholdSigner
// var _ ThresholdSigner = (*ThresholdSignerHSM)(nil)
