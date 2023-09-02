package signer

import (
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

type ISigner interface {
	// SignAndVerify is responsible for signing the block and verifying the signature
	// It absracts the threshold signature verification
	SignAndVerify(chainID string, threshold int, hrst types.HRSTKey, grpcTimeout time.Duration, stamp time.Time, timeStartSignBlock time.Time, signBytes []byte) ([]byte, bool, error)

	GetPubKey(chainID string) (crypto.PubKey, error)

	WaitForSignStatesToFlushToDisk()

	// SaveLastSignedState saves the last sign state in the "high watermark" file at the cosigner lever.
	SaveLastSignedState(chainID string, signStateConsensus types.SignStateConsensus) error
	/*

		// TODO: This should be the job of ThresholdValidator
		LoadSignStateIfNecessary(chainID string) error

		// FIX: Below should not be the responsibility of the ISigner
		// Its a temporary hack to get the peers and localCosign
		GetPeers() []pcosigner.ICosigner          // Returns the remote peers (for use in GRPC)
		GetLocalCosign() pcosigner.ILocalCosigner //
	*/
	// sign(chainID string, threshold int, hrst types.HRSTKey, grpcTimeout time.Duration, stamp time.Time, timeStartSignBlock time.Time, signBytes []byte) ([]byte, time.Time, error)
	// verify(chainID string, signBytes []byte, signature []byte) (bool, error)
}
