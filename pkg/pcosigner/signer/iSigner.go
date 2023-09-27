package signer

import (
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

// ISigner is responsible for signing the block and verifying the signature
// This abstracts the threshold signature verification, so we can implements multiple "cosigners"
// Ususally this is implemented by a Cosigner node that embedds a local cosigner, []remote cosigners those are responsible for communicatating with the other nodes on the network.
type ISigner interface {
	// SignAndVerify is responsible for signing the block and verifying the signature
	// It absracts the threshold signature verification
	SignAndVerify(chainID string, threshold int, hrst types.HRSTKey, grpcTimeout time.Duration, stamp time.Time, timeStartSignBlock time.Time, signBytes []byte) ([]byte, bool, error)

	GetPubKey(chainID string) (crypto.PubKey, error)

	WaitForSignStatesToFlushToDisk()

	// SaveLastSignedState saves the last sign state in the "high watermark" file at the cosigner lever.
	SaveLastSignedState(chainID string, signStateConsensus types.SignStateConsensus) error

	GetLocalCosign() pcosigner.ILocalCosigner
	GetPeers() []pcosigner.IRemoteCosigner
	// TODO: Potentially add generate?
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
