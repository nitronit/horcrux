package pcosigner

// TODO: Move back to Cosigner Package
import (
	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/pkg/pcosigner/cipher"
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

// An interface for a Cosigners, both local and remote
type ICosigner interface {
	// GetID should return the id number of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int
	// GetAddress gets the P2P URL (GRPC and Raft)
	GetAddress() string
}

type IRemoteCosigner interface {
	ICosigner
	// Sign the requested bytes
	// TODO: Change name to PostNoncesAndSign
	SetNoncesAndSign(req CosignerSetNoncesAndSignRequest) (*CosignerSignResponse, error)
	// GetNonces requests nonce frpm the peer cosigners
	GetNonces(chainID string, hrst types.HRSTKey) (*CosignNoncesResponse, error)
}

// ILocalCosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type ILocalCosigner interface {
	IRemoteCosigner
	VerifySignature(chainID string, payload, signature []byte) bool
	// GetPubKey gets the combined public key (permament)
	// Not used by Remote Cosigner and should it be really used by the local cosigner?
	GetPubKey(chainID string) (cometcrypto.PubKey, error)
	WaitForSignStatesToFlushToDisk()
	LoadSignStateIfNecessary(id string) error
	SaveLastSignedState(id string, consensus types.SignStateConsensus) error
	CombineSignatures(id string, sigs []cipher.PartialSignature) ([]byte, error)
}

func FromILocalToICosigner(iface ILocalCosigner) []ICosigner {
	icosign := make([]ICosigner, 0)
	icosign = append(icosign, ICosigner(iface))
	return icosign
}
func FromIRemoteToICosigner(iface []IRemoteCosigner) []ICosigner {
	icosign := make([]ICosigner, 0)
	for _, cosigner := range iface {
		icosign = append(icosign, ICosigner(cosigner))
	}
	return icosign
}
