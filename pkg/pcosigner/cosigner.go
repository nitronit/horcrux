package pcosigner

import (
	"fmt"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/pcosigner/cipher"
	"github.com/strangelove-ventures/horcrux/pkg/types"

	shamirService "github.com/strangelove-ventures/horcrux/pkg/proto/cosigner_service"
)

func NewThresholdSignerSoft(config *RuntimeConfig, id int, chainID string) (*cipher.ThresholdSignerSoft, error) {
	keyFile, err := config.KeyFileExistsCosigner(chainID)
	if err != nil {
		return nil, err
	}

	key, err := cipher.LoadCosignerEd25519Key(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading cosigner key: %s", err)
	}

	if key.ID != id {
		return nil, fmt.Errorf("key shard ID (%d) in (%s) does not match cosigner ID (%d)", key.ID, keyFile, id)
	}
	privateKeyShard := key.PrivateShard
	pubKey := key.PubKey.Bytes()
	threshold := uint8(config.Config.ThresholdModeConfig.Threshold)
	total := uint8(len(config.Config.ThresholdModeConfig.Cosigners))

	s, err := cipher.NewThresholdSignerSoft(
		privateKeyShard,
		pubKey,
		threshold,
		total)

	return &s, nil
}

type Cosigner struct {
	id      int
	address string
}

func NewCosign(id int, address string) Cosigner {
	return Cosigner{
		id:      id,
		address: address,
	}
}
func (cosign *Cosigner) GetAddress() string {
	return cosign.address
}

// GetID returns the ID of the remote cosigner
// Implements the cosigner interface
func (cosign *RemoteCosigner) GetID() int {
	return cosign.id
}

type CosignerSignBlockResponse struct {
	Signature []byte
}

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
type CosignerSignRequest struct {
	ChainID   string
	SignBytes []byte
}

type CosignerSignResponse struct {
	NoncePublic []byte
	Timestamp   time.Time
	Signature   []byte
}

type CosignNonce struct {
	SourceID      int
	DestinationID int
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *CosignNonce) toProto() *shamirService.Nonce {
	return &shamirService.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

// CosignerNonces is a list of CosignerNonce
type CosignerNonces []CosignNonce

func (secretParts CosignerNonces) ToProto() (out []*shamirService.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerNonceFromProto(secretPart *shamirService.Nonce) CosignNonce {
	return CosignNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func CosignerNoncesFromProto(secretParts []*shamirService.Nonce) []CosignNonce {
	out := make([]CosignNonce, len(secretParts))
	for i, secretPart := range secretParts {
		out[i] = CosignerNonceFromProto(secretPart)
	}
	return out
}

type CosignerSetNonceRequest struct {
	ChainID   string
	SourceID  int
	PubKey    []byte
	Share     []byte
	Signature []byte
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

type CosignNoncesResponse struct {
	Nonces []CosignNonce
}

// TODO: Change name to PostNoncesAndSign
type CosignerSetNoncesAndSignRequest struct {
	ChainID   string
	Nonces    []CosignNonce
	HRST      types.HRSTKey
	SignBytes []byte
}
