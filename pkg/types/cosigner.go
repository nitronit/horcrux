package types

import (
	"crypto/rsa"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/cosigner/proto"
)

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// SignBytes should be a serialized block
type CosignerSignRequest struct {
	SignBytes []byte
}

type CosignerSignResponse struct {
	EphemeralPublic []byte
	Timestamp       time.Time
	Signature       []byte
}

type CosignerSetEphemeralSecretPartRequest struct {
	SourceID                       int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
	Height                         int64
	Round                          int64
	Step                           int8
	Timestamp                      time.Time
}

type CosignerSignBlockRequest struct {
	ChainID string
	Block   *Block
}

type CosignerSignBlockResponse struct {
	Signature []byte
}

type CosignerEphemeralSecretPartsResponse struct {
	EncryptedSecrets []CosignerEphemeralSecretPart
}

type CosignerSetEphemeralSecretPartsAndSignRequest struct {
	EncryptedSecrets []CosignerEphemeralSecretPart
	HRST             HRSTKey
	SignBytes        []byte
}

type CosignerPeer struct {
	ID        int
	PublicKey rsa.PublicKey
}

type CosignerGetEphemeralSecretPartRequest struct {
	ID        int
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

// HACK: Duplicate use of Block and toProto is temporary.
type Block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

// func (block Block) toProto() *proto.Block {
// 	return &proto.Block{
// 		Height:    block.Height,
// 		Round:     block.Round,
// 		Step:      int32(block.Step),
// 		SignBytes: block.SignBytes,
// 		Timestamp: block.Timestamp.UnixNano(),
// 	}
// }

func (block Block) ToProto() *proto.Block {
	return &proto.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

type CosignerEphemeralSecretPart struct {
	SourceID                       int
	DestinationID                  int
	SourceEphemeralSecretPublicKey []byte
	EncryptedSharePart             []byte
	SourceSig                      []byte
}

func (secretPart *CosignerEphemeralSecretPart) toProto() *proto.EphemeralSecretPart {
	return &proto.EphemeralSecretPart{
		SourceID:                       int32(secretPart.SourceID),
		DestinationID:                  int32(secretPart.DestinationID),
		SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
		EncryptedSharePart:             secretPart.EncryptedSharePart,
		SourceSig:                      secretPart.SourceSig,
	}
}

type CosignerEphemeralSecretParts []CosignerEphemeralSecretPart

func (secretParts CosignerEphemeralSecretParts) ToProto() (out []*proto.EphemeralSecretPart) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}
func (secretParts CosignerEphemeralSecretParts) toProto() (out []*proto.EphemeralSecretPart) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerEphemeralSecretPartFromProto(secretPart *proto.EphemeralSecretPart) CosignerEphemeralSecretPart {
	return CosignerEphemeralSecretPart{
		SourceID:                       int(secretPart.SourceID),
		DestinationID:                  int(secretPart.DestinationID),
		SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
		EncryptedSharePart:             secretPart.EncryptedSharePart,
		SourceSig:                      secretPart.SourceSig,
	}
}

func CosignerEphemeralSecretPartsFromProto(
	secretParts []*proto.EphemeralSecretPart) (out []CosignerEphemeralSecretPart) {
	for _, secretPart := range secretParts {
		out = append(out, CosignerEphemeralSecretPartFromProto(secretPart))
	}
	return
}
