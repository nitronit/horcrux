package thresholdsigner

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"
	tmcryptoed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// ThresholdSignerSoft implements the interface pkg/cosigner/threshold_signer.go
// ThresholdSignerSoft is the implementation of a soft sign signer at the local level.
type ThresholdSignerSoft struct {
	pubKeyBytes []byte
	key         types.CosignerKey
	// total signers
	total     uint8
	threshold uint8
	// Height, Round, Step, Timestamp --> metadata
	hrsMeta map[types.HRSTKey]HrsMetadata
}

// NewThresholdSignerSoft constructs a ThresholdSigner
// that signs using the local key share file.
func NewThresholdSignerSoft(key types.CosignerKey, threshold, total uint8) *ThresholdSignerSoft {
	softSigner := &ThresholdSignerSoft{
		key:       key,
		hrsMeta:   make(map[types.HRSTKey]HrsMetadata),
		total:     total,
		threshold: threshold,
	}

	// cache the public key bytes for signing operations.
	// Ensures casting else it will naturally panic.
	ed25519Key := softSigner.key.PubKey.(tmcryptoed25519.PubKey)
	softSigner.pubKeyBytes = make([]byte, len(ed25519Key))
	softSigner.pubKeyBytes = ed25519Key[:]

	return softSigner
}

// Implements ThresholdSigner in threshold_signer.go
func (softSigner *ThresholdSignerSoft) Type() string {
	return SignerTypeSoftSign
}

// Implements ThresholdSigner in threshold_signer.go
func (softSigner *ThresholdSignerSoft) GetID() (int, error) {
	return softSigner.key.ID, nil
}

// Implements ThresholdSigner in threshold_signer.go
func (softSigner *ThresholdSignerSoft) Sign(
	signBytes []byte, m *LastSignStateWrapper) (types.CosignerSignResponse, error) {
	m.LastSignStateMutex.Lock()
	defer m.LastSignStateMutex.Unlock()

	res := types.CosignerSignResponse{}
	lss := m.LastSignState

	hrst, err := types.UnpackHRST(signBytes)
	if err != nil {
		return res, err
	}

	sameHRS, err := lss.CheckHRS(hrst)
	if err != nil {
		return res, err
	}

	// If the HRS is the same the sign bytes may still differ by timestamp
	// It is ok to re-sign a different timestamp if that is the only difference in the sign bytes
	// same HRS, and only differ by timestamp  its ok to sign again
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			res.EphemeralPublic = lss.EphemeralPublic
			res.Signature = lss.Signature
			return res, nil
		} else if err := lss.OnlyDifferByTimestamp(signBytes); err != nil {
			return res, err // same HRS, and only differ by timestamp  its ok to sign again
		}
	}

	meta, ok := softSigner.hrsMeta[hrst]
	if !ok {
		return res, errors.New("no metadata at HRS")
	}

	shareParts := make([]tsed25519.Scalar, 0)
	publicKeys := make([]tsed25519.Element, 0)

	// calculate secret and public keys
	for _, peer := range meta.Peers {
		if len(peer.Share) == 0 {
			continue
		}
		shareParts = append(shareParts, peer.Share)
		publicKeys = append(publicKeys, peer.EphemeralSecretPublicKey)
	}

	ephemeralShare := tsed25519.AddScalars(shareParts)
	ephemeralPublic := tsed25519.AddElements(publicKeys)

	// check bounds for ephemeral share to avoid passing out of bounds valids to SignWithShare
	if len(ephemeralShare) != 32 {
		return res, errors.New("ephemeral share is out of bounds")
	}

	var scalarBytes [32]byte
	copy(scalarBytes[:], ephemeralShare)
	if !edwards25519.ScMinimal(&scalarBytes) {
		return res, errors.New("ephemeral share is out of bounds")
	}

	sig := tsed25519.SignWithShare(
		signBytes, softSigner.key.ShareKey, ephemeralShare, softSigner.pubKeyBytes, ephemeralPublic)

	m.LastSignState.EphemeralPublic = ephemeralPublic
	err = m.LastSignState.Save(types.SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
		SignBytes: signBytes,
	}, nil, true)
	if err != nil {
		var isSameHRSError *types.SameHRSError
		if !errors.As(err, &isSameHRSError) {
			return res, err
		}
	}

	for existingKey := range softSigner.hrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrst) {
			delete(softSigner.hrsMeta, existingKey)
		}
	}

	res.EphemeralPublic = ephemeralPublic
	res.Signature = sig
	return res, nil
}

// Implements ThresholdSigner from threshold_signer.go
func (softSigner *ThresholdSignerSoft) DealShares(
	height int64, round int64, step int8, timestamp time.Time) (HrsMetadata, error) {
	hrsKey := types.HRSTKey{
		Height:    height,
		Round:     round,
		Step:      step,
		Timestamp: timestamp.UnixNano(),
	}

	meta, ok := softSigner.hrsMeta[hrsKey]
	if ok {
		return meta, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	meta = HrsMetadata{
		Secret: secret,
		Peers:  make([]PeerMetadata, softSigner.total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!

	meta.DealtShares = tsed25519.DealShares(meta.Secret, softSigner.threshold, softSigner.total)

	softSigner.hrsMeta[hrsKey] = meta

	return meta, nil
}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
// Implements ThresholdSigner interface from threshold_signer.go
func (softSigner *ThresholdSignerSoft) GetEphemeralSecretPart(
	req types.CosignerGetEphemeralSecretPartRequest, m *LastSignStateWrapper, peers map[int]types.CosignerPeer) (
	types.CosignerEphemeralSecretPart, error) {

	res := types.CosignerEphemeralSecretPart{}

	// protects the meta map
	m.LastSignStateMutex.Lock()
	defer m.LastSignStateMutex.Unlock()

	hrst := types.HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.hrsMeta[hrst]

	// generate metadata placeholder
	if !ok {
		newMeta, err := softSigner.DealShares(req.Height, req.Round, req.Step, req.Timestamp)

		if err != nil {
			return res, err
		}

		meta = newMeta
		softSigner.hrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Peers[softSigner.key.ID-1].Share = meta.DealtShares[softSigner.key.ID-1]
	meta.Peers[softSigner.key.ID-1].EphemeralSecretPublicKey = ourEphPublicKey

	// grab the peer info for the ID being requested
	peer, ok := peers[req.ID]
	if !ok {
		return res, errors.New("unknown peer ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &peer.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = softSigner.key.ID
	res.SourceEphemeralSecretPublicKey = ourEphPublicKey
	res.EncryptedSharePart = encrypted

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity

	jsonBytes, err := tmjson.Marshal(res)

	if err != nil {
		return res, err
	}

	digest := sha256.Sum256(jsonBytes)
	signature, err := rsa.SignPSS(rand.Reader, &softSigner.key.RSAKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return res, err
	}

	res.SourceSig = signature

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner (signer)
// Implements ThresholdSigner interface in threshold_signer.go
func (softSigner *ThresholdSignerSoft) SetEphemeralSecretPart(
	req types.CosignerSetEphemeralSecretPartRequest, m *LastSignStateWrapper, peers map[int]types.CosignerPeer) error {

	// Verify the source signature
	if req.SourceSig == nil {
		return errors.New("SourceSig field is required")
	}

	digestMsg := types.CosignerEphemeralSecretPart{
		SourceID: req.SourceID,
		// DestinationID:                  0,
		SourceEphemeralSecretPublicKey: req.SourceEphemeralSecretPublicKey,
		EncryptedSharePart:             req.EncryptedSharePart,
		// SourceSig:                      []byte{},
	}

	digestBytes, err := tmjson.Marshal(digestMsg)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(digestBytes)
	peer, ok := peers[req.SourceID]

	if !ok {
		return fmt.Errorf("unknown cosigner: %d", req.SourceID)
	}

	peerPub := peer.PublicKey
	err = rsa.VerifyPSS(&peerPub, crypto.SHA256, digest[:], req.SourceSig, nil)
	if err != nil {
		return err
	}

	// protects the meta map
	m.LastSignStateMutex.Lock()
	defer m.LastSignStateMutex.Unlock()

	hrst := types.HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.hrsMeta[hrst] // generate metadata placeholder, softSigner.HrsMeta[hrst] is non-addressable
	if !ok {
		// TODO: this is a bit of a hack, we should be able to get it from hrst variable?
		newMeta, err := softSigner.DealShares(req.Height, req.Round, req.Step, time.Time{})

		if err != nil {
			return err
		}
		meta = newMeta
		softSigner.hrsMeta[hrst] = meta // updates the metadata placeholder
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &softSigner.key.RSAKey, req.EncryptedSharePart, nil)
	if err != nil {
		return err
	}
	// set slot
	// Share & EphemeralSecretPublicKey is a SLICE so its a valid change of the shared struct softSigner!
	meta.Peers[req.SourceID-1].Share = sharePart
	meta.Peers[req.SourceID-1].EphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey

	return nil
}

// _ is a type assertion to ensure that ThresholdSignerSoft implements the ThresholdSigner interface
// var _ ThresholdSigner = (*ThresholdSignerSoft)(nil)
