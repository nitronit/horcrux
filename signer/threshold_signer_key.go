package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"

	amino "github.com/tendermint/go-amino"
	tmCrypto "github.com/tendermint/tendermint/crypto"
	tmEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tmCryptoEncoding "github.com/tendermint/tendermint/crypto/encoding"
	tmProtoCrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
)

// ThresholdSignerKey is a single keyholder for a single(!) m-of-n threshold signer.
type ThresholdSignerKey struct {
	PubKey   tmCrypto.PubKey `json:"pub_key"`
	ShareKey []byte          `json:"secret_share"`
	// ThresholdSigners private RSA key
	RSAKey rsa.PrivateKey `json:"rsa_key"`
	ID     int            `json:"id"`
	// Co-signers public rsa key
	CosignerKeys []*rsa.PublicKey `json:"rsa_pubs"`
}

func (thresholdSignerKey *ThresholdSignerKey) MarshalJSON() ([]byte, error) {
	type Alias ThresholdSignerKey

	// marshal our private key and all public keys
	privateBytes := x509.MarshalPKCS1PrivateKey(&thresholdSignerKey.RSAKey)
	rsaPubKeysBytes := make([][]byte, 0)
	for _, pubKey := range thresholdSignerKey.CosignerKeys {
		publicBytes := x509.MarshalPKCS1PublicKey(pubKey)
		rsaPubKeysBytes = append(rsaPubKeysBytes, publicBytes)
	}

	protoPubkey, err := tmCryptoEncoding.PubKeyToProto(thresholdSignerKey.PubKey)
	if err != nil {
		return nil, err
	}

	protoBytes, err := protoPubkey.Marshal()
	if err != nil {
		return nil, err
	}

	return json.Marshal(&struct {
		RSAKey       []byte   `json:"rsa_key"`
		Pubkey       []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Pubkey:       protoBytes,
		RSAKey:       privateBytes,
		CosignerKeys: rsaPubKeysBytes,
		Alias:        (*Alias)(thresholdSignerKey),
	})
}

func (thresholdSignerKey *ThresholdSignerKey) UnmarshalJSON(data []byte) error {
	type Alias ThresholdSignerKey

	aux := &struct {
		RSAKey       []byte   `json:"rsa_key"`
		PubkeyBytes  []byte   `json:"pub_key"`
		CosignerKeys [][]byte `json:"rsa_pubs"`
		*Alias
	}{
		Alias: (*Alias)(thresholdSignerKey),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(aux.RSAKey)
	if err != nil {
		return err
	}

	var pubkey tmCrypto.PubKey
	var protoPubkey tmProtoCrypto.PublicKey
	err = protoPubkey.Unmarshal(aux.PubkeyBytes)

	// Prior to the tendermint protobuf migration, the public key bytes in key files
	// were encoded using the go-amino libraries via
	// cdc.MarshalBinaryBare(cosignerKey.PubKey)
	//
	// To support reading the public key bytes from these key files, we fallback to
	// amino unmarshalling if the protobuf unmarshalling fails
	if err != nil {
		var pub tmEd25519.PubKey
		codec := amino.NewCodec()
		codec.RegisterInterface((*tmCrypto.PubKey)(nil), nil)
		codec.RegisterConcrete(tmEd25519.PubKey{}, "tendermint/PubKeyEd25519", nil)
		errInner := codec.UnmarshalBinaryBare(aux.PubkeyBytes, &pub)
		if errInner != nil {
			return err
		}
		pubkey = pub
	} else {
		pubkey, err = tmCryptoEncoding.PubKeyFromProto(protoPubkey)
		if err != nil {
			return err
		}
	}

	// unmarshal the public key bytes for each cosigner
	thresholdSignerKey.CosignerKeys = make([]*rsa.PublicKey, 0)
	for _, bytes := range aux.CosignerKeys {
		cosignerRsaPubkey, err := x509.ParsePKCS1PublicKey(bytes)
		if err != nil {
			return err
		}
		thresholdSignerKey.CosignerKeys = append(thresholdSignerKey.CosignerKeys, cosignerRsaPubkey)
	}

	thresholdSignerKey.RSAKey = *privateKey
	thresholdSignerKey.PubKey = pubkey
	return nil
}

// LoadCosignerKey loads a CosignerKey from file.
func LoadCosignerKey(file string) (ThresholdSignerKey, error) {
	pvKey := ThresholdSignerKey{}
	keyJSONBytes, err := os.ReadFile(file)
	if err != nil {
		return pvKey, err
	}

	err = json.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return pvKey, err
	}

	return pvKey, nil
}
