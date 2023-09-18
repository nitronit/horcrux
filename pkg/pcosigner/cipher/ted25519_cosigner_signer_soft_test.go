package cipher_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
	"time"

	"math/big"

	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/strangelove-ventures/horcrux/pkg/pcosigner/cipher"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

func TestThresholdSignerSoft_GenerateNonces(t *testing.T) {
	type fields struct {
		privateKeyShard []byte
		pubKey          []byte
		threshold       uint8
		total           uint8
	}
	tests := []struct {
		name    string
		fields  fields
		want    cipher.Nonces
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := cipher.NewThresholdSignerSoft(
				tt.fields.privateKeyShard, tt.fields.pubKey, tt.fields.threshold, tt.fields.total)

			if (err != nil) != tt.wantErr {
				t.Errorf("ThresholdSignerSoft.NewThresholdSignerSoft() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := s.GenerateNonces()
			if (err != nil) != tt.wantErr {
				t.Errorf("ThresholdSignerSoft.GenerateNonces() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ThresholdSignerSoft.GenerateNonces() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Reverse(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	for i := len(dst)/2 - 1; i >= 0; i-- {
		opp := len(dst) - 1 - i
		dst[i], dst[opp] = dst[opp], dst[i]
	}

	return dst
}
func TestSignthreshold25519(test *testing.T) {
	// pack a vote into sign bytes
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = time.Now()

	message := comet.VoteSignBytes("chain-id", &vote)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)

	// persistentshares is the privateKey split into 3 shamir parts
	persistentshares := tsed25519.DealShares(tsed25519.ExpandSecret(privateKey.Seed()), 2, 3)

	// Double check Pubkey
	//persistentSharesPub1 := tsed25519.ScalarMultiplyBase(persistentshares[0])
	//persistentSharesPub2 := tsed25519.ScalarMultiplyBase(persistentshares[1])
	//persistentSharesPub3 := tsed25519.ScalarMultiplyBase(persistentshares[2])

	/////////////// Deal Ephermal Shares: /////////////////////////
	// each player generates secret Ri
	r1 := make([]byte, 32)
	_, err = rand.Read(r1)
	require.NoError(test, err)

	r2 := make([]byte, 32)
	_, err = rand.Read(r2)
	require.NoError(test, err)

	r3 := make([]byte, 32)
	_, err = rand.Read(r3)
	require.NoError(test, err)

	// R1, R2, R3
	pub1 := tsed25519.ScalarMultiplyBase(r1) // noncePub1
	pub2 := tsed25519.ScalarMultiplyBase(r2) // noncePub2
	pub3 := tsed25519.ScalarMultiplyBase(r3) // noncePub3

	// R=R1+R2+...Rn
	ephPublicKey := tsed25519.AddElements([]tsed25519.Element{pub1, pub2, pub3}) // R

	// each player split their ephermal secret per t,n, Rij by Shamir secret sharing
	dealer1 := tsed25519.DealShares(r1, 2, 3)
	dealer2 := tsed25519.DealShares(r2, 2, 3)
	dealer3 := tsed25519.DealShares(r3, 2, 3)

	// A=A1+A2+...An = A=s1⋅B+s2⋅B+...sn⋅B
	//publicKey2 := tsed25519.AddElements(
	//	[]tsed25519.Element{persistentSharesPub1, persistentSharesPub2, persistentSharesPub3})
	// require.Equal(test, publicKey, publicKey_2)

	// each player sends s(i)_{j} to corresponding other player j (i.e. s(1)_{2} to player 2)
	// each player sums all s(i)_{j}, i=1 ... n, j= self id to form their working secret
	ephShare1 := tsed25519.AddScalars([]tsed25519.Scalar{dealer1[0], dealer2[0], dealer3[0]}) // nonceShare1
	ephShare2 := tsed25519.AddScalars([]tsed25519.Scalar{dealer1[1], dealer2[1], dealer3[1]}) // nonceShare2
	ephShare3 := tsed25519.AddScalars([]tsed25519.Scalar{dealer1[2], dealer2[2], dealer3[2]}) // nonceShare3
	/*
		// ephShare1Pub := tsed25519.ScalarMultiplyBase(ephShare1)
		// ephShare2Pub := tsed25519.ScalarMultiplyBase(ephShare2)
		// ephShare3Pub := tsed25519.ScalarMultiplyBase(ephShare3)
		// ephSharePublicKey := tsed25519.AddElements([]tsed25519.Element{ephShare1Pub, ephShare2Pub, ephShare3Pub})


		_, _ = fmt.Printf("ephShare1Pub keys: %x\n", ephShare1Pub)
		_, _ = fmt.Printf("ephShare2Pub keys: %x\n", ephShare2Pub)
		_, _ = fmt.Printf("ephShare3Pub keys: %x\n", ephShare3Pub)
		_, _ = fmt.Printf("ephSharePublicKey keys: %x\n", ephSharePublicKey)
	*/
	_, _ = fmt.Printf("public keys: %x\n", publicKey)
	// _, _ = fmt.Printf("public keys: %x\n", publicKey2)
	_, err = fmt.Printf("eph public keys: %x\n", ephPublicKey)
	if err != nil {
		panic(err)
	}
	// End of Dealshares.

	var x, y, z big.Int
	x.SetBytes(persistentshares[0])
	y.SetBytes(ephShare1)
	z.Mul(&x, &y)
	testar := tsed25519.ScalarMultiplyBase(Reverse(z.Bytes()))
	_, err = fmt.Printf("testing keys: %x\n", testar)
	require.NoError(test, err)

	// fmt.Printf("eph secret: %x\n", ephemeralPublic)
	// k=H(R_i||pub||M) (mod l)
	// S_i = r_i + k* l_i * s_i (mod l)
	// k=H(ephPublicKey||publicKey||M) (mod l)
	//

	shareSig1 := tsed25519.SignWithShare(message, persistentshares[0], ephShare1, publicKey, ephPublicKey)
	shareSig2 := tsed25519.SignWithShare(message, persistentshares[1], ephShare2, publicKey, ephPublicKey)
	shareSig3 := tsed25519.SignWithShare(message, persistentshares[2], ephShare3, publicKey, ephPublicKey)

	{
		// signature[:32] == R
		combinedSig := tsed25519.CombineShares(3, []int{1, 2, 3}, [][]byte{shareSig1, shareSig2, shareSig3})
		var signature []byte
		signature = append(signature, ephPublicKey...)
		signature = append(signature, combinedSig...)
		_, _ = fmt.Printf("Signature: %x\n", signature)
		_, _ = fmt.Printf("Signature in String: %x\n", hex.EncodeToString(signature))
		_, _ = fmt.Printf("Signature: %t\n", ed25519.Verify(publicKey, message, signature))

		if !ed25519.Verify(publicKey, message, signature) {
			test.Error("Invalid Signature for signer [1,2,3]")
		}
	}
	{
		combinedSig := tsed25519.CombineShares(3, []int{1, 2}, [][]byte{shareSig1, shareSig2})
		var signature []byte
		signature = append(signature, ephPublicKey...)
		signature = append(signature, combinedSig...)
		if !ed25519.Verify(publicKey, message, signature) {
			test.Error("Invalid Signature for signer [1,2]")
		}
	}
	{
		combinedSig := tsed25519.CombineShares(3, []int{1}, [][]byte{shareSig1})
		var signature []byte
		signature = append(signature, ephPublicKey...)
		signature = append(signature, combinedSig...)
		if ed25519.Verify(publicKey, message, signature) {
			test.Error("Valid signature for signer [1]")
		}
	}
}

type keyPairWithShares struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	shares     []tsed25519.Scalar
}

func generateKeyPairWithShares(t *testing.T) keyPairWithShares {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return keyPairWithShares{
		publicKey:  publicKey,
		privateKey: privateKey,
		shares:     tsed25519.DealShares(tsed25519.ExpandSecret(privateKey.Seed()), 2, 3),
	}
}

func TestThreshold25519(t *testing.T) {
	// big.NewInt(0).MulRange(1, 3)
	delta := new(big.Int).MulRange(1, 3)
	orderL := new(big.Int).SetBits([]big.Word{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000})
	secret := big.NewInt(int64(29))

	_, _ = fmt.Printf("orderL : %s\n", orderL.String())
	_, _ = fmt.Printf("Secret : %s\n", secret.String())
	_, _ = fmt.Printf("delta : %s\n", delta.String())
	// delta * X (mod OrderL) = 1
	// X * secret (mod OrderL)
	delta.ModInverse(delta, orderL) // delta * X (mod OrderL) = 1
	_, _ = fmt.Printf("X : %s\n", delta.String())
	secret.Mul(secret, delta) //
	_, _ = fmt.Printf("Secret*Delta : %s\n", secret.String())
	secret.Mod(secret, orderL)
	_, _ = fmt.Printf("Secret mod orderL : %s\n", secret.String())

}

// pack a vote into sign bytes
/*
	var vote cometproto.Vote
	vote.Height = 1
	vote.Round = 0
	vote.Type = cometproto.PrevoteType
	vote.Timestamp = time.Now()

	message := comet.VoteSignBytes("chain-id", &vote)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyPair := generateKeyPairWithShares(t)
	ephKeyPair := generateKeyPairWithShares(t)

	shareSig1 := SignWithShare(message, keyPair.shares[0], ephKeyPair.shares[0], keyPair.publicKey, ephKeyPair.publicKey)
	shareSig2 := SignWithShare(message, keyPair.shares[1], ephKeyPair.shares[1], keyPair.publicKey, ephKeyPair.publicKey)
	shareSig3 := SignWithShare(message, keyPair.shares[2], ephKeyPair.shares[2], keyPair.publicKey, ephKeyPair.publicKey)

}
*/
