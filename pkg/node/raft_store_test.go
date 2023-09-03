package node_test

import (
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/node"
	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

// Test_StoreInMemOpenSingleNode tests that a command can be applied to the log
// stored in RAM.
func Test_StoreInMemOpenSingleNode(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "store_test")
	defer os.RemoveAll(tmpDir)

	dummyPub := cometcryptoed25519.PubKey{}

	eciesKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
	require.NoError(t, err)

	key := pcosigner.CosignerEd25519Key{
		PubKey:       dummyPub,
		PrivateShard: []byte{},
		ID:           1,
	}

	cosigner := pcosigner.NewLocalCosigner(
		log.NewNopLogger(),
		&pcosigner.RuntimeConfig{},
		pcosigner.NewCosignerSecurityECIES(
			pcosigner.CosignerECIESKey{
				ID:        key.ID,
				ECIESKey:  eciesKey,
				ECIESPubs: []*ecies.PublicKey{&eciesKey.PublicKey},
			}),
		pcosigner.NewCosign(key.ID, ""),
	)

	remoteCosigns := make([]pcosigner.IRemoteCosigner, 0)
	remoteCosigns = append(remoteCosigns, pcosigner.NewRemoteCosigner(1, "temp"))
	shadowRemoteCosign := pcosigner.FromIRemoteToICosigner(remoteCosigns)
	//spew.Dump(&remoteCosigns)
	//spew.Dump(&shadowRemoteCosign)

	//fmt.Printf("remotecosign: %s \n", spew.Dump(&remoteCosigns))
	//fmt.Printf("shadowRemoteCosign: %v \n", spew.Dump(&shadowRemoteCosign))

	s := node.NewRaftStore("1", tmpDir, "127.0.0.1:0", 1*time.Second, log.NewNopLogger(), cosigner, shadowRemoteCosign)

	validator := node.NewThresholdValidator(log.NewNopLogger(), nil, 0, 1, 1, cosigner, remoteCosigns, s)

	s.SetThresholdValidator(validator)

	if _, err := s.Open(shadowRemoteCosign); err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	// Simple way to ensure there is a leader.
	time.Sleep(3 * time.Second)

	if err := s.Set("foo", "bar"); err != nil {
		t.Fatalf("failed to set key: %s", err.Error())
	}

	// Wait for committed log entry to be applied.
	time.Sleep(500 * time.Millisecond)
	value, err := s.Get("foo")
	if err != nil {
		t.Fatalf("failed to get key: %s", err.Error())
	}
	if value != "bar" {
		t.Fatalf("key has wrong value: %s", value)
	}

	if err := s.Delete("foo"); err != nil {
		t.Fatalf("failed to delete key: %s", err.Error())
	}

	// Wait for committed log entry to be applied.
	time.Sleep(500 * time.Millisecond)
	value, err = s.Get("foo")
	if err != nil {
		t.Fatalf("failed to get key: %s", err.Error())
	}
	if value != "" {
		t.Fatalf("key has wrong value: %s", value)
	}
}
