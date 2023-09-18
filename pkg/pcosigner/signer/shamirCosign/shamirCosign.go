package shamircosign

import (
	"errors"
	logg "log"
	"runtime"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/pcosigner/cipher"

	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/strangelove-ventures/horcrux/pkg/metrics"
)

func waitUntilCompleteOrTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

type ShamirCosign struct {
	LocalCosign   pcosigner.ILocalCosigner    // Server: The "Cosigner's" LocalCosigner
	PeerCosigners []pcosigner.IRemoteCosigner // Client: The "Cosigner's" RemoteCosigners
	logger        log.Logger
	pendingDiskWG sync.WaitGroup
}

func NewShamirCosign(
	logger log.Logger, myCosigner pcosigner.ILocalCosigner, peerCosigners []pcosigner.IRemoteCosigner) *ShamirCosign {
	return &ShamirCosign{
		logger:        logger,
		LocalCosign:   myCosigner,
		PeerCosigners: peerCosigners,
	}
}

// waitForSignStatesToFlushToDisk waits for any sign states to finish writing to disk.
func (s *ShamirCosign) WaitForSignStatesToFlushToDisk() {
	s.pendingDiskWG.Wait()

	s.LocalCosign.WaitForSignStatesToFlushToDisk()
}

func (s *ShamirCosign) waitForPeerSetNoncesAndSign(
	chainID string,
	peer pcosigner.IRemoteCosigner,
	hrst types.HRSTKey,
	noncesMap map[pcosigner.IRemoteCosigner][]pcosigner.CosignNonce,
	signBytes []byte,
	shareSignatures *[][]byte,
	shareSignaturesMutex *sync.Mutex,
	wg *sync.WaitGroup,
	threshold int,
) {
	peerStartTime := time.Now()
	defer wg.Done()
	peerNonces := make([]pcosigner.CosignNonce, 0, threshold-1)

	peerID := peer.GetID()

	for _, nonces := range noncesMap {
		for _, nonce := range nonces {
			// if share is intended for peer, check to make sure source peer is included in threshold
			if nonce.DestinationID != peerID {
				continue
			}
			for thresholdPeer := range noncesMap {
				if thresholdPeer.GetID() != nonce.SourceID {
					continue
				}
				// source peer is included in threshold signature, include in sharing
				peerNonces = append(peerNonces, nonce)
				break
			}
			break
		}
	}

	sigRes, err := peer.SetNoncesAndSign(pcosigner.CosignerSetNoncesAndSignRequest{
		ChainID:   chainID,
		Nonces:    peerNonces,
		HRST:      hrst,
		SignBytes: signBytes,
	})

	if err != nil {
		s.logger.Error(
			"Cosigner failed to set nonces and sign",
			"id", peerID,
			"err", err.Error(),
		)
		return
	}

	metrics.TimedCosignerSignLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
	s.logger.Debug(
		"ShamirCosign received signature part",
		"cosigner", peerID,
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)
	shareSignaturesMutex.Lock()
	defer shareSignaturesMutex.Unlock()

	peerIdx := peerID - 1
	(*shareSignatures)[peerIdx] = make([]byte, len(sigRes.Signature))
	copy((*shareSignatures)[peerIdx], sigRes.Signature)
}
func (s *ShamirCosign) GetLocalCosign() pcosigner.ILocalCosigner {
	return s.LocalCosign
}
func (s *ShamirCosign) GetPeers() []pcosigner.IRemoteCosigner {
	return s.PeerCosigners
}
func (s *ShamirCosign) LoadSignStateIfNecessary(chainID string) error {
	return s.LocalCosign.LoadSignStateIfNecessary(chainID)
}
func (s *ShamirCosign) SaveLastSignedState(chainID string, signStateConsensus types.SignStateConsensus) error {
	return s.LocalCosign.SaveLastSignedState(chainID, signStateConsensus)
}
func (s *ShamirCosign) SignAndVerify(
	chainID string, threshold int, hrst types.HRSTKey, grpcTimeout time.Duration, stamp time.Time, timeStartSignBlock time.Time, signBytes []byte) ([]byte, bool, error) {
	signature, _, err := s.sign(chainID, threshold, hrst, grpcTimeout, stamp, timeStartSignBlock, signBytes)
	if err != nil {
		// TODO Delete
		_, filename, line, _ := runtime.Caller(1)
		logg.Printf("sign [error] %s:%d %v", filename, line, err)
		return nil, false, err
	}
	verified, err := s.verify(chainID, signBytes, signature)
	if err != nil {
		return signature, false, err
	}
	return signature, verified, err
}

func (s *ShamirCosign) sign(
	chainID string, threshold int, hrst types.HRSTKey, grpcTimeout time.Duration,
	stamp time.Time, timeStartSignBlock time.Time, signBytes []byte) ([]byte, time.Time, error) {
	numPeers := len(s.PeerCosigners)
	total := uint8(numPeers + 1)
	getEphemeralWaitGroup := sync.WaitGroup{}

	// Only wait until we have enough threshold signatures
	getEphemeralWaitGroup.Add(threshold - 1)
	// Used to track how close we are to threshold

	// Here the actual signing process starts from a cryptological perspective
	// TODO: This process should be factored out. It is not the responsibility of the validator to know
	// how to arrange signature of a block. It should be a separate component that is injected into the validator.
	nonces := make(map[pcosigner.IRemoteCosigner][]pcosigner.CosignNonce)
	thresholdPeersMutex := sync.Mutex{}

	// From each cosigner peer we are requesting the nonce.
	// This is done asynchronously.
	// pv.waitForPeersNonces uses GRPC to get the nonce from the peer.

	for _, c := range s.PeerCosigners {
		// spew.Dump(c)
		go s.waitForPeerNonces(chainID, c, hrst, &getEphemeralWaitGroup,
			nonces, &thresholdPeersMutex, threshold)
	}

	// Requesting a nonce from our own cosigner (a.k.a. the local cosigner)
	myNonces, err := s.LocalCosign.GetNonces(chainID, hrst)
	if err != nil {
		s.logger.Error("Error getting nonces", "chainID", chainID, "err", err)
		// TODO: pv.notifyBlockSignError(chainID, block.HRSKey())
		// Our ephemeral secret parts are required, cannot proceed
		return nil, stamp, err
	}

	// Wait for cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout

	if waitUntilCompleteOrTimeout(&getEphemeralWaitGroup, grpcTimeout) {
		s.logger.Error("Error waitUntilCompleteOrTimeout", "chainID", chainID, "err", err)
		// TODO: pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("timed out waiting for ephemeral shares")
	}

	thresholdPeersMutex.Lock()
	nonces[s.LocalCosign] = myNonces.Nonces
	thresholdPeersMutex.Unlock()

	metrics.TimedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())
	s.logger.Debug(
		"Have threshold peers",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)
	setEphemeralAndSignWaitGroup := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	setEphemeralAndSignWaitGroup.Add(threshold)

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	for cosigner := range nonces {
		// set peerNonces and sign in single rpc call in parallel using goroutines
		// go
		s.waitForPeerSetNoncesAndSign(chainID, cosigner, hrst, nonces,
			signBytes, &shareSignatures, &shareSignaturesMutex, &setEphemeralAndSignWaitGroup, threshold)
	}

	// Wait for threshold cosigners to be complete
	// A Cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&setEphemeralAndSignWaitGroup, 4*time.Second) {
		// pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("timed out waiting for peers to sign")
	}

	metrics.TimedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())
	s.logger.Debug(
		"Done waiting for cosigners, assembling signatures",
		"chain_id", chainID,
		"height", hrst.Height,
		"round", hrst.Round,
		"step", hrst.Step,
	)
	// collect all valid responses into array of partial signatures
	shareSigs := make([]cipher.PartialSignature, 0, threshold)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, cipher.PartialSignature{
			ID:        idx + 1,
			Signature: shareSig,
		})
	}
	if len(shareSigs) < threshold {
		metrics.TotalInsufficientCosigners.Inc()
		// pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, errors.New("not enough co-signers")
	}
	// assemble the partial signatures into a valid signature
	signature, err := s.LocalCosign.CombineSignatures(chainID, shareSigs)
	if err != nil {
		// pv.notifyBlockSignError(chainID, block.HRSKey())
		return nil, stamp, err
	}
	return signature, stamp, nil
}
func (s *ShamirCosign) verify(chainID string, signBytes []byte, signature []byte) (bool, error) {
	verified := s.LocalCosign.VerifySignature(chainID, signBytes, signature)
	return verified, nil
}

func (s *ShamirCosign) GetPubKey(chainID string) (crypto.PubKey, error) {
	return s.LocalCosign.GetPubKey(chainID)
}

func (s *ShamirCosign) waitForPeerNonces(
	chainID string,
	peer pcosigner.IRemoteCosigner,
	hrst types.HRSTKey,
	wg *sync.WaitGroup,
	nonces map[pcosigner.IRemoteCosigner][]pcosigner.CosignNonce,
	thresholdPeersMutex *sync.Mutex,
	threshold int,
) {
	peerStartTime := time.Now()
	peerNonces, err := peer.GetNonces(chainID, hrst)
	if err != nil {
		// Significant missing shares may lead to signature failure
		metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Add(float64(1))
		metrics.TotalMissedNonces.WithLabelValues(peer.GetAddress()).Inc()
		s.logger.Error("Error getting nonces", "cosigner", peer.GetID(), "err", err)
		return
	}
	// Significant missing shares may lead to signature failure
	metrics.MissedNonces.WithLabelValues(peer.GetAddress()).Set(0)
	metrics.TimedCosignerNonceLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

	// Check so that wg.Done is not called more than (threshold - 1) times which causes hardlock
	thresholdPeersMutex.Lock()
	if len(nonces) < threshold-1 {
		nonces[peer] = peerNonces.Nonces
		defer wg.Done()
	}
	thresholdPeersMutex.Unlock()
}
