package signer

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	metrics "github.com/strangelove-ventures/horcrux/pkg/metrics"

	"github.com/hashicorp/raft"
	cosigner "github.com/strangelove-ventures/horcrux/pkg/cosigner"
	proto "github.com/strangelove-ventures/horcrux/pkg/proto"
	state "github.com/strangelove-ventures/horcrux/pkg/state"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/libs/log"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	rpcTypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	tm "github.com/tendermint/tendermint/types"

	// TODO: Refactor. This should be the responsibility of the thresholdsigner and/or the LocalSigner
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

type ThresholdValidator struct {
	threshold int

	pubkey crypto.PubKey

	// stores the last sign state for a block we have fully signed
	// Cached to respond to SignVote requests if we already have a signature
	lastSignState      state.SignState
	lastSignStateMutex sync.Mutex

	// stores the last sign state that we've started progress on
	lastSignStateInitiated      state.SignState
	lastSignStateInitiatedMutex sync.Mutex

	// our own cosigner
	cosigner cosigner.Cosigner

	// peer cosigners
	peers []cosigner.Cosigner

	raftStore *RaftStore

	logger log.Logger
}

type ThresholdValidatorOpt struct {
	Pubkey    crypto.PubKey
	Threshold int
	SignState state.SignState
	Cosigner  cosigner.Cosigner
	Peers     []cosigner.Cosigner
	RaftStore *RaftStore
	Logger    log.Logger
}

// NewThresholdValidator creates and returns a new ThresholdValidator
func NewThresholdValidator(opt *ThresholdValidatorOpt) *ThresholdValidator {
	validator := &ThresholdValidator{}
	validator.cosigner = opt.Cosigner
	validator.peers = opt.Peers
	validator.threshold = opt.Threshold
	validator.pubkey = opt.Pubkey
	validator.lastSignState = opt.SignState
	validator.lastSignStateMutex = sync.Mutex{}

	validator.lastSignStateInitiated = state.NewThresholdsignerSignState(
		opt.SignState.Height, opt.SignState.Round, opt.SignState.Step)

	validator.lastSignStateInitiatedMutex = sync.Mutex{}
	validator.raftStore = opt.RaftStore
	validator.logger = opt.Logger
	return validator
}

func (pv *ThresholdValidator) SaveLastSignedState(signState state.SignStateConsensus) error {
	return pv.lastSignState.Save(signState, &pv.lastSignStateMutex, true)
}

func (pv *ThresholdValidator) SaveLastSignedStateInitiated(signState state.SignStateConsensus) error {
	return pv.lastSignStateInitiated.Save(signState, &pv.lastSignStateInitiatedMutex, true)
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *ThresholdValidator) GetPubKey() (crypto.PubKey, error) {
	return pv.pubkey, nil
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignVote(chainID string, vote *tmProto.Vote) error {
	block := &Block{
		Height:    vote.Height,
		Round:     int64(vote.Round),
		Step:      state.VoteToStep(vote),
		Timestamp: vote.Timestamp,
		SignBytes: tm.VoteSignBytes(chainID, vote),
	}
	sig, stamp, err := pv.SignBlock(chainID, block)

	vote.Signature = sig
	vote.Timestamp = stamp

	return err
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *ThresholdValidator) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	block := &Block{
		Height:    proposal.Height,
		Round:     int64(proposal.Round),
		Step:      state.ProposalToStep(proposal),
		Timestamp: proposal.Timestamp,
		SignBytes: tm.ProposalSignBytes(chainID, proposal),
	}
	sig, stamp, err := pv.SignBlock(chainID, block)

	proposal.Signature = sig
	proposal.Timestamp = stamp

	return err
}

func (pv *ThresholdValidator) newBeyondBlockError(hrs state.HRSKey) *BeyondBlockError {
	return &BeyondBlockError{
		msg: fmt.Sprintf("Progress already started on block %d.%d.%d, skipping %d.%d.%d",
			pv.lastSignStateInitiated.Height, pv.lastSignStateInitiated.Round, pv.lastSignStateInitiated.Step,
			hrs.Height, hrs.Round, hrs.Step),
	}
}

func (pv *ThresholdValidator) waitForPeerEphemeralShares(
	peer cosigner.Cosigner,
	hrst state.HRSTKey,
	wg *sync.WaitGroup,
	encryptedEphemeralSharesThresholdMap *map[cosigner.Cosigner][]state.CosignerEphemeralSecretPart,
	thresholdPeersMutex *sync.Mutex,
) {
	peerStartTime := time.Now()
	ephemeralSecretParts, err := peer.GetEphemeralSecretParts(hrst)
	if err != nil {

		// Significant missing shares may lead to signature failure
		metrics.MissedEphemeralShares.WithLabelValues(peer.GetAddress()).Add(float64(1))
		metrics.TotalMissedEphemeralShares.WithLabelValues(peer.GetAddress()).Inc()
		pv.logger.Error("Error getting secret parts", "peer", peer.GetID(), "err", err)
		return
	}
	// Significant missing shares may lead to signature failure
	metrics.MissedEphemeralShares.WithLabelValues(peer.GetAddress()).Set(0)
	metrics.TimedCosignerEphemeralShareLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())

	// Check so that getEphemeralWaitGroup.Done is not called more than (threshold - 1) times which causes hardlock
	thresholdPeersMutex.Lock()
	if len(*encryptedEphemeralSharesThresholdMap) < pv.threshold-1 {
		(*encryptedEphemeralSharesThresholdMap)[peer] = ephemeralSecretParts.EncryptedSecrets
		defer wg.Done()
	}
	thresholdPeersMutex.Unlock()
}

func (pv *ThresholdValidator) waitForPeerSetEphemeralSharesAndSign(
	ourID int,
	peer cosigner.Cosigner,
	hrst state.HRSTKey,
	encryptedEphemeralSharesThresholdMap *map[cosigner.Cosigner][]state.CosignerEphemeralSecretPart,
	signBytes []byte,
	shareSignatures *[][]byte,
	shareSignaturesMutex *sync.Mutex,
	ephemeralPublic *[]byte,
	wg *sync.WaitGroup,
) {
	peerStartTime := time.Now()
	defer wg.Done()
	peerEphemeralSecretParts := make([]state.CosignerEphemeralSecretPart, 0, pv.threshold-1)
	for _, EncryptedSecrets := range *encryptedEphemeralSharesThresholdMap {
		for _, ephemeralSecretPart := range EncryptedSecrets {
			// if share is intended for peer, check to make sure source peer is included in threshold
			if ephemeralSecretPart.DestinationID == peer.GetID() {
				for thresholdPeer := range *encryptedEphemeralSharesThresholdMap {
					if thresholdPeer.GetID() == ephemeralSecretPart.SourceID {
						// source peer is included in threshold signature, include in sharing
						peerEphemeralSecretParts = append(peerEphemeralSecretParts, ephemeralSecretPart)
						break
					}
				}
				break
			}
		}
	}

	pv.logger.Debug("Number of eph parts for peer", "peer", peer.GetID(), "count", len(peerEphemeralSecretParts))

	peerID := peer.GetID()
	sigRes, err := peer.SetEphemeralSecretPartsAndSign(state.CosignerSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: peerEphemeralSecretParts,
		HRST:             hrst,
		SignBytes:        signBytes,
	})

	if err != nil {
		pv.logger.Error("Sign error", err.Error())
		return
	}

	metrics.TimedCosignerSignLag.WithLabelValues(peer.GetAddress()).Observe(time.Since(peerStartTime).Seconds())
	pv.logger.Debug(fmt.Sprintf("Received signature from %d", peerID))

	shareSignaturesMutex.Lock()
	defer shareSignaturesMutex.Unlock()

	peerIdx := peerID - 1
	(*shareSignatures)[peerIdx] = make([]byte, len(sigRes.Signature))
	copy((*shareSignatures)[peerIdx], sigRes.Signature)
	if peerID == ourID {
		*ephemeralPublic = sigRes.EphemeralPublic
	}
}

func (pv *ThresholdValidator) getExistingBlockSignature(block *Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes
	hrs := state.HRSKey{
		Height: height,
		Round:  round,
		Step:   step,
	}
	latestBlock, existingSignature := pv.lastSignState.GetFromCache(hrs, &pv.lastSignStateMutex)
	if existingSignature != nil {
		// If a proposal has already been signed for this HRS, return that
		if block.Step == state.StepPropose || bytes.Equal(signBytes, existingSignature.SignBytes) {
			return existingSignature.Signature, block.Timestamp, nil
		}
		if err := existingSignature.OnlyDifferByTimestamp(signBytes); err != nil {
			return nil, stamp, err
		}

		// only differ by timestamp, okay to sign again
		return nil, stamp, nil
	} else if latestBlock.Height > height ||
		(latestBlock.Height == height && latestBlock.Round > round) ||
		(latestBlock.Height == height && latestBlock.Round == round && latestBlock.Step > step) {
		return nil, stamp, pv.newBeyondBlockError(hrs)
	}
	return nil, stamp, newStillWaitingForBlockError(hrs)
}

func (pv *ThresholdValidator) SignBlock(chainID string, block *Block) ([]byte, time.Time, error) {
	height, round, step, stamp, signBytes := block.Height, block.Round, block.Step, block.Timestamp, block.SignBytes

	blocka := &state.Block{
		Height:    height,
		Round:     round,
		Step:      step,
		SignBytes: signBytes,
		Timestamp: stamp}

	timeStartSignBlock := time.Now()
	// Only the leader can execute this function. Followers can handle the requests,
	// but they just need to proxy the request to the raft leader
	// TODO: This seems to be one of the issues to decouple RAFT
	if pv.raftStore.raft == nil {
		return nil, stamp, errors.New("raft not yet initialized")
	}
	if pv.raftStore.raft.State() != raft.Leader {
		pv.logger.Debug("I am not the raft leader. Proxying request to the leader")
		metrics.TotalNotRaftLeader.Inc()
		signRes, err := pv.raftStore.LeaderSignBlock(state.CosignerSignBlockRequest{
			ChainID: chainID, Block: blocka})
		if err != nil {
			if _, ok := err.(*rpcTypes.RPCError); ok {
				rpcErrUnwrapped := err.(*rpcTypes.RPCError).Data
				// Need to return BeyondBlockError after proxy since the error type will be lost over RPC
				if len(rpcErrUnwrapped) > 33 && rpcErrUnwrapped[:33] == "Progress already started on block" {
					return nil, stamp, &BeyondBlockError{msg: rpcErrUnwrapped}
				}
			}
			return nil, stamp, err
		}
		return signRes.Signature, stamp, nil
	}

	metrics.TotalRaftLeader.Inc()
	pv.logger.Debug("I am the raft leader. Managing the sign process for this block")

	hrst := state.HRSTKey{
		Height:    height,
		Round:     round,
		Step:      step,
		Timestamp: stamp.UnixNano(),
	}

	// Keep track of the last block that we began the signing process for. Only allow one attempt per block
	if err := pv.SaveLastSignedStateInitiated(state.NewSignStateConsensus(height, round, step)); err != nil {
		switch err.(type) {
		case *state.SameHRSError:
			// Wait for last sign state signature to be the same block
			signAgain := false
			for i := 0; i < 100; i++ {
				existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(block)
				if sameBlockErr == nil {
					if existingSignature == nil {
						signAgain = true
						break
					}
					return existingSignature, existingTimestamp, nil
				}
				switch sameBlockErr.(type) {
				case *StillWaitingForBlockError:
					time.Sleep(10 * time.Millisecond)
					continue
				default:
					return nil, existingTimestamp, sameBlockErr
				}

			}
			if !signAgain {
				return nil, stamp, errors.New("timed out waiting for block signature from cluster")
			}
		default:
			existingSignature, existingTimestamp, sameBlockErr := pv.getExistingBlockSignature(block)
			if sameBlockErr == nil {
				return existingSignature, stamp, nil
			}
			return nil, existingTimestamp, pv.newBeyondBlockError(state.HRSKey{
				Height: height,
				Round:  round,
				Step:   step,
			})
		}
	}

	numPeers := len(pv.peers)
	total := uint8(numPeers + 1)
	getEphemeralWaitGroup := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	getEphemeralWaitGroup.Add(pv.threshold - 1)
	// Used to track how close we are to threshold

	ourID := pv.cosigner.GetID()

	encryptedEphemeralSharesThresholdMap := make(
		map[cosigner.Cosigner][]state.CosignerEphemeralSecretPart)
	thresholdPeersMutex := sync.Mutex{}

	for _, peer := range pv.peers {
		go pv.waitForPeerEphemeralShares(peer, hrst, &getEphemeralWaitGroup,
			&encryptedEphemeralSharesThresholdMap, &thresholdPeersMutex)
	}

	ourEphemeralSecretParts, err := pv.cosigner.GetEphemeralSecretParts(hrst)
	if err != nil {
		// Our ephemeral secret parts are required, cannot proceed
		return nil, stamp, err
	}

	// Wait for threshold cosigners to be complete
	// A cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&getEphemeralWaitGroup, 4*time.Second) {
		return nil, stamp, errors.New("timed out waiting for ephemeral shares")
	}

	thresholdPeersMutex.Lock()
	encryptedEphemeralSharesThresholdMap[pv.cosigner] = ourEphemeralSecretParts.EncryptedSecrets
	thresholdPeersMutex.Unlock()

	metrics.TimedSignBlockThresholdLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug("Have threshold peers")

	setEphemeralAndSignWaitGroup := sync.WaitGroup{}

	// Only wait until we have threshold sigs
	setEphemeralAndSignWaitGroup.Add(pv.threshold)

	// destination for share signatures
	shareSignatures := make([][]byte, total)

	// share sigs is updated by goroutines
	shareSignaturesMutex := sync.Mutex{}

	var ephemeralPublic []byte

	for peer := range encryptedEphemeralSharesThresholdMap {
		// set peerEphemeralSecretParts and sign in single rpc call.
		go pv.waitForPeerSetEphemeralSharesAndSign(ourID, peer, hrst, &encryptedEphemeralSharesThresholdMap,
			signBytes, &shareSignatures, &shareSignaturesMutex, &ephemeralPublic, &setEphemeralAndSignWaitGroup)
	}

	// Wait for threshold cosigners to be complete
	// A cosigner will either respond in time, or be cancelled with timeout
	if waitUntilCompleteOrTimeout(&setEphemeralAndSignWaitGroup, 4*time.Second) {
		return nil, stamp, errors.New("timed out waiting for peers to sign")
	}

	metrics.TimedSignBlockCosignerLag.Observe(time.Since(timeStartSignBlock).Seconds())
	pv.logger.Debug("Done waiting for cosigners, assembling signatures")

	// collect all valid responses into array of ids and signatures for the threshold lib
	sigIds := make([]int, 0)
	shareSigs := make([][]byte, 0)
	for idx, shareSig := range shareSignatures {
		if len(shareSig) == 0 {
			continue
		}
		sigIds = append(sigIds, idx+1)

		// we are ok to use the share signatures - complete boolean
		// prevents future concurrent access
		shareSigs = append(shareSigs, shareSig)
	}

	if len(sigIds) < pv.threshold {
		metrics.TotalInsufficientCosigners.Inc()
		return nil, stamp, errors.New("not enough co-signers")
	}

	// assemble into final signature
	combinedSig := tsed25519.CombineShares(total, sigIds, shareSigs)

	signature := ephemeralPublic
	signature = append(signature, combinedSig...)

	// verify the combined signature before saving to watermark
	if !pv.pubkey.VerifySignature(signBytes, signature) {
		metrics.TotalInvalidSignature.Inc()
		return nil, stamp, errors.New("combined signature is not valid")
	}

	newLss := state.SignStateConsensus{
		Height:    height,
		Round:     round,
		Step:      step,
		Signature: signature,
		SignBytes: signBytes,
	}
	// Err will be present if newLss is not above high watermark
	err = pv.lastSignState.Save(newLss, &pv.lastSignStateMutex, true)
	if err != nil {
		if _, isSameHRSError := err.(*state.SameHRSError); !isSameHRSError {
			return nil, stamp, err
		}
	}

	// Emit last signed state to cluster
	err = pv.raftStore.Emit(raftEventLSS, newLss)
	if err != nil {
		pv.logger.Error("Error emitting LSS", err.Error())
	}

	timeSignBlock := time.Since(timeStartSignBlock).Seconds()
	metrics.TimedSignBlockLag.Observe(timeSignBlock)

	return signature, stamp, nil
}

type Block struct {
	Height    int64
	Round     int64
	Step      int8
	SignBytes []byte
	Timestamp time.Time
}

func (block Block) toProto() *proto.Block {
	return &proto.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

func (block Block) ToProto() *proto.Block {
	return &proto.Block{
		Height:    block.Height,
		Round:     block.Round,
		Step:      int32(block.Step),
		SignBytes: block.SignBytes,
		Timestamp: block.Timestamp.UnixNano(),
	}
}

type BeyondBlockError struct {
	msg string
}

func (e *BeyondBlockError) Error() string { return e.msg }

type StillWaitingForBlockError struct {
	msg string
}

func (e *StillWaitingForBlockError) Error() string { return e.msg }

func newStillWaitingForBlockError(hrs state.HRSKey) *StillWaitingForBlockError {
	return &StillWaitingForBlockError{
		msg: fmt.Sprintf("Still waiting for block %d.%d.%d",
			hrs.Height, hrs.Round, hrs.Step),
	}
}

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
