package state

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/gogo/protobuf/proto"
	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/libs/protoio"
	"github.com/tendermint/tendermint/libs/tempfile"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

const (
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
	blocksToCache      = 3
)

const StepPropose int8 = 1

func CanonicalVoteToStep(vote *tmproto.CanonicalVote) int8 {
	switch vote.Type {
	case tmproto.PrevoteType:
		return stepPrevote
	case tmproto.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func VoteToStep(vote *tmproto.Vote) int8 {
	switch vote.Type {
	case tmproto.PrevoteType:
		return stepPrevote
	case tmproto.PrecommitType:
		return stepPrecommit
	default:
		panic("Unknown vote type")
	}
}

func ProposalToStep(_ *tmproto.Proposal) int8 {
	return stepPropose
}

// SignState stores signing information for high level watermark management.
type SignState struct {
	Height          int64            `json:"height"`
	Round           int64            `json:"round"`
	Step            int8             `json:"step"`
	EphemeralPublic []byte           `json:"ephemeral_public"`
	Signature       []byte           `json:"signature,omitempty"`
	SignBytes       tmbytes.HexBytes `json:"signbytes,omitempty"`
	cache           map[HRSKey]SignStateConsensus

	filePath string // `json:"filepath"`
}

type SignStateConsensus struct {
	// TODO: Ask why we dont use HRS anonuymus fields.
	Height    int64
	Round     int64
	Step      int8
	Signature []byte
	SignBytes tmbytes.HexBytes
}

func NewSignStateConsensus(height int64, round int64, step int8) SignStateConsensus {
	return SignStateConsensus{
		Height: height,
		Round:  round,
		Step:   step,
	}
}

// Creates a new Thresholdsigner Sign State
func NewThresholdsignerSignState(height int64, round int64, step int8) SignState {
	return SignState{
		Height:   height,
		Round:    round,
		Step:     step,
		filePath: "none",
		cache:    make(map[HRSKey]SignStateConsensus),
	}
}

type ConflictingDataError struct {
	msg string
}

func (e *ConflictingDataError) Error() string { return e.msg }

func newConflictingDataError(existingSignBytes, newSignBytes []byte) *ConflictingDataError {
	return &ConflictingDataError{
		msg: fmt.Sprintf("conflicting data. existing: %s - new: %s",
			hex.EncodeToString(existingSignBytes), hex.EncodeToString(newSignBytes)),
	}
}

func (signState *SignState) GetFromCache(hrs HRSKey, lock *sync.Mutex) (HRSKey, *SignStateConsensus) {
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	latestBlock := HRSKey{
		Height: signState.Height,
		Round:  signState.Round,
		Step:   signState.Step,
	}
	if ssc, ok := signState.cache[hrs]; ok {
		return latestBlock, &ssc
	}
	return latestBlock, nil
}

func (signState *SignState) Save(ssc SignStateConsensus, lock *sync.Mutex, async bool) error {
	// One lock/unlock for less/equal check and mutation.
	// Setting nil for lock for getErrorIfLessOrEqual to avoid recursive lock
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}

	err := signState.GetErrorIfLessOrEqual(ssc.Height, ssc.Round, ssc.Step, nil)
	if err != nil {
		return err
	}
	// HRS is greater than existing state, allow

	signState.cache[HRSKey{Height: ssc.Height, Round: ssc.Round, Step: ssc.Step}] = ssc
	for hrs := range signState.cache {
		if hrs.Height < ssc.Height-blocksToCache {
			delete(signState.cache, hrs)
		}
	}

	signState.Height = ssc.Height
	signState.Round = ssc.Round
	signState.Step = ssc.Step
	signState.Signature = ssc.Signature
	signState.SignBytes = ssc.SignBytes
	if async {
		go func() {
			signState.save()
		}()
	} else {
		signState.save()
	}

	return nil
}

// Save persists the FilePvLastSignState to its filePath.
func (signState *SignState) save() {
	outFile := signState.filePath
	if outFile == "none" {
		return
	}
	if outFile == "" {
		panic("cannot save SignState: filePath not set")
	}
	// TODO: ERAse this: fmt.Println("signState:", signState)
	jsonBytes, err := tmjson.MarshalIndent(signState, "", "  ")
	if err != nil {
		// TODO: ERAse this:.Println("Some json error:\n\t", err)
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0600)
	if err != nil {
		fmt.Println("Tempfile error")
		panic(err)
	}
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// SignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// Returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (signState *SignState) CheckHRS(hrst HRSTKey) (bool, error) {
	if signState.Height > hrst.Height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", hrst.Height, signState.Height)
	}

	if signState.Height == hrst.Height {
		if signState.Round > hrst.Round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v",
				hrst.Height, hrst.Round, signState.Round)
		}

		if signState.Round == hrst.Round {
			if signState.Step > hrst.Step {
				return false, fmt.Errorf("step regression at height %v round %v. Got %v, last step %v",
					hrst.Height, hrst.Round, hrst.Step, signState.Step)
			} else if signState.Step == hrst.Step {
				if signState.SignBytes != nil {
					if signState.Signature == nil {
						panic("pv: Signature is nil but SignBytes is not!")
					}
					return true, nil
				}
				return false, errors.New("no SignBytes found")
			}
		}
	}
	return false, nil
}

type SameHRSError struct {
	msg string
}

func (e *SameHRSError) Error() string { return e.msg }

func newSameHRSError(hrs HRSKey) *SameHRSError {
	return &SameHRSError{
		msg: fmt.Sprintf("HRS is the same as current: %d:%d:%d", hrs.Height, hrs.Round, hrs.Step),
	}
}

func (signState *SignState) GetErrorIfLessOrEqual(height int64, round int64, step int8, lock *sync.Mutex) error {
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	if height < signState.Height {
		// lower height than current, don't allow state rollback
		return errors.New("height regression not allowed")
	}
	if height > signState.Height {
		return nil
	}
	// Height is equal

	if round < signState.Round {
		// lower round than current round for same block, don't allow state rollback
		return errors.New("round regression not allowed")
	}
	if round > signState.Round {
		return nil
	}
	// Height and Round are equal

	if step < signState.Step {
		// lower round than current round for same block, don't allow state rollback
		return errors.New("step regression not allowed")
	}
	if step == signState.Step {
		// same HRS as current
		return newSameHRSError(HRSKey{Height: height, Round: round, Step: step})
	}
	// Step is greater, so all good
	return nil
}

// LoadSignState loads a sign state from disk.
func LoadSignState(filepath string) (SignState, error) {
	state := SignState{}
	stateJSONBytes, err := os.ReadFile(filepath)
	if err != nil {
		return state, err
	}

	err = tmjson.Unmarshal(stateJSONBytes, &state)
	if err != nil {
		return state, err
	}
	state.cache = make(map[HRSKey]SignStateConsensus)
	state.cache[HRSKey{Height: state.Height, Round: state.Round, Step: state.Step}] = SignStateConsensus{
		Height:    state.Height,
		Round:     state.Round,
		Step:      state.Step,
		Signature: state.Signature,
		SignBytes: state.SignBytes,
	}
	state.filePath = filepath
	return state, nil
}

// LoadOrCreateSignState loads the sign state from filepath
// If the sign state could not be loaded, an empty sign state is initialized
// and saved to filepath.
func LoadOrCreateSignState(filepath string) (SignState, error) {
	existing, err := LoadSignState(filepath)
	if err == nil {
		return existing, nil
	}

	// There was an error loading the sign state
	// Make an empty sign state and save it
	fmt.Println("There was an error loading the sign state. Instead we create an empty state and save it")
	fmt.Println("filepath:", filepath)
	state := SignState{}
	state.filePath = filepath
	state.cache = make(map[HRSKey]SignStateConsensus)
	state.save()
	fmt.Println("state is: ", state)
	return state, nil
}

// OnlyDifferByTimestamp returns true if the sign bytes of the sign state
// are the same as the new sign bytes excluding the timestamp.
func (signState *SignState) OnlyDifferByTimestamp(signBytes []byte) error {
	return onlyDifferByTimestamp(signState.Step, signState.SignBytes, signBytes)
}

func (signState *SignStateConsensus) OnlyDifferByTimestamp(signBytes []byte) error {
	return onlyDifferByTimestamp(signState.Step, signState.SignBytes, signBytes)
}

func onlyDifferByTimestamp(step int8, signStateSignBytes, signBytes []byte) error {
	if step == stepPropose {
		return checkProposalOnlyDifferByTimestamp(signStateSignBytes, signBytes)
	} else if step == stepPrevote || step == stepPrecommit {
		return checkVoteOnlyDifferByTimestamp(signStateSignBytes, signBytes)
	}

	return fmt.Errorf("unexpected sign step: %d", step)
}

func checkVoteOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) error {
	var lastVote, newVote tmproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		return fmt.Errorf("lastSignBytes cannot be unmarshalled into vote: %v", err)
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		return fmt.Errorf("signBytes cannot be unmarshalled into vote: %v", err)
	}

	// set the times to the same value and check equality
	newVote.Timestamp = lastVote.Timestamp

	isEqual := proto.Equal(&newVote, &lastVote)

	if !isEqual {
		lastVoteBlockID := lastVote.GetBlockID()
		newVoteBlockID := newVote.GetBlockID()
		if newVoteBlockID == nil && lastVoteBlockID != nil {
			return errors.New("already signed vote with non-nil BlockID. refusing to sign vote on nil BlockID")
		}
		if newVoteBlockID != nil && lastVoteBlockID == nil {
			return errors.New("already signed vote with nil BlockID. refusing to sign vote on non-nil BlockID")
		}
		if !bytes.Equal(lastVoteBlockID.GetHash(), newVoteBlockID.GetHash()) {
			return fmt.Errorf("differing block IDs - last Vote: %s, new Vote: %s",
				lastVoteBlockID.GetHash(), newVoteBlockID.GetHash())
		}
		return newConflictingDataError(lastSignBytes, newSignBytes)
	}

	return nil
}

func checkProposalOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) error {
	var lastProposal, newProposal tmproto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		return fmt.Errorf("lastSignBytes cannot be unmarshalled into proposal: %v", err)
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		return fmt.Errorf("signBytes cannot be unmarshalled into proposal: %v", err)
	}

	// set the times to the same value and check equality
	newProposal.Timestamp = lastProposal.Timestamp

	isEqual := proto.Equal(&newProposal, &lastProposal)

	if !isEqual {
		return newConflictingDataError(lastSignBytes, newSignBytes)
	}

	return nil
}
