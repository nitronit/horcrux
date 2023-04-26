package signer

import (
	"sync"

	"github.com/tendermint/tendermint/crypto"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

// PvGuard guards access to an underlying PrivValidator by using mutexes
// for each of the PrivValidator interface functions
// Basically embedding the "local" threshold validator/signer at each node
// into tendermint
type PvGuard struct {
	PrivValidator tm.PrivValidator // embeds the local threshold validator via interface
	pvMutex       sync.Mutex
}

// GetPubKey implements tn.types.PrivValidator
func (pv *PvGuard) GetPubKey() (crypto.PubKey, error) {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.GetPubKey()
}

// SignVote implements tm.types.PrivValidator
func (pv *PvGuard) SignVote(chainID string, vote *tmProto.Vote) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignVote(chainID, vote)
}

// SignProposal implements tm.types.PrivValidator
func (pv *PvGuard) SignProposal(chainID string, proposal *tmProto.Proposal) error {
	pv.pvMutex.Lock()
	defer pv.pvMutex.Unlock()
	return pv.PrivValidator.SignProposal(chainID, proposal)
}
