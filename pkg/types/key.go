package types

import "github.com/strangelove-ventures/horcrux/pkg/cosigner/proto"

// COMMENT: Height Round Step Key to keep track of ...?
// HRSKey  (block-) Height, (consensus-) Round, (consensus-) Step
//   - Height: The height of the block that is being propose
//   - Round: The round of the consensus algorithm
//   - Step: The step of the consensus algorithm
//
// TODO: This should be generic eniugh to be used for other consensus/blockchains algorithms
type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

// HRSTKey Height Round Step Time to keep track of ....?
type HRSTKey struct {
	Height    int64
	Round     int64
	Step      int8
	Timestamp int64
}

// ToProto is a HRSTKey method that returns an *proto.HRST (i.e the address of)
func (hrst HRSTKey) ToProto() *proto.HRST {
	return &proto.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
	}
}

// Less is a HRSTKey method that return true if we are less than the other key
func (hrst *HRSTKey) Less(other HRSTKey) bool {
	if hrst.Height < other.Height {
		return true
	}

	if hrst.Height > other.Height {
		return false
	}

	// height is equal, check round

	if hrst.Round < other.Round {
		return true
	}

	if hrst.Round > other.Round {
		return false
	}

	// round is equal, check step

	if hrst.Step < other.Step {
		return true
	}

	// HRS is greater or equal
	return false
}

// HRSTKeyFromProto returns a HRSTKey from a proto.HRST
// TODO: Explain more
func HRSTKeyFromProto(hrs *proto.HRST) HRSTKey {
	return HRSTKey{
		Height:    hrs.GetHeight(),
		Round:     hrs.GetRound(),
		Step:      int8(hrs.GetStep()),
		Timestamp: hrs.GetTimestamp(),
	}
}
