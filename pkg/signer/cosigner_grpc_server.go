package signer

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/pkg/cosigner"
	proto "github.com/strangelove-ventures/horcrux/pkg/proto"
	state "github.com/strangelove-ventures/horcrux/pkg/state"
)

type CosignerGRPCServer struct {
	cosigner                              *cosigner.LocalCosigner
	thresholdValidator                    *ThresholdValidator
	raftStore                             *RaftStore
	proto.UnimplementedCosignerGRPCServer // embedding UnimplementedCosignerGRPCServer
}

func (rpc *CosignerGRPCServer) SignBlock(
	ctx context.Context, req *proto.CosignerGRPCSignBlockRequest) (*proto.CosignerGRPCSignBlockResponse, error) {
	block := &Block{
		Height:    req.Block.GetHeight(),
		Round:     req.Block.GetRound(),
		Step:      int8(req.Block.GetStep()),
		SignBytes: req.Block.GetSignBytes(),
		Timestamp: time.Unix(0, req.Block.GetTimestamp()),
	}
	res, _, err := rpc.thresholdValidator.SignBlock(req.ChainID, block)
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCSignBlockResponse{
		Signature: res,
	}, nil
}

// implements CosignerGRPCServer interface in proto
func (rpc *CosignerGRPCServer) SetEphemeralSecretPartsAndSign(
	ctx context.Context,
	req *proto.CosignerGRPCSetEphemeralSecretPartsAndSignRequest,
) (*proto.CosignerGRPCSetEphemeralSecretPartsAndSignResponse, error) {
	res, err := rpc.cosigner.SetEphemeralSecretPartsAndSign(state.CosignerSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: state.CosignerEphemeralSecretPartsFromProto(req.GetEncryptedSecrets()),
		HRST:             state.HRSTKeyFromProto(req.GetHrst()),
		SignBytes:        req.GetSignBytes(),
	})
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCSetEphemeralSecretPartsAndSignResponse{
		EphemeralPublic: res.EphemeralPublic,
		Timestamp:       res.Timestamp.UnixNano(),
		Signature:       res.Signature,
	}, nil
}

// implements CosignerGRPCServer interface in proto
func (rpc *CosignerGRPCServer) GetEphemeralSecretParts(
	ctx context.Context,
	req *proto.CosignerGRPCGetEphemeralSecretPartsRequest,
) (*proto.CosignerGRPCGetEphemeralSecretPartsResponse, error) {
	res, err := rpc.cosigner.GetEphemeralSecretParts(state.HRSTKeyFromProto(req.GetHrst()))
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCGetEphemeralSecretPartsResponse{
		EncryptedSecrets: state.CosignerEphemeralSecretParts(res.EncryptedSecrets).ToProto(),
	}, nil
}

// implements CosignerGRPCServer interface in proto
func (rpc *CosignerGRPCServer) TransferLeadership(
	ctx context.Context,
	req *proto.CosignerGRPCTransferLeadershipRequest,
) (*proto.CosignerGRPCTransferLeadershipResponse, error) {
	leaderID := req.GetLeaderID()
	if leaderID != "" {
		for _, peer := range rpc.raftStore.Peers {
			thisPeerID := fmt.Sprint(peer.GetID())
			if thisPeerID == leaderID {
				peerRaftAddress := p2pURLToRaftAddress(peer.GetAddress())
				fmt.Printf("Transferring leadership to ID: %s - Address: %s\n", thisPeerID, peerRaftAddress)
				// TODO: Abstract out this so it takes itself instead of a raft function
				rpc.raftStore.raft.LeadershipTransferToServer(raft.ServerID(thisPeerID), raft.ServerAddress(peerRaftAddress))
				return &proto.CosignerGRPCTransferLeadershipResponse{LeaderID: thisPeerID, LeaderAddress: peerRaftAddress}, nil
			}
		}
	}
	fmt.Printf("Transferring leadership to next candidate\n")
	rpc.raftStore.raft.LeadershipTransfer()
	return &proto.CosignerGRPCTransferLeadershipResponse{}, nil
}
