package signer

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
	"github.com/strangelove-ventures/horcrux/pkg/cosigner"
	proto "github.com/strangelove-ventures/horcrux/pkg/cosigner/proto"
	"github.com/strangelove-ventures/horcrux/pkg/types"
)

type GRPCServer struct {
	cosigner           cosigner.ILocalCosigner
	thresholdValidator *ThresholdValidator
	raftStore          *RaftStore
	// TODO: Change the proto files to be named UnimplementedGRPCServer
	proto.UnimplementedGRPCServer // embedding UnimplementedGRPCServer
}

func (rpc *GRPCServer) SignBlock(
	ctx context.Context, req *proto.GRPCSignBlockRequest) (*proto.GRPCSignBlockResponse, error) {
	block := &types.Block{
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
	return &proto.GRPCSignBlockResponse{
		Signature: res,
	}, nil
}

func (rpc *GRPCServer) SetEphemeralSecretPartsAndSign(
	ctx context.Context,
	req *proto.GRPCSetEphemeralSecretPartsAndSignRequest,
) (*proto.GRPCSetEphemeralSecretPartsAndSignResponse, error) {
	res, err := rpc.cosigner.SetEphemeralSecretPartsAndSign(types.CosignerSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: types.CosignerEphemeralSecretPartsFromProto(req.GetEncryptedSecrets()),
		HRST:             types.HRSTKeyFromProto(req.GetHrst()),
		SignBytes:        req.GetSignBytes(),
	})
	if err != nil {
		rpc.raftStore.logger.Error("Failed to sign with share", "error", err)
		return nil, err
	}
	rpc.raftStore.logger.Info("Signed with share",
		"height", req.Hrst.Height,
		"round", req.Hrst.Round,
		"step", req.Hrst.Step,
	)
	return &proto.GRPCSetEphemeralSecretPartsAndSignResponse{
		EphemeralPublic: res.EphemeralPublic,
		Timestamp:       res.Timestamp.UnixNano(),
		Signature:       res.Signature,
	}, nil
}

func (rpc *GRPCServer) GetEphemeralSecretParts(
	ctx context.Context,
	req *proto.GRPCGetEphemeralSecretPartsRequest,
) (*proto.GRPCGetEphemeralSecretPartsResponse, error) {
	res, err := rpc.cosigner.GetEphemeralSecretParts(types.HRSTKeyFromProto(req.GetHrst()))
	if err != nil {
		return nil, err
	}
	return &proto.GRPCGetEphemeralSecretPartsResponse{
		EncryptedSecrets: types.CosignerEphemeralSecretParts(res.EncryptedSecrets).ToProto(),
	}, nil
}

// TransferLeadership transfers leadership to the given peer ID or to the next candidate if no ID is given.
func (rpc *GRPCServer) TransferLeadership(
	ctx context.Context,
	req *proto.GRPCTransferLeadershipRequest,
) (*proto.GRPCTransferLeadershipResponse, error) {
	leaderID := req.GetLeaderID()
	// FIXME: When is leaderID != "" ever not the case?
	if leaderID != "" {
		for _, peer := range rpc.raftStore.Peers {
			thisPeerID := fmt.Sprint(peer.GetID())
			if thisPeerID == leaderID {
				peerRaftAddress := p2pURLToRaftAddress(peer.GetAddress())
				// FIXME: This should maybe be a logging statement
				rpc.raftStore.logger.Info("Transferring leadership to:",
					"id", thisPeerID,
					"address", peerRaftAddress)
				rpc.raftStore.raft.LeadershipTransferToServer(raft.ServerID(thisPeerID), raft.ServerAddress(peerRaftAddress))
				return &proto.GRPCTransferLeadershipResponse{LeaderID: thisPeerID, LeaderAddress: peerRaftAddress}, nil
			}
		}
	}
	rpc.raftStore.logger.Info("Transferring leadership to next candidate")
	rpc.raftStore.raft.LeadershipTransfer()
	return &proto.GRPCTransferLeadershipResponse{}, nil
}

func (rpc *GRPCServer) GetLeader(
	ctx context.Context,
	req *proto.GRPCGetLeaderRequest,
) (*proto.GRPCGetLeaderResponse, error) {
	leader := rpc.raftStore.GetLeader()
	return &proto.GRPCGetLeaderResponse{Leader: string(leader)}, nil
}
