// This is responsible for the Cosigners Connections.
package node

import (
	"context"
	"fmt"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"
	"github.com/strangelove-ventures/horcrux/pkg/types"

	"github.com/hashicorp/raft"

	"github.com/strangelove-ventures/horcrux/pkg/proto"
	proto2 "github.com/strangelove-ventures/horcrux/pkg/proto"
)

// Enures that GRPCServer implements the proto.CosignerGRPCServer interface.
var _ proto.ICosignerGRPCServer = &GRPCServer{}
var _ proto2.IRaftGRPCServer = &GRPCServer{}

// TODO Implement as

type CosignGRPCServer struct {
	cosigner pcosigner.ILocalCosigner

	logger log.Logger
	proto.UnimplementedICosignerGRPCServer
	// Promoted Fields is embedded to have forward compatiblitity
}

type RaftGRPCServer struct {
	// logger log.Logger
	peers []pcosigner.ICosigner
	// The "node's" ThresholdValidator
	// thresholdValidator *ThresholdValidator

	// The "node's" RaftStore
	raftStore *RaftStore

	// Promoted Fields is embedded to have forward compatiblitity
	proto2.UnimplementedIRaftGRPCServer
}
type GRPCServer struct {
	*CosignGRPCServer
	// The "node's" LocalCosigner
	*RaftGRPCServer
}

// NewGRPCServer returns a new GRPCServer.
func NewGRPCServer(
	cosigner pcosigner.ILocalCosigner,
	// thresholdValidator *ThresholdValidator,
	raftStore *RaftStore,
) *GRPCServer {
	return &GRPCServer{
		CosignGRPCServer: &CosignGRPCServer{cosigner: cosigner}, // The nodes local cosigner
		RaftGRPCServer:   &RaftGRPCServer{raftStore: raftStore}, // The nodes raftStore
	}
}

// SignBlock "pseudo-implements" the ICosignerGRPCServer interface in pkg/proto/cosigner_grpc_server_grpc.pb.go
func (rpc *RaftGRPCServer) SignBlock(
	_ context.Context,
	req *proto2.RaftGRPCSignBlockRequest,
) (*proto2.RaftGRPCSignBlockResponse, error) {
	block := &Block{
		Height:    req.Block.GetHeight(),
		Round:     req.Block.GetRound(),
		Step:      int8(req.Block.GetStep()),
		SignBytes: req.Block.GetSignBytes(),
		Timestamp: time.Unix(0, req.Block.GetTimestamp()),
	}
	// this
	res, _, err := rpc.raftStore.thresholdValidator.SignBlock(req.ChainID, block)
	if err != nil {
		return nil, err
	}
	return &proto2.RaftGRPCSignBlockResponse{
		Signature: res,
	}, nil
}

// TransferLeadership pseudo-implements the ICosignerGRPCServer interface in pkg/proto/cosigner_grpc_server_grpc.pb.go
func (rpc *RaftGRPCServer) TransferLeadership(
	_ context.Context,
	req *proto2.RaftGRPCTransferLeadershipRequest,
) (*proto2.RaftGRPCTransferLeadershipResponse, error) {
	if rpc.raftStore.raft.State() != raft.Leader {
		return &proto2.RaftGRPCTransferLeadershipResponse{}, nil
	}
	leaderID := req.GetLeaderID()
	if leaderID != "" {
		// TODO: Not an elegant fix. Se other notes.
		for _, c := range rpc.peers {
			shardID := fmt.Sprint(c.GetID())
			if shardID == leaderID {
				raftAddress := p2pURLToRaftAddress(c.GetAddress())
				fmt.Printf("Transferring leadership to ID: %s - Address: %s\n", shardID, raftAddress)
				rpc.raftStore.raft.LeadershipTransferToServer(raft.ServerID(shardID), raft.ServerAddress(raftAddress))
				return &proto2.RaftGRPCTransferLeadershipResponse{LeaderID: shardID, LeaderAddress: raftAddress}, nil
			}
		}
	}
	fmt.Printf("Transferring leadership to next candidate\n")
	rpc.raftStore.raft.LeadershipTransfer()
	return &proto2.RaftGRPCTransferLeadershipResponse{}, nil
}

// GetLeader pseudo-implements the ICosignerGRPCServer interface in pkg/proto/cosigner_grpc_server_grpc.pb.go
// GetLeader gets the current raft cluster leader and send it as respons.
func (rpc *RaftGRPCServer) GetLeader(
	context.Context,
	*proto2.RaftGRPCGetLeaderRequest,
) (*proto2.RaftGRPCGetLeaderResponse, error) {
	leader := rpc.raftStore.GetLeader()
	return &proto2.RaftGRPCGetLeaderResponse{Leader: string(leader)}, nil
}

// SetNoncesAndSign implements the ICosignerGRPCServer interface.
// The CosignGRPCServer resonse to the request from the client.
func (rpc *CosignGRPCServer) SetNoncesAndSign(
	_ context.Context,
	req *proto.CosignerGRPCSetNoncesAndSignRequest,
) (*proto.CosignerGRPCSetNoncesAndSignResponse, error) {
	res, err := rpc.cosigner.SetNoncesAndSign(
		pcosigner.CosignerSetNoncesAndSignRequest{
			ChainID:   req.ChainID,
			Nonces:    pcosigner.CosignerNoncesFromProto(req.GetNonces()),
			HRST:      types.HRSTKeyFromProto(req.GetHrst()),
			SignBytes: req.GetSignBytes(),
		})
	if err != nil {
		rpc.logger.Error(
			"Failed to sign with shard",
			"chain_id", req.ChainID,
			"height", req.Hrst.Height,
			"round", req.Hrst.Round,
			"step", req.Hrst.Step,
			"error", err,
		)
		return nil, err
	}
	rpc.logger.Info(
		"Signed with shard",
		"chain_id", req.ChainID,
		"height", req.Hrst.Height,
		"round", req.Hrst.Round,
		"step", req.Hrst.Step,
	)
	return &proto.CosignerGRPCSetNoncesAndSignResponse{
		NoncePublic: res.NoncePublic,
		Timestamp:   res.Timestamp.UnixNano(),
		Signature:   res.Signature,
	}, nil
}

// GetNonces implements the ICosignerGRPCServer interface.
func (rpc *CosignGRPCServer) GetNonces(
	_ context.Context,
	req *proto.CosignerGRPCGetNoncesRequest,
) (*proto.CosignerGRPCGetNoncesResponse, error) {
	res, err := rpc.cosigner.GetNonces(
		req.ChainID,
		types.HRSTKeyFromProto(req.GetHrst()),
	)
	if err != nil {
		return nil, err
	}
	return &proto.CosignerGRPCGetNoncesResponse{
		Nonces: pcosigner.CosignerNonces(res.Nonces).ToProto(),
	}, nil
}
