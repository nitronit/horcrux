package node

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/metrics"
	"github.com/strangelove-ventures/horcrux/pkg/proto/raft_service/raftService"
	"github.com/strangelove-ventures/horcrux/pkg/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	raftEventLSS = "LSS"
)

const (
	rpcTimeout = 4 * time.Second
)

func GetContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

func (f *fsm) getEventHandler(key string) func(string) {
	return map[string]func(string){
		raftEventLSS: f.handleLSSEvent,
	}[key]
}

func (f *fsm) shouldRetain(key string) bool {
	// Last sign state handled as events only
	return key != raftEventLSS
}

func (f *fsm) handleLSSEvent(value string) {
	lss := &types.ChainSignStateConsensus{}
	err := json.Unmarshal([]byte(value), lss)
	if err != nil {
		f.logger.Error(
			"LastSignState Unmarshal Error",
			"error", err,
		)
		return
	}
	if err := f.thresholdValidator.LoadSignStateIfNecessary(lss.ChainID); err != nil {
		f.logger.Error(
			"Error loading sign state during raft replication",
			"chain_id", lss.ChainID,
			"error", err,
		)
		return
	}
	_ = f.thresholdValidator.SaveLastSignedState(lss.ChainID, lss.SignStateConsensus)
	if err != nil {
		f.logger.Error("[error] - thresholdValidator.SaveLastSignedState %v", err)
		// Our ephemeral secret parts are required, cannot proceed
	}
	_ = f.thresholdValidator.thresholdalgorithm.SaveLastSignedState(lss.ChainID, lss.SignStateConsensus)
	if err != nil {
		f.logger.Error("[error] - thresholdalgorithm.SaveLastSignedState %v", err)
		// Our ephemeral secret parts are required, cannot proceed
	}
}

func (s *RaftStore) getLeaderGRPCClient() (raftService.IRaftGRPCClient, *grpc.ClientConn, error) {
	var leader string
	for i := 0; i < 30; i++ {
		leader = string(s.GetLeader())
		if leader != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if leader == "" {
		metrics.TotalRaftLeaderElectiontimeout.Inc()
		return nil, nil, errors.New("timed out waiting for leader election to complete")
	}
	conn, err := grpc.Dial(leader, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}

	return raftService.NewIRaftGRPCClient(conn), conn, nil
}

// SignBlock implements the ILeader interface
func (s *RaftStore) SignBlock(req ValidatorSignBlockRequest) (*ValidatorSignBlockResponse, error) {
	client, conn, err := s.getLeaderGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := GetContext()
	defer cancelFunc()
	res, err := client.SignBlock(context, &raftService.RaftGRPCSignBlockRequest{
		ChainID: req.ChainID,
		Block:   req.Block.toProto(),
	})
	if err != nil {
		return nil, err
	}
	return &ValidatorSignBlockResponse{
		Signature: res.GetSignature(),
	}, nil
}
