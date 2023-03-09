package signer

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/cosigner"
	proto "github.com/strangelove-ventures/horcrux/pkg/cosigner/proto"
	metrics "github.com/strangelove-ventures/horcrux/pkg/metrics"
	state "github.com/strangelove-ventures/horcrux/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	raftEventLSS = "LSS"
)

func (f *fsm) getEventHandler(key string) func(string) {
	return map[string]func(string){
		raftEventLSS: f.handleLSSEvent,
	}[key]
}

func (f *fsm) shouldRetain(key string) bool {
	// Last sign types handled as events only
	return key != raftEventLSS
}

func (f *fsm) handleLSSEvent(value string) {
	lss := &state.SignStateConsensus{}
	err := json.Unmarshal([]byte(value), lss)
	if err != nil {
		f.logger.Error("LSS Unmarshal Error", err.Error())
		return
	}
	// TODO: This is double trouble.
	_ = f.thresholdValidator.SaveLastSignedState(*lss)
	_ = f.cosigner.SaveLastSignedState(*lss)
}

func (s *RaftStore) getLeaderGRPCClient() (proto.GRPCClient, *grpc.ClientConn, error) {
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
	return proto.NewGRPCClient(conn), conn, nil
}

func (s *RaftStore) LeaderSignBlock(req state.CosignerSignBlockRequest) (
	*state.CosignerSignBlockResponse, error) {
	client, conn, err := s.getLeaderGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := cosigner.GetContext()
	defer cancelFunc()
	res, err := client.SignBlock(context, &proto.GRPCSignBlockRequest{
		ChainID: req.ChainID,
		Block:   req.Block.ToProto(),
	})
	if err != nil {
		return nil, err
	}
	return &state.CosignerSignBlockResponse{
		Signature: res.GetSignature(),
	}, nil
}
