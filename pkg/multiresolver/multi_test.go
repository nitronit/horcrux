package multiresolver_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/strangelove-ventures/horcrux/pkg/node"
	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"

	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/strangelove-ventures/horcrux/pkg/multiresolver"
	"github.com/strangelove-ventures/horcrux/pkg/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createListener(nodeID string, homedir string) (string, func(), error) {
	sock, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	port := strconv.Itoa(sock.Addr().(*net.TCPAddr).Port)

	// Initiliaze the localcosign as an ILocalCosigner.
	cosign := pcosigner.Cosigner{}
	vlocalcosign := pcosigner.NewLocalCosigner(
		log.NewNopLogger(), nil, nil, cosign)

	var localcosign pcosigner.ILocalCosigner
	localcosign = vlocalcosign
	var remoteCosigners []pcosigner.IRemoteCosigner
	remoteCosigners = append(remoteCosigners, vlocalcosign)

	var peers []pcosigner.ICosigner
	peers = append(peers, vlocalcosign)

	timeDuration := 500 * time.Millisecond

	s := node.NewRaftStore(
		nodeID,
		homedir,
		"127.0.0.1:"+port,
		500*time.Millisecond,
		log.NewNopLogger(), localcosign, peers)

	// Need to set pointers to avoid nil pointers.
	thresholdvalidator := node.NewThresholdValidator(log.NewNopLogger(), nil, 0, timeDuration, 0, localcosign, remoteCosigners, s)
	s.SetThresholdValidator(thresholdvalidator)

	transportManager, err := s.Open(peers)
	if err != nil {
		fmt.Printf("Error opening transport manager: %v\n", err)
		return "", nil, err
	}

	grpcServer := grpc.NewServer()
	proto.RegisterICosignerGRPCServer(grpcServer, node.NewGRPCServer(localcosign, s))
	transportManager.Register(grpcServer)

	go func() {
		_ = grpcServer.Serve(sock)
	}()

	return port, func() {
		grpcServer.Stop()
	}, nil
}

func TestMultiResolver(t *testing.T) {
	targetIP, targetDNS := "multi:///", "multi:///"

	tmp := t.TempDir()

	for i := 0; i < 3; i++ {
		port, c, err := createListener(strconv.Itoa(i+1), filepath.Join(tmp, fmt.Sprintf("cosigner%d", i+1)))
		require.NoError(t, err)
		defer c()

		if i != 0 {
			targetIP += ","
			targetDNS += ","
		}

		targetIP += "127.0.0.1:" + port
		targetDNS += "localhost:" + port
	}

	multiresolver.Register()

	serviceConfig := `{"loadBalancingConfig": [ { "round_robin": {} } ]}`
	retryOpts := []grpcretry.CallOption{
		grpcretry.WithBackoff(grpcretry.BackoffExponential(100 * time.Millisecond)),
		grpcretry.WithMax(5),
	}

	connDNS, err := grpc.Dial(targetDNS,
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)),
	)
	require.NoError(t, err)
	defer connDNS.Close()

	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	grpcClient := proto.NewIRaftGRPCClient(connDNS)
	_, err = grpcClient.GetLeader(ctx, &proto.RaftGRPCGetLeaderRequest{})
	require.NoError(t, err)

	connIP, err := grpc.Dial(targetIP,
		grpc.WithDefaultServiceConfig(serviceConfig),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)),
	)
	require.NoError(t, err)
	defer connIP.Close()

	grpcClient = proto.NewIRaftGRPCClient(connIP)
	_, err = grpcClient.GetLeader(ctx, &proto.RaftGRPCGetLeaderRequest{})
	require.NoError(t, err)
}
