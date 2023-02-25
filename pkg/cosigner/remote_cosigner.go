package cosigner

import (
	"context"
	"net/url"
	"time"

	proto "github.com/strangelove-ventures/horcrux/pkg/proto"
	"github.com/strangelove-ventures/horcrux/pkg/state"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	rpcTimeout = 4 * time.Second
)

// RemoteCosigner uses CosignerGRPC to request signing from a remote cosigner
type RemoteCosigner struct {
	id      int
	address string
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string) *RemoteCosigner {

	cosigner := &RemoteCosigner{
		id:      id,
		address: address,
	}
	return cosigner
}

// getContext returns a context with a timeout
func getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

func GetContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

// GetID returns the ID of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetID() int {
	return cosigner.id
}

// GetAddress returns the P2P URL of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetAddress() string {
	return cosigner.address
}

func (cosigner *RemoteCosigner) getGRPCClient() (proto.CosignerGRPCClient, *grpc.ClientConn, error) {
	var grpcAddress string
	url, err := url.Parse(cosigner.address)
	if err != nil {
		grpcAddress = cosigner.address
	} else {
		grpcAddress = url.Host
	}
	conn, err := grpc.Dial(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return proto.NewCosignerGRPCClient(conn), conn, nil
}

// GetEphemeralSecretParts implements the cosigner interface
func (cosigner *RemoteCosigner) GetEphemeralSecretParts(
	req state.HRSTKey) (*state.CosignerEphemeralSecretPartsResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := getContext()
	defer cancelFunc()
	res, err := client.GetEphemeralSecretParts(context, &proto.CosignerGRPCGetEphemeralSecretPartsRequest{
		Hrst: req.ToProto(),
	})
	if err != nil {
		return nil, err
	}
	return &state.CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: state.CosignerEphemeralSecretPartsFromProto(res.GetEncryptedSecrets()),
	}, nil
}

// SetEphemeralSecretPartsAndSign implements the cosigner interface
func (cosigner *RemoteCosigner) SetEphemeralSecretPartsAndSign(
	req state.CosignerSetEphemeralSecretPartsAndSignRequest) (*state.CosignerSignResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := getContext()
	defer cancelFunc()
	res, err := client.SetEphemeralSecretPartsAndSign(context, &proto.CosignerGRPCSetEphemeralSecretPartsAndSignRequest{
		EncryptedSecrets: state.CosignerEphemeralSecretParts(req.EncryptedSecrets).ToProto(),
		Hrst:             req.HRST.ToProto(),
		SignBytes:        req.SignBytes,
	})
	if err != nil {
		return nil, err
	}
	return &state.CosignerSignResponse{
		EphemeralPublic: res.GetEphemeralPublic(),
		Timestamp:       time.Unix(0, res.GetTimestamp()),
		Signature:       res.GetSignature(),
	}, nil
}

// _ is a type assertion to ensure that RemoteCosigner implements the Cosigner interface
var _ Cosigner = (*RemoteCosigner)(nil)
