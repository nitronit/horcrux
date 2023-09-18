package pcosigner

// RemoteCosigner implements ICosigner and uses gRPC make to request to other LocalCosigners
// Another way to think about this is that RemoteCosigner is a client that makes a requests to a remote LocalCosigner which is the server
// Step by step:
// 1. Request: Remote --> gRPC --> Local
// 2. Response: Remote <-- gRPC <-- Local
// In GRPC: Onthe client side, the client has a stub (referred to as just a client in some languages)
// 			that provides the same methods(!) as the server.

import (
	"context"
	"net/url"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/types"

	shamirService "github.com/strangelove-ventures/horcrux/pkg/proto/cosigner_service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RemoteCosigner uses CosignerGRPC to request/query a signing process from a LocalCosigner
//
//   - RemoteCosigner acts as a client(!) and requests via gRPC the other
//     "node's" LocalCosigner to set the nonces and sign the payload and respons.
//   - RemoteCosigner --> gRPC --> LocalCosigner
//   - RemoteCosigner implements the Cosigner interface
type RemoteCosigner struct {
	Cosigner
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string) *RemoteCosigner {

	cosigner := &RemoteCosigner{Cosigner{
		id:      id,
		address: address,
	},
	}
	return cosigner
}

const (
	rpcTimeout = 4 * time.Second
)

func getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

// GetAddress returns the P2P URL of the remote cosigner
// Implements the ICosigner interface

// GetPubKey returns public key of the validator.
// Implements Cosigner interface
/*
func (cosigner *RemoteCosigner) GetPubKey(_ string) (cometcrypto.PubKey, error) {
	return nil, fmt.Errorf("unexpected call to RemoteCosigner.GetPubKey")
}

// VerifySignature validates a signed payload against the public key.
// Implements ICosigner interface
func (cosigner *RemoteCosigner) VerifySignature(_ string, _, _ []byte) bool {
	return false
}
*/
func (cosigner *RemoteCosigner) getGRPCClient() (shamirService.ICosignerGRPCClient, *grpc.ClientConn, error) {
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
	return shamirService.NewICosignerGRPCClient(conn), conn, nil
}

// GetNonces implements the Cosigner interface
// It uses the gRPC client to request the nonces from the other
// Its the client side (Stub) of the gRPC
// TODO: Change name to DealNonces or RequestNonces
func (cosigner *RemoteCosigner) GetNonces(
	chainID string,
	req types.HRSTKey,
) (*CosignNoncesResponse, error) {

	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := getContext()
	defer cancelFunc()
	res, err := client.GetNonces(
		context,
		&shamirService.CosignerGRPCGetNoncesRequest{
			ChainID: chainID,
			Hrst:    req.ToProto(),
		},
	)
	if err != nil {
		return nil, err
	}
	// Returns one nonce from each cosigner
	return &CosignNoncesResponse{
		Nonces: CosignerNoncesFromProto(res.GetNonces()),
	}, nil
}

// SetNoncesAndSign implements the Cosigner interface
// It acts as a client(!) and requests via gRPC to the server (LocalCosigner) other
// "node's" LocalCosigner to set the nonces and sign the payload.
func (cosigner *RemoteCosigner) SetNoncesAndSign(
	req CosignerSetNoncesAndSignRequest) (*CosignerSignResponse, error) {
	client, conn, err := cosigner.getGRPCClient()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	context, cancelFunc := getContext()
	defer cancelFunc()
	// Requests the server to Set the Nonces and Sign the payload
	res, err := client.SetNoncesAndSign(context,
		&shamirService.CosignerGRPCSetNoncesAndSignRequest{
			ChainID:   req.ChainID,
			Nonces:    CosignerNonces(req.Nonces).ToProto(),
			Hrst:      req.HRST.ToProto(),
			SignBytes: req.SignBytes,
		})
	if err != nil {
		return nil, err
	}
	return &CosignerSignResponse{
		NoncePublic: res.GetNoncePublic(),
		Timestamp:   time.Unix(0, res.GetTimestamp()),
		Signature:   res.GetSignature(),
	}, nil
}
