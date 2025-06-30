package shared

import (
	"github.com/grepplabs/kafka-proxy/pkg/apis"
	"github.com/grepplabs/kafka-proxy/plugin/local-auth-scram/proto"
	"github.com/hashicorp/go-plugin"
	"golang.org/x/net/context"
)

// GRPCClient is an implementation of PasswordAuthenticator that talks over gRPC.
type GRPCClient struct {
	broker *plugin.GRPCBroker
	client proto.ScramAuthenticatorClient
}

func (m *GRPCClient) GetCredential(storeinfo string) (string, string, error) {
	resp, err := m.client.GetCredential(context.Background(), &proto.LoadCredentialRequest{
		Storeinfo: storeinfo,
	})
	if err != nil {
		return "", "", err
	}
	return resp.Username, resp.Password, nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	broker *plugin.GRPCBroker
	Impl   apis.ScramAuthenticator
	proto.UnimplementedScramAuthenticatorServer
}

func (m *GRPCServer) GetCredential(
	ctx context.Context,
	req *proto.LoadCredentialRequest) (*proto.GetCredentialResponse, error) {
	u, p, err := m.Impl.GetCredential(req.Storeinfo)
	return &proto.GetCredentialResponse{Username: u, Password: p}, err
}
