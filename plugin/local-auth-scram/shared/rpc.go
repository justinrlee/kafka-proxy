package shared

import (
	"net/rpc"

	"github.com/grepplabs/kafka-proxy/pkg/apis"
)

type RPCClient struct{ client *rpc.Client }

func (m *RPCClient) GetCredential(storeinfo string) (string, string, error) {
	var resp map[string]interface{}
	err := m.client.Call("Plugin.GetCredential", map[string]interface{}{
		"storeinfo": storeinfo,
	}, &resp)
	return resp["username"].(string), resp["password"].(string), err
}

type RPCServer struct {
	Impl apis.ScramAuthenticator
}

func (m *RPCServer) GetCredential(args map[string]interface{}, resp *map[string]interface{}) error {
	u, p, err := m.Impl.GetCredential(args["storeinfo"].(string))
	*resp = map[string]interface{}{
		"username": u,
		"password": p,
	}
	return err
}
