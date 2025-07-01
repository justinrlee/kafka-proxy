package main

import (
	"flag"
	"os"

	"github.com/grepplabs/kafka-proxy/plugin/local-auth-scram/shared"
	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
)

const EnvSaslPassword = "SASL_PASSWORD"

type ScramAuthenticator struct {
	Username string
	Password string
}

func (pa ScramAuthenticator) GetCredential(storeinfo string) (username string, password string, err error) {
	return pa.Username, pa.Password, nil
}

func (f *ScramAuthenticator) flagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("auth plugin settings", flag.ContinueOnError)
	fs.StringVar(&f.Username, "username", "", "Expected SASL username")
	fs.StringVar(&f.Password, "password", "", "Expected SASL password")
	return fs
}

func main() {
	scramAuthenticator := &ScramAuthenticator{}
	flags := scramAuthenticator.flagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logrus.Errorf("error parsing flags: %v", err)
		os.Exit(1)
	}

	if scramAuthenticator.Password == "" {
		scramAuthenticator.Password = os.Getenv(EnvSaslPassword)
	}

	if scramAuthenticator.Username == "" || scramAuthenticator.Password == "" {
		logrus.Errorf("parameters username and password are required")
		os.Exit(1)
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"scramAuthenticator": &shared.ScramAuthenticatorPlugin{Impl: scramAuthenticator},
		},
		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
