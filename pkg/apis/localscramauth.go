package apis

type ScramAuthenticator interface {
	GetCredential(storeinfo string) (string, string, error)
}

type ScramAuthenticatorFactory interface {
	New(params []string) (ScramAuthenticator, error)
}
