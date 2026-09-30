package scram

// KeyInfo is information about how the keys were made.
type KeyInfo struct {
	Salt   []byte
	Iters  int
	Hasher Hasher
}

type ClientKeys struct {
	ClientKey []byte
	ServerKey []byte
	KeyInfo
}

type ServerKeys struct {
	ServerKey []byte
	StoredKey []byte
	KeyInfo
}
