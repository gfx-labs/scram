package scram

import (
	"crypto/rand"
	"errors"

	"github.com/xdg-go/stringprep"
)

// newNonce is replaced in tests to reproduce RFC test vectors.
var newNonce = rand.Text

// Normalize applies SASLprep to a password. Like PostgreSQL, it returns the
// input unchanged if SASLprep fails, so distinct passwords never collide.
func Normalize(password string) string {
	res, err := stringprep.SASLprep.Prepare(password)
	if err != nil {
		return password
	}
	return res
}

// ChannelBinding identifies a channel binding type and its data, for example
// "tls-server-end-point" and the hash of the server certificate.
type ChannelBinding struct {
	Type string
	Data []byte
}

// validate rejects bindings with no data, which would bind to nothing while
// appearing to succeed.
func (cb *ChannelBinding) validate() error {
	if cb != nil && (cb.Type == "" || len(cb.Data) == 0) {
		return errors.New("scram: ChannelBinding requires Type and Data")
	}
	return nil
}

func authMessage(clientFirstBare, serverFirst, clientFinalWithoutProof string) []byte {
	return []byte(clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof)
}

// Default parameter policy.
const (
	// DefaultMinIters is the minimum iteration count from RFC 7677.
	DefaultMinIters = 4096
	// DefaultMaxIters bounds the work a server can make a client do.
	DefaultMaxIters = 1_000_000
	// DefaultMinSaltLen is the shortest salt accepted by default.
	DefaultMinSaltLen = 8
)

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
