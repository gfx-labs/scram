package scram

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// DefaultSaltLen is the salt length used by NewKeyInfo.
const DefaultSaltLen = 16

// KeyInfo describes how keys were derived.
type KeyInfo struct {
	Salt   []byte
	Iters  int
	Hasher Hasher
}

// NewKeyInfo returns a KeyInfo with a random salt of DefaultSaltLen bytes.
func NewKeyInfo(hasher Hasher, iters int) (KeyInfo, error) {
	salt := make([]byte, DefaultSaltLen)
	rand.Read(salt)
	info := KeyInfo{Salt: salt, Iters: iters, Hasher: hasher}
	return info, info.validate()
}

func (k KeyInfo) validate() error {
	if k.Hasher == nil || k.Iters < 1 || len(k.Salt) == 0 {
		return ErrInvalidKeys
	}
	return nil
}

func (k KeyInfo) checkPolicy(minIters, maxIters, minSaltLen int) error {
	if k.Iters < minIters || (maxIters > 0 && k.Iters > maxIters) {
		return fmt.Errorf("%w: %d", ErrIterationsOutOfRange, k.Iters)
	}
	if len(k.Salt) < minSaltLen {
		return fmt.Errorf("%w: %d bytes", ErrSaltTooShort, len(k.Salt))
	}
	return nil
}

func validKey(key []byte, size int) bool {
	if len(key) != size {
		return false
	}
	for _, b := range key {
		if b != 0 {
			return true
		}
	}
	return false
}

// ClientKeys are the secrets a client needs. Both keys are password-equivalent.
type ClientKeys struct {
	ClientKey []byte
	ServerKey []byte
	KeyInfo
}

// Validate checks that both keys are present and match the hash size.
func (k ClientKeys) Validate() error {
	if err := k.validate(); err != nil {
		return err
	}
	n := k.Hasher.Size()
	if !validKey(k.ClientKey, n) || !validKey(k.ServerKey, n) {
		return ErrInvalidKeys
	}
	return nil
}

// ServerKeys returns the verifier a server stores for these client keys.
func (k ClientKeys) ServerKeys() ServerKeys {
	return ServerKeys{StoredKey: k.Hasher.StoredKey(k.ClientKey), ServerKey: k.ServerKey, KeyInfo: k.KeyInfo}
}

// ServerKeys are the verifier a server stores for a user.
type ServerKeys struct {
	StoredKey []byte
	ServerKey []byte
	KeyInfo
}

// Validate checks that both keys are present and match the hash size.
func (k ServerKeys) Validate() error {
	if err := k.validate(); err != nil {
		return err
	}
	n := k.Hasher.Size()
	if !validKey(k.StoredKey, n) || !validKey(k.ServerKey, n) {
		return ErrInvalidKeys
	}
	return nil
}

// DeriveClientKeys derives ClientKey and ServerKey from a password.
func DeriveClientKeys(password string, info KeyInfo) (ClientKeys, error) {
	if err := info.validate(); err != nil {
		return ClientKeys{}, err
	}
	salted, err := info.Hasher.SaltedPassword(password, info.Salt, info.Iters)
	if err != nil {
		return ClientKeys{}, err
	}
	defer clear(salted)
	return ClientKeys{
		ClientKey: info.Hasher.ClientKey(salted),
		ServerKey: info.Hasher.ServerKey(salted),
		KeyInfo:   info,
	}, nil
}

// DeriveServerKeys derives the stored verifier from a password.
func DeriveServerKeys(password string, info KeyInfo) (ServerKeys, error) {
	ck, err := DeriveClientKeys(password, info)
	if err != nil {
		return ServerKeys{}, err
	}
	defer clear(ck.ClientKey)
	return ck.ServerKeys(), nil
}

// ClientPasswordLookup returns a client Lookup that derives keys from a password.
func ClientPasswordLookup(password string, hasher Hasher) func(salt []byte, iters int) (ClientKeys, error) {
	return func(salt []byte, iters int) (ClientKeys, error) {
		return DeriveClientKeys(password, KeyInfo{Salt: salt, Iters: iters, Hasher: hasher})
	}
}

// ClientKeysLookup returns a client Lookup that uses precomputed keys. The server
// must offer the same salt and iteration count the keys were derived with.
func ClientKeysLookup(keys ClientKeys) func(salt []byte, iters int) (ClientKeys, error) {
	return func(salt []byte, iters int) (ClientKeys, error) {
		if err := keys.Validate(); err != nil {
			return ClientKeys{}, err
		}
		if string(keys.Salt) != string(salt) || keys.Iters != iters {
			return ClientKeys{}, errors.New("scram: server salt or iteration count does not match stored keys")
		}
		return keys, nil
	}
}
