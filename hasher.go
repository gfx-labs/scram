package scram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/subtle"
	"errors"
	"hash"
)

// Hasher constructs the hash used by a SCRAM mechanism, for example sha256.New for SCRAM-SHA-256.
type Hasher func() hash.Hash

// Size returns the output size of the hash in bytes.
func (h Hasher) Size() int { return h().Size() }

// HMAC returns HMAC(key, msg).
func (h Hasher) HMAC(key, msg []byte) []byte {
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil)
}

// H returns H(msg).
func (h Hasher) H(msg []byte) []byte {
	d := h()
	d.Write(msg)
	return d.Sum(nil)
}

// SaltedPassword returns Hi(Normalize(password), salt, iters), where Hi is PBKDF2.
func (h Hasher) SaltedPassword(password string, salt []byte, iters int) ([]byte, error) {
	if h == nil || iters < 1 || len(salt) == 0 {
		return nil, errors.New("scram: invalid key derivation parameters")
	}
	return pbkdf2.Key(h, Normalize(password), salt, iters, h.Size())
}

// ClientKey returns HMAC(saltedPassword, "Client Key").
func (h Hasher) ClientKey(saltedPassword []byte) []byte {
	return h.HMAC(saltedPassword, []byte("Client Key"))
}

// ServerKey returns HMAC(saltedPassword, "Server Key").
func (h Hasher) ServerKey(saltedPassword []byte) []byte {
	return h.HMAC(saltedPassword, []byte("Server Key"))
}

// StoredKey returns H(clientKey).
func (h Hasher) StoredKey(clientKey []byte) []byte { return h.H(clientKey) }

// ClientSignature returns HMAC(storedKey, authMessage).
func (h Hasher) ClientSignature(storedKey, authMessage []byte) []byte {
	return h.HMAC(storedKey, authMessage)
}

// ServerSignature returns HMAC(serverKey, authMessage).
func (h Hasher) ServerSignature(serverKey, authMessage []byte) []byte {
	return h.HMAC(serverKey, authMessage)
}

// xor returns a XOR b, or nil if the lengths differ.
func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	out := make([]byte, len(a))
	subtle.XORBytes(out, a, b)
	return out
}
