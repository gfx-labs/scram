package scram

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

type Hasher func() hash.Hash

func (T Hasher) HMAC(key []byte, str []byte) []byte {
	h := hmac.New(T, key)
	h.Write(str)
	return h.Sum(nil)
}

// Hi is PBKDF2(HMAC, str, salt, iterationCount, output length of HMAC)
func (T Hasher) Hi(str []byte, salt []byte, iterationCount int) []byte {
	if iterationCount < 1 {
		panic("iterationCount must be >= 1")
	}

	hasher := hmac.New(T, str)

	salt1 := make([]byte, len(salt), len(salt)+4)
	copy(salt1, salt)
	salt1 = binary.BigEndian.AppendUint32(salt1, 1)
	hasher.Write(salt1)
	hi := hasher.Sum(nil)
	ui := bytes.Clone(hi)

	for i := 1; i < iterationCount; i++ {
		hasher.Reset()
		hasher.Write(ui)
		ui = hasher.Sum(ui[:0])
		if len(ui) != len(hi) {
			panic("expected len(ui) == len(hi)")
		}
		for j, a := range hi {
			b := ui[j]
			hi[j] = a ^ b
		}
	}

	return hi
}

// SaltedPassword is Hi(Normalize(password), salt, iterationCount)
func (T Hasher) SaltedPassword(password []byte, salt []byte, iterationCount int) []byte {
	return T.Hi(Normalize(password), salt, iterationCount)
}

var (
	clientKeyMessage = []byte("Client Key")
	serverKeyMessage = []byte("Server Key")
)

// ClientKey is HMAC(saltedPassword, 'Client Key')
func (T Hasher) ClientKey(saltedPassword []byte) []byte {
	return T.HMAC(saltedPassword, clientKeyMessage)
}

// ServerKey is HMAC(saltedPassword, 'Server Key')
func (T Hasher) ServerKey(saltedPassword []byte) []byte {
	return T.HMAC(saltedPassword, serverKeyMessage)
}

func (T Hasher) H(str []byte) []byte {
	h := T()
	h.Write(str)
	return h.Sum(nil)
}

// StoredKey is H(clientKey)
func (T Hasher) StoredKey(clientKey []byte) []byte {
	return T.H(clientKey)
}

// ClientSignature is HMAC(storedKey, authMessage)
func (T Hasher) ClientSignature(storedKey []byte, authMessage []byte) []byte {
	return T.HMAC(storedKey, authMessage)
}

// ClientProof is clientKey XOR clientSignature
func (T Hasher) ClientProof(clientKey []byte, clientSignature []byte) []byte {
	if len(clientKey) != len(clientSignature) {
		panic("expected len(clientKey) == len(clientSignature)")
	}

	var res = make([]byte, len(clientKey))
	for i, a := range clientKey {
		b := clientSignature[i]
		res[i] = a ^ b
	}

	return res
}

// ServerSignature is HMAC(serverKey, authMessage)
func (T Hasher) ServerSignature(serverKey []byte, authMessage []byte) []byte {
	return T.HMAC(serverKey, authMessage)
}
