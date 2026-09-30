package scram

import (
	"bytes"
	"crypto/hmac"
	"io"

	"github.com/gfx-labs/scram/message"
)

func ClientPasswordLookup(password string, hasher Hasher) func(salt []byte, iters int) (ClientKeys, bool) {
	return func(salt []byte, iters int) (ClientKeys, bool) {
		saltedPassword := hasher.SaltedPassword([]byte(password), salt, iters)
		clientKey := hasher.ClientKey(saltedPassword)
		serverKey := hasher.ServerKey(saltedPassword)
		return ClientKeys{
			ClientKey: clientKey,
			ServerKey: serverKey,
			KeyInfo: KeyInfo{
				Salt:   salt,
				Iters:  iters,
				Hasher: hasher,
			},
		}, true
	}
}

func ClientKeysLookup(keys ClientKeys) func(salt []byte, iters int) (ClientKeys, bool) {
	return func(salt []byte, iters int) (ClientKeys, bool) {
		if !bytes.Equal(keys.Salt, salt) {
			return ClientKeys{}, false
		}

		if keys.Iters != iters {
			return ClientKeys{}, false
		}

		return keys, true
	}
}

type ClientConversation struct {
	User   string
	Lookup func(salt []byte, iters int) (ClientKeys, bool)

	// valid after state 0
	clientFirstMessageWithoutHeader []byte

	// valid after state 1
	keys        ClientKeys
	authMessage []byte

	state int
}

func (T *ClientConversation) Write(msg []byte) (resp []byte, err error) {
	switch T.state {
	case 0:
		var nonce []byte
		nonce, err = AppendNonce(nil)
		if err != nil {
			return
		}

		resp = message.EncodeClientFirstMessage(nil, nil, []byte(T.User), nonce)
		var ok bool
		T.clientFirstMessageWithoutHeader, ok = message.StripClientFirstMessageHeader(resp)
		if !ok {
			err = ErrOtherError
			return
		}
		T.state++
		return
	case 1:
		nonce, salt, iters, ok := message.DecodeServerFirstMessage(msg)
		if !ok {
			err = ErrInvalidEncoding
			return
		}

		T.keys, ok = T.Lookup(salt, iters)
		if !ok {
			err = ErrUnknownUser
			return
		}
		storedKey := T.keys.Hasher.StoredKey(T.keys.ClientKey)
		T.authMessage = AuthMessage(
			T.clientFirstMessageWithoutHeader,
			msg,
			message.EncodeClientFinalMessageWithoutProof(
				[]byte{0x6e, 0x2c, 0x2c},
				nonce,
			),
		)
		clientSignature := T.keys.Hasher.ClientSignature(storedKey, T.authMessage)
		clientProof := T.keys.Hasher.ClientProof(T.keys.ClientKey, clientSignature)

		resp = message.EncodeClientFinalMessage(
			[]byte{0x6e, 0x2c, 0x2c},
			nonce,
			clientProof,
		)
		T.state++
		return
	case 2:
		serverSignature, ok := message.DecodeServerFinalMessage(msg)
		if !ok {
			err = ErrInvalidEncoding
			return
		}

		expectedServerKey := T.keys.Hasher.ServerSignature(T.keys.ServerKey, T.authMessage)

		if !hmac.Equal(serverSignature, expectedServerKey) {
			err = ErrInvalidProof
			return
		}

		err = io.EOF
		T.state++
		return
	default:
		err = io.EOF
		return
	}
}
