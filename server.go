package scram

import (
	"bytes"
	"io"

	"github.com/gfx-labs/scram/message"
)

type ServerConversation struct {
	// Lookup keys by username
	Lookup func(user string) (ServerKeys, bool)

	// valid after state 0
	keys                            ServerKeys
	nonce                           []byte
	clientFirstMessageWithoutHeader []byte
	serverFirstMessage              []byte

	// valid after state 1
	RecoveredClientKey []byte

	state int
}

func (T *ServerConversation) Write(msg []byte) (resp []byte, err error) {
	switch T.state {
	case 0:
		_, _, user, nonce, ok := message.DecodeClientFirstMessage(msg)
		if !ok {
			err = ErrInvalidEncoding
			return
		}
		T.keys, ok = T.Lookup(string(user))
		if !ok {
			err = ErrUnknownUser
			return
		}
		nonce, err = AppendNonce(nonce)
		if err != nil {
			return
		}
		T.nonce = nonce

		T.clientFirstMessageWithoutHeader, ok = message.StripClientFirstMessageHeader(msg)
		if !ok {
			err = ErrInvalidEncoding
			return
		}

		resp = message.EncodeServerFirstMessage(
			nonce,
			T.keys.Salt,
			T.keys.Iters,
		)
		T.serverFirstMessage = resp
		T.state++
		return
	case 1:
		_, nonce, proof, ok := message.DecodeClientFinalMessage(msg)
		if !ok {
			err = ErrInvalidEncoding
			return
		}
		if !bytes.Equal(T.nonce, nonce) {
			err = ErrOtherError
			return
		}

		clientFinalMessageWithoutProof, ok := message.StripClientFinalMessageProof(msg)
		if !ok {
			err = ErrInvalidEncoding
			return
		}
		authMessage := AuthMessage(T.clientFirstMessageWithoutHeader, T.serverFirstMessage, clientFinalMessageWithoutProof)

		// recover client key
		serverSignature := T.keys.Hasher.ServerSignature(T.keys.ServerKey, authMessage)
		clientSignature := T.keys.Hasher.ClientSignature(T.keys.StoredKey, authMessage)
		if len(clientSignature) != len(proof) {
			err = ErrInvalidProof
			return
		}
		T.RecoveredClientKey = make([]byte, len(clientSignature))
		for i, a := range clientSignature {
			b := proof[i]
			T.RecoveredClientKey[i] = a ^ b
		}

		// check client key
		storedKey := T.keys.Hasher.StoredKey(T.RecoveredClientKey)
		if !bytes.Equal(storedKey, T.keys.StoredKey) {
			err = ErrInvalidProof
			return
		}

		resp = message.EncodeServerFinalMessage(serverSignature)
		err = io.EOF
		T.state++
		return
	default:
		err = io.EOF
		return
	}
}
