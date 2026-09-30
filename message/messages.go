package message

import (
	"encoding/base64"
)

func EncodeClientFirstMessageWithoutHeader(user []byte, nonce []byte) []byte {
	size := 5
	size += len(user)
	size += len(nonce)

	res := Encoder(make([]byte, 0, size))
	res = res.AppendValue('n', user)
	res = res.AppendValue('r', nonce)

	return res
}

func DecodeClientFirstMessageWithoutHeader(message []byte) (user []byte, nonce []byte, ok bool) {
	d := Decoder(message)

	var key rune
	d, key, user, ok = d.ReadValue()
	if !ok || key != 'n' {
		ok = false
		return
	}

	d, key, nonce, ok = d.ReadValue()
	if !ok || key != 'r' {
		ok = false
		return
	}

	return
}

// EncodeClientFirstMessage is the initial message from the client
// Pass nil for channelBinding for no support, []byte{} for supporting but server doesn't support, or the channel binding
func EncodeClientFirstMessage(channelBinding []byte, authzid []byte, user []byte, nonce []byte) []byte {
	size := 8
	if len(channelBinding) != 0 {
		size += 1
		size += len(channelBinding)
	}
	if len(authzid) != 0 {
		size += 2
		size += len(authzid)
	}
	size += len(user)
	size += len(nonce)

	res := Encoder(make([]byte, 0, size))
	if channelBinding == nil {
		res = res.AppendKey('n')
	} else if len(channelBinding) == 0 {
		res = res.AppendKey('y')
	} else {
		res = res.AppendValue('p', channelBinding)
	}
	if len(authzid) == 0 {
		res = res.AppendNull()
	} else {
		res = res.AppendValue('a', authzid)
	}
	res = res.AppendValue('n', user)
	res = res.AppendValue('r', nonce)

	return res
}

func DecodeClientFirstMessage(message []byte) (channelBinding []byte, authzid []byte, user []byte, nonce []byte, ok bool) {
	d := Decoder(message)

	var key rune
	d, key, channelBinding, ok = d.ReadValue()
	if ok {
		if key != 'p' {
			ok = false
			return
		}
	} else {
		d, key, ok = d.ReadKey()
		if !ok {
			return
		}
		switch key {
		case 'n':
		case 'y':
			authzid = []byte{}
		default:
			ok = false
			return
		}
	}

	d, key, authzid, ok = d.ReadValue()
	if ok {
		if key != 'a' {
			ok = false
			return
		}
	} else {
		d, ok = d.ReadNull()
		if !ok {
			return
		}
	}

	d, key, user, ok = d.ReadValue()
	if !ok || key != 'n' {
		ok = false
		return
	}

	d, key, nonce, ok = d.ReadValue()
	if !ok || key != 'r' {
		ok = false
		return
	}

	return
}

func EncodeServerFirstMessage(nonce []byte, salt []byte, iters int) []byte {
	size := 8
	size += len(nonce)
	saltLen := base64.StdEncoding.EncodedLen(len(salt))
	size += saltLen
	itersSize := 0
	for i := iters; i != 0; i /= 10 {
		itersSize++
	}

	res := Encoder(make([]byte, 0, size+itersSize))
	res = res.AppendValue('r', nonce)
	res = res.AppendBase64('s', salt)
	res = res.AppendInt('i', iters)

	return res
}

func DecodeServerFirstMessage(message []byte) (nonce []byte, salt []byte, iters int, ok bool) {
	d := Decoder(message)

	var key rune
	d, key, nonce, ok = d.ReadValue()
	if !ok || key != 'r' {
		ok = false
		return
	}

	d, key, salt, ok = d.ReadBase64()
	if !ok || key != 's' {
		ok = false
		return
	}

	d, key, iters, ok = d.ReadInt()
	if !ok || key != 'i' {
		ok = false
		return
	}

	ok = true
	return
}

func EncodeClientFinalMessageWithoutProof(channel []byte, nonce []byte) []byte {
	size := 5
	channelLen := base64.StdEncoding.EncodedLen(len(channel))
	size += channelLen
	size += len(nonce)

	res := Encoder(make([]byte, 0, size))
	res = res.AppendBase64('c', channel)
	res = res.AppendValue('r', nonce)

	return res
}

func DecodeClientFinalMessageWithoutProof(message []byte) (channel []byte, nonce []byte, ok bool) {
	d := Decoder(message)

	var key rune
	d, key, channel, ok = d.ReadBase64()
	if !ok || key != 'c' {
		ok = false
		return
	}

	d, key, nonce, ok = d.ReadValue()
	if !ok || key != 'r' {
		ok = false
		return
	}

	return
}

func EncodeClientFinalMessage(channel []byte, nonce []byte, proof []byte) []byte {
	size := 8
	channelLen := base64.StdEncoding.EncodedLen(len(channel))
	size += channelLen
	size += len(nonce)
	proofLen := base64.StdEncoding.EncodedLen(len(proof))
	size += proofLen

	res := Encoder(make([]byte, 0, size))
	res = res.AppendBase64('c', channel)
	res = res.AppendValue('r', nonce)
	res = res.AppendBase64('p', proof)

	return res
}

func DecodeClientFinalMessage(message []byte) (channel []byte, nonce []byte, proof []byte, ok bool) {
	d := Decoder(message)

	var key rune
	d, key, channel, ok = d.ReadBase64()
	if !ok || key != 'c' {
		ok = false
		return
	}

	d, key, nonce, ok = d.ReadValue()
	if !ok || key != 'r' {
		ok = false
		return
	}

	d, key, proof, ok = d.ReadBase64()
	if !ok || key != 'p' {
		ok = false
		return
	}

	return
}

func EncodeServerFinalMessage(serverSignature []byte) []byte {
	size := 2
	size += base64.StdEncoding.EncodedLen(len(serverSignature))

	res := Encoder(make([]byte, 0, size))
	res = res.AppendBase64('v', serverSignature)

	return res
}

func DecodeServerFinalMessage(message []byte) (serverSignature []byte, ok bool) {
	d := Decoder(message)

	var key rune
	d, key, serverSignature, ok = d.ReadBase64()
	if !ok || key != 'v' {
		ok = false
		return
	}

	return
}
