package scram

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/xdg-go/stringprep"
)

func Normalize(str []byte) []byte {
	res, err := stringprep.SASLprep.Prepare(string(str))
	if err != nil {
		return nil
	}
	return []byte(res)
}

// AuthMessage is clientFirstMessageWithoutHeader + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof
func AuthMessage(clientFirstMessageWithoutHeader []byte, serverFirstMessage []byte, clientFinalMessageWithoutProof []byte) []byte {
	var res = make([]byte, len(clientFirstMessageWithoutHeader)+len(serverFirstMessage)+len(clientFinalMessageWithoutProof)+2)
	n := copy(res, clientFirstMessageWithoutHeader)
	res[n] = ','
	n++
	n += copy(res[n:], serverFirstMessage)
	res[n] = ','
	n++
	copy(res[n:], clientFinalMessageWithoutProof)
	return res
}

func AppendNonce(buf []byte) ([]byte, error) {
	raw := make([]byte, 24)
	_, err := io.ReadFull(rand.Reader, raw)
	if err != nil {
		return nil, err
	}

	size := base64.StdEncoding.EncodedLen(24)
	start := len(buf)
	for i := 0; i < size; i++ {
		buf = append(buf, 0)
	}

	base64.StdEncoding.Encode(buf[start:], raw)
	return buf, nil
}
