package message

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"unicode/utf8"
)

type Encoder []byte

func validKey(key rune) bool {
	return (key >= 'a' && key <= 'z') || (key >= 'A' && key <= 'Z')
}

func validValueRune(value rune) bool {
	switch value {
	case '\x00', ',':
		return false
	default:
		return true
	}
}

func validValue(value []byte) bool {
	/*
		technically invalid by RFC, but some postgres clients will send null values for some reason
		(such as for client nonce).

		if len(value) == 0 {
			return false
		}
	*/
	for len(value) != 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError {
			return false
		}
		value = value[size:]
		if !validValueRune(r) {
			return false
		}
	}
	return true
}

func (Encoder) validateKey(key rune) {
	if !validKey(key) {
		panic(fmt.Sprintf("invalid key '%c'", key))
	}
}

func (Encoder) validateValueBytes(value []byte) {
	if !validValue(value) {
		panic(fmt.Sprintf(`invalid value: "%s"`, value))
	}
}

func (T Encoder) AppendNull() Encoder {
	res := T
	if len(res) == 0 {
		panic("null cannot be appending at beginning of message")
	}
	res = append(res, ',')
	return res
}

func (T Encoder) AppendKey(key rune) Encoder {
	T.validateKey(key)

	res := T
	if len(res) != 0 {
		res = append(res, ',')
	}
	res = utf8.AppendRune(res, key)

	return res
}

func (T Encoder) AppendValue(key rune, value []byte) Encoder {
	T.validateValueBytes(value)

	res := T
	res = res.AppendKey(key)
	res = append(res, '=')
	res = append(res, value...)

	return res
}

func (T Encoder) AppendBase64(key rune, value []byte) Encoder {
	res := T
	res = res.AppendKey(key)
	res = append(res, '=')
	start := len(res)
	size := base64.StdEncoding.EncodedLen(len(value))
	for i := 0; i < size; i++ {
		res = append(res, 0)
	}
	base64.StdEncoding.Encode(res[start:], value)

	return res
}

func (T Encoder) AppendInt(key rune, value int) Encoder {
	res := T
	res = res.AppendKey(key)
	res = append(res, '=')
	res = strconv.AppendInt(res, int64(value), 10)

	return res
}
