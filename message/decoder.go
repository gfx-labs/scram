package message

import (
	"encoding/base64"
	"strconv"
)

type Decoder []byte

func (T Decoder) ReadNull() (remaining Decoder, ok bool) {
	remaining = T

	if len(remaining) == 0 {
		ok = true
		return
	}

	if remaining[0] != ',' {
		return
	}
	remaining = remaining[1:]
	ok = true
	return
}

func (T Decoder) ReadKey() (remaining Decoder, key rune, ok bool) {
	remaining = T

	if len(remaining) == 0 {
		return
	}
	key = rune(remaining[0])

	if !validKey(key) {
		return
	}

	remaining = remaining[1:]

	if len(remaining) != 0 {
		switch remaining[0] {
		case ',':
			remaining = remaining[1:]
		case '=':
		default:
			remaining = T
			ok = false
			return
		}
	}

	ok = true
	return
}

func (T Decoder) ReadValue() (remaining Decoder, key rune, value []byte, ok bool) {
	remaining = T

	remaining, key, ok = remaining.ReadKey()
	if !ok {
		return
	}

	// read equal sign
	if len(remaining) == 0 || remaining[0] != '=' {
		remaining = T
		ok = false
		return
	}
	remaining = remaining[1:]

	// read until comma
	value = remaining
	for i, b := range value {
		if b == ',' {
			value = value[:i]
			break
		}
	}

	if !validValue(value) {
		remaining = T
		ok = false
		return
	}

	remaining = remaining[len(value):]

	// consume comma
	if len(remaining) != 0 {
		remaining = remaining[1:]
	}

	ok = true
	return
}

func (T Decoder) ReadBase64() (remaining Decoder, key rune, value []byte, ok bool) {
	remaining = T

	var rawValue []byte
	remaining, key, rawValue, ok = T.ReadValue()
	if !ok {
		return
	}
	value = make([]byte, base64.StdEncoding.DecodedLen(len(rawValue)))
	n, err := base64.StdEncoding.Decode(value, rawValue)
	if err != nil {
		remaining = T
		ok = false
		return
	}
	value = value[:n]

	return
}

func (T Decoder) ReadInt() (remaining Decoder, key rune, value int, ok bool) {
	remaining = T

	var rawValue []byte
	remaining, key, rawValue, ok = T.ReadValue()
	if !ok {
		return
	}
	var err error
	value, err = strconv.Atoi(string(rawValue))
	if err != nil {
		remaining = T
		ok = false
		return
	}

	return
}
