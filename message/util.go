package message

func StripClientFirstMessageHeader(message []byte) ([]byte, bool) {
	d := Decoder(message)

	var key rune
	var ok bool
	d, key, _, ok = d.ReadValue()
	if ok {
		if key != 'p' {
			return nil, false
		}
	} else {
		d, key, ok = d.ReadKey()
		if !ok {
			return nil, false
		}
		switch key {
		case 'n', 'y':
		default:
			return nil, false
		}
	}

	d, key, _, ok = d.ReadValue()
	if ok {
		if key != 'a' {
			return nil, false
		}
	} else {
		d, ok = d.ReadNull()
		if !ok {
			return nil, false
		}
	}

	return d, true
}

func StripClientFinalMessageProof(message []byte) ([]byte, bool) {
	d := Decoder(message)

	var key rune
	var ok bool
	d, key, _, ok = d.ReadValue()
	if !ok || key != 'c' {
		return nil, false
	}

	d, key, _, ok = d.ReadValue()
	if !ok || key != 'r' {
		return nil, false
	}

	return message[:len(message)-len(d)-1], true
}
