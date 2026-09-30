// Package message encodes and parses SCRAM messages as defined in RFC 5802 section 7.
package message

import (
	"strconv"
	"strings"
)

// Channel binding flags.
const (
	CBNone        = 'n' // client does not support channel binding
	CBUnsupported = 'y' // client supports it but thinks the server does not
	CBUsed        = 'p' // client requires channel binding
)

// GS2Header is the gs2-header that prefixes the client-first-message.
type GS2Header struct {
	CBFlag  byte   // CBNone, CBUnsupported or CBUsed
	CBName  string // channel binding type, set only with CBUsed
	Authzid string // decoded authorization identity, empty if absent
}

// Encode returns the wire form, including the trailing ','.
func (h GS2Header) Encode() (string, error) {
	var sb strings.Builder
	switch h.CBFlag {
	case CBNone, CBUnsupported:
		if h.CBName != "" {
			return "", ErrInvalidEncoding
		}
		sb.WriteByte(h.CBFlag)
	case CBUsed:
		if !isCBName(h.CBName) {
			return "", ErrUnsupportedChannelBindingType
		}
		sb.WriteString("p=" + h.CBName)
	default:
		return "", ErrInvalidEncoding
	}
	sb.WriteByte(',')
	if h.Authzid != "" {
		a, err := EncodeSaslname(h.Authzid)
		if err != nil {
			return "", err
		}
		sb.WriteString("a=" + a)
	}
	sb.WriteByte(',')
	return sb.String(), nil
}

// ClientFirst is the client-first-message.
type ClientFirst struct {
	GS2      GS2Header
	Username string // decoded
	Nonce    string
}

// Encode returns the full message and the client-first-message-bare used in AuthMessage.
func (m ClientFirst) Encode() (full, bare string, err error) {
	gs2, err := m.GS2.Encode()
	if err != nil {
		return "", "", err
	}
	user, err := EncodeSaslname(m.Username)
	if err != nil {
		return "", "", err
	}
	if m.Nonce == "" || !checkPrintable(m.Nonce) {
		return "", "", ErrInvalidEncoding
	}
	bare = "n=" + user + ",r=" + m.Nonce
	return gs2 + bare, bare, nil
}

// ParseClientFirst parses a client-first-message. It returns the raw gs2-header
// and client-first-message-bare exactly as received, for use in AuthMessage and
// channel binding verification.
func ParseClientFirst(msg string) (m ClientFirst, gs2Raw, bare string, err error) {
	if len(msg) > MaxMessageSize {
		return m, "", "", ErrInvalidEncoding
	}
	flag, rest, ok := strings.Cut(msg, ",")
	if !ok {
		return m, "", "", ErrInvalidEncoding
	}
	authz, bare, ok := strings.Cut(rest, ",")
	if !ok {
		return m, "", "", ErrInvalidEncoding
	}
	gs2Raw = msg[:len(flag)+len(authz)+2]

	switch {
	case flag == "n" || flag == "y":
		m.GS2.CBFlag = flag[0]
	case strings.HasPrefix(flag, "p="):
		m.GS2.CBFlag = CBUsed
		m.GS2.CBName = flag[2:]
		if !isCBName(m.GS2.CBName) {
			return m, "", "", ErrInvalidEncoding
		}
	default:
		return m, "", "", ErrInvalidEncoding
	}

	if authz != "" {
		if !strings.HasPrefix(authz, "a=") || len(authz) == 2 {
			return m, "", "", ErrInvalidEncoding
		}
		if m.GS2.Authzid, err = DecodeSaslname(authz[2:]); err != nil {
			return m, "", "", err
		}
	}

	attrs, err := parseAttrs(bare)
	if err != nil {
		return m, "", "", err
	}
	if attrs[0].key == 'm' {
		return m, "", "", ErrExtensionsNotSupported
	}
	if len(attrs) < 2 || attrs[0].key != 'n' || attrs[1].key != 'r' {
		return m, "", "", ErrInvalidEncoding
	}
	// libpq sends an empty username, since PostgreSQL takes it from the startup packet.
	if m.Username, err = DecodeSaslname(attrs[0].val); err != nil {
		return m, "", "", err
	}
	m.Nonce = attrs[1].val
	if m.Nonce == "" || !checkPrintable(m.Nonce) {
		return m, "", "", ErrInvalidEncoding
	}
	if err = checkExtensions(attrs[2:]); err != nil {
		return m, "", "", err
	}
	return m, gs2Raw, bare, nil
}

// ServerFirst is the server-first-message.
type ServerFirst struct {
	Nonce string // client nonce followed by server nonce
	Salt  []byte
	Iters int
}

func (m ServerFirst) Encode() (string, error) {
	if m.Nonce == "" || !checkPrintable(m.Nonce) || len(m.Salt) == 0 || m.Iters < 1 {
		return "", ErrInvalidEncoding
	}
	return "r=" + m.Nonce + ",s=" + b64.EncodeToString(m.Salt) + ",i=" + strconv.Itoa(m.Iters), nil
}

func ParseServerFirst(msg string) (m ServerFirst, err error) {
	attrs, err := parseAttrs(msg)
	if err != nil {
		return m, err
	}
	if attrs[0].key == 'm' {
		return m, ErrExtensionsNotSupported
	}
	if len(attrs) < 3 || attrs[0].key != 'r' || attrs[1].key != 's' || attrs[2].key != 'i' {
		return m, ErrInvalidEncoding
	}
	m.Nonce = attrs[0].val
	if m.Nonce == "" || !checkPrintable(m.Nonce) {
		return m, ErrInvalidEncoding
	}
	if m.Salt, err = decodeBase64(attrs[1].val); err != nil {
		return m, err
	}
	if m.Iters, err = parsePositiveInt(attrs[2].val); err != nil {
		return m, err
	}
	return m, checkExtensions(attrs[3:])
}

// ClientFinal is the client-final-message.
type ClientFinal struct {
	ChannelBinding []byte // gs2-header followed by channel binding data, if any
	Nonce          string
	Proof          []byte
}

// EncodeWithoutProof returns client-final-message-without-proof.
func (m ClientFinal) EncodeWithoutProof() (string, error) {
	if len(m.ChannelBinding) == 0 || m.Nonce == "" || !checkPrintable(m.Nonce) {
		return "", ErrInvalidEncoding
	}
	return "c=" + b64.EncodeToString(m.ChannelBinding) + ",r=" + m.Nonce, nil
}

func (m ClientFinal) Encode() (string, error) {
	s, err := m.EncodeWithoutProof()
	if err != nil {
		return "", err
	}
	if len(m.Proof) == 0 {
		return "", ErrInvalidEncoding
	}
	return s + ",p=" + b64.EncodeToString(m.Proof), nil
}

// ParseClientFinal parses a client-final-message and returns client-final-message-without-proof as received.
func ParseClientFinal(msg string) (m ClientFinal, withoutProof string, err error) {
	attrs, err := parseAttrs(msg)
	if err != nil {
		return m, "", err
	}
	if len(attrs) < 3 || attrs[0].key != 'c' || attrs[1].key != 'r' {
		return m, "", ErrInvalidEncoding
	}
	last := attrs[len(attrs)-1]
	if last.key != 'p' {
		return m, "", ErrInvalidEncoding
	}
	if m.ChannelBinding, err = decodeBase64(attrs[0].val); err != nil {
		return m, "", err
	}
	m.Nonce = attrs[1].val
	if m.Nonce == "" || !checkPrintable(m.Nonce) {
		return m, "", ErrInvalidEncoding
	}
	if m.Proof, err = decodeBase64(last.val); err != nil {
		return m, "", err
	}
	if err = checkExtensions(attrs[2 : len(attrs)-1]); err != nil {
		return m, "", err
	}
	withoutProof = msg[:len(msg)-len(last.val)-3]
	return m, withoutProof, nil
}

// ServerFinal is the server-final-message. Exactly one of Verifier or Err is set.
type ServerFinal struct {
	Verifier []byte
	Err      Error
}

func (m ServerFinal) Encode() (string, error) {
	switch {
	case m.Err != "" && m.Verifier == nil:
		if !checkValue(string(m.Err)) || m.Err == "" {
			return "", ErrInvalidEncoding
		}
		return "e=" + string(m.Err), nil
	case m.Err == "" && len(m.Verifier) != 0:
		return "v=" + b64.EncodeToString(m.Verifier), nil
	default:
		return "", ErrInvalidEncoding
	}
}

func ParseServerFinal(msg string) (m ServerFinal, err error) {
	attrs, err := parseAttrs(msg)
	if err != nil {
		return m, err
	}
	switch attrs[0].key {
	case 'e':
		if attrs[0].val == "" {
			return m, ErrInvalidEncoding
		}
		m.Err = Error(attrs[0].val)
	case 'v':
		if m.Verifier, err = decodeBase64(attrs[0].val); err != nil {
			return m, err
		}
	default:
		return m, ErrInvalidEncoding
	}
	return m, checkExtensions(attrs[1:])
}

// checkExtensions accepts optional extensions and rejects mandatory ones.
// Attributes defined by RFC 5802 may not be repeated as extensions.
func checkExtensions(attrs []attr) error {
	for _, a := range attrs {
		switch a.key {
		case 'm':
			return ErrExtensionsNotSupported
		case 'a', 'n', 'r', 'c', 's', 'i', 'p', 'v', 'e':
			return ErrInvalidEncoding
		}
	}
	return nil
}
