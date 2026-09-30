package message

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxMessageSize bounds every message accepted by the parsers.
const MaxMessageSize = 8192

var b64 = base64.StdEncoding.Strict()

type attr struct {
	key byte
	val string
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// checkValue enforces the RFC 5802 value grammar: UTF-8 without NUL or ','.
func checkValue(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsAny(s, "\x00,")
}

// checkPrintable enforces the RFC 5802 printable grammar: %x21-2B / %x2D-7E.
func checkPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == ',' {
			return false
		}
	}
	return true
}

func parseAttrs(msg string) ([]attr, error) {
	if len(msg) > MaxMessageSize || !checkValue(strings.ReplaceAll(msg, ",", "")) {
		return nil, ErrInvalidEncoding
	}
	parts := strings.Split(msg, ",")
	out := make([]attr, len(parts))
	for i, p := range parts {
		if len(p) < 2 || !isAlpha(p[0]) || p[1] != '=' {
			return nil, ErrInvalidEncoding
		}
		out[i] = attr{key: p[0], val: p[2:]}
	}
	return out, nil
}

func decodeBase64(s string) ([]byte, error) {
	// encoding/base64 skips '\r' and '\n' even in strict mode. The RFC base64 grammar does not allow them.
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return nil, ErrInvalidEncoding
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	return b, nil
}

// parsePositiveInt parses posit-number = %x31-39 *DIGIT.
func parsePositiveInt(s string) (int, error) {
	if s == "" || s[0] == '0' || strings.TrimLeft(s, "0123456789") != "" {
		return 0, ErrInvalidEncoding
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, ErrInvalidEncoding
	}
	return n, nil
}

var saslnameEncoder = strings.NewReplacer("=", "=3D", ",", "=2C")

// EncodeSaslname escapes '=' and ',' in a username or authzid.
func EncodeSaslname(s string) (string, error) {
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return "", ErrInvalidUsernameEncoding
	}
	return saslnameEncoder.Replace(s), nil
}

// DecodeSaslname reverses EncodeSaslname. Any '=' not followed by "2C" or "3D" is rejected.
func DecodeSaslname(s string) (string, error) {
	if !checkValue(s) {
		return "", ErrInvalidUsernameEncoding
	}
	var sb strings.Builder
	for {
		before, after, found := strings.Cut(s, "=")
		sb.WriteString(before)
		if !found {
			return sb.String(), nil
		}
		switch {
		case strings.HasPrefix(after, "2C"):
			sb.WriteByte(',')
		case strings.HasPrefix(after, "3D"):
			sb.WriteByte('=')
		default:
			return "", ErrInvalidUsernameEncoding
		}
		s = after[2:]
	}
}

func isCBName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !(c >= '0' && c <= '9') && c != '.' && c != '-' {
			return false
		}
	}
	return true
}
