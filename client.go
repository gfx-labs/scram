package scram

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/gfx-labs/scram/message"
)

var sha256Hasher Hasher = sha256.New

// ClientConfig configures a SCRAM client.
type ClientConfig struct {
	// Username is sent to the server. PostgreSQL clients usually send "".
	Username string
	// Authzid is an optional authorization identity.
	Authzid string

	// Lookup returns the client's keys for the salt and iteration count the
	// server offered. See ClientPasswordLookup and ClientKeysLookup.
	Lookup func(salt []byte, iters int) (ClientKeys, error)

	// ChannelBinding, if set, is used and required.
	ChannelBinding *ChannelBinding
	// ClientSupportsChannelBinding should be true when the client supports
	// channel binding but the server did not advertise it (for example
	// SCRAM-SHA-256 was offered without SCRAM-SHA-256-PLUS). This sends the
	// "y" flag so the server can detect a downgrade. Ignored if ChannelBinding is set.
	ClientSupportsChannelBinding bool

	// MinIters, MaxIters and MinSaltLen bound the parameters a server may send.
	// Zero selects DefaultMinIters, DefaultMaxIters and DefaultMinSaltLen.
	MinIters   int
	MaxIters   int
	MinSaltLen int
}

// ClientConversation is one client-side SCRAM exchange. It is not safe for concurrent use.
type ClientConversation struct {
	cfg ClientConfig

	state           convState
	gs2Header       string
	clientFirstBare string
	clientNonce     string

	keys        ClientKeys
	authMessage []byte
}

// NewClientConversation starts a client exchange.
func NewClientConversation(cfg ClientConfig) *ClientConversation {
	return &ClientConversation{cfg: cfg}
}

// Step returns the next client message. Call it first with nil to get the
// client-first-message, then with each server message. After the
// server-final-message it returns (nil, nil) and Done reports true. Any error
// ends the conversation.
func (c *ClientConversation) Step(in []byte) (out []byte, err error) {
	if c.cfg.Lookup == nil {
		c.state = stateFailed
		return nil, errors.New("scram: ClientConfig.Lookup is required")
	}
	switch c.state {
	case stateInitial:
		if in != nil {
			err = errors.New("scram: client speaks first")
		} else {
			out, err = c.first()
		}
	case stateFirstDone:
		out, err = c.final(string(in))
	case stateFinalSent:
		err = c.verify(string(in))
		c.wipe()
	default:
		return nil, ErrConversationFinished
	}
	if err != nil {
		c.state = stateFailed
		c.wipe()
		return nil, err
	}
	c.state++
	return out, nil
}

// Done reports whether the conversation has finished, successfully or not.
func (c *ClientConversation) Done() bool {
	return c.state == stateSucceeded || c.state == stateFailed
}

// Authenticated reports whether the server proved knowledge of the verifier.
func (c *ClientConversation) Authenticated() bool { return c.state == stateSucceeded }

func (c *ClientConversation) wipe() {
	c.keys = ClientKeys{}
	c.authMessage = nil
}

func (c *ClientConversation) first() ([]byte, error) {
	gs2 := message.GS2Header{CBFlag: message.CBNone, Authzid: c.cfg.Authzid}
	switch {
	case c.cfg.ChannelBinding != nil:
		gs2.CBFlag = message.CBUsed
		gs2.CBName = c.cfg.ChannelBinding.Type
	case c.cfg.ClientSupportsChannelBinding:
		gs2.CBFlag = message.CBUnsupported
	}
	c.clientNonce = newNonce()
	full, bare, err := message.ClientFirst{GS2: gs2, Username: c.cfg.Username, Nonce: c.clientNonce}.Encode()
	if err != nil {
		return nil, err
	}
	c.gs2Header = full[:len(full)-len(bare)]
	c.clientFirstBare = bare
	return []byte(full), nil
}

func (c *ClientConversation) final(in string) ([]byte, error) {
	sf, err := message.ParseServerFirst(in)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(sf.Nonce, c.clientNonce) || len(sf.Nonce) == len(c.clientNonce) {
		return nil, ErrNonceMismatch
	}
	info := KeyInfo{Salt: sf.Salt, Iters: sf.Iters}
	if err := info.checkPolicy(
		orDefault(c.cfg.MinIters, DefaultMinIters),
		orDefault(c.cfg.MaxIters, DefaultMaxIters),
		orDefault(c.cfg.MinSaltLen, DefaultMinSaltLen),
	); err != nil {
		return nil, err
	}

	keys, err := c.cfg.Lookup(sf.Salt, sf.Iters)
	if err != nil {
		return nil, err
	}
	if err := keys.Validate(); err != nil {
		return nil, err
	}

	cb := []byte(c.gs2Header)
	if c.cfg.ChannelBinding != nil {
		cb = append(cb, c.cfg.ChannelBinding.Data...)
	}
	msg := message.ClientFinal{ChannelBinding: cb, Nonce: sf.Nonce}
	withoutProof, err := msg.EncodeWithoutProof()
	if err != nil {
		return nil, err
	}
	h := keys.Hasher
	am := authMessage(c.clientFirstBare, in, withoutProof)
	msg.Proof = xor(keys.ClientKey, h.ClientSignature(h.StoredKey(keys.ClientKey), am))
	out, err := msg.Encode()
	if err != nil {
		return nil, err
	}
	c.keys = keys
	c.authMessage = am
	return []byte(out), nil
}

func (c *ClientConversation) verify(in string) error {
	sf, err := message.ParseServerFinal(in)
	if err != nil {
		return err
	}
	if sf.Err != "" {
		return fmt.Errorf("scram: server error: %w", sf.Err)
	}
	expected := c.keys.Hasher.ServerSignature(c.keys.ServerKey, c.authMessage)
	if !hmac.Equal(sf.Verifier, expected) {
		return ErrInvalidServerSignature
	}
	return nil
}
