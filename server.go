package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"sync"

	"github.com/gfx-labs/scram/message"
)

// ServerConfig configures a SCRAM server. It is safe to share between conversations.
type ServerConfig struct {
	// Lookup returns the stored keys for a username. Return ErrUnknownUser if the
	// user does not exist. The server then runs a mock exchange so unknown users
	// cannot be told apart from a wrong password. Other errors abort the exchange.
	Lookup func(username string) (ServerKeys, error)

	// ChannelBinding is the channel binding the server supports, or nil for none.
	ChannelBinding *ChannelBinding
	// RequireChannelBinding rejects clients that do not use channel binding.
	RequireChannelBinding bool

	// Authorize decides whether username may act as authzid. It runs only
	// after the client has proved its identity. If nil, any non-empty authzid
	// is rejected.
	Authorize func(username, authzid string) error

	// MockSecret keys the fake salt for unknown users. If nil a random
	// per-process secret is used, so fake salts change across restarts.
	MockSecret []byte
	// MockHasher and MockIters describe the fake verifier for unknown users.
	// They should match real users. Defaults: sha256, DefaultMinIters.
	MockHasher Hasher
	MockIters  int

	// MinIters and MinSaltLen reject weak stored keys. Zero selects
	// DefaultMinIters and DefaultMinSaltLen. Set 1 to disable.
	MinIters   int
	MinSaltLen int
}

var (
	processMockSecret     []byte
	processMockSecretOnce sync.Once
)

func (c *ServerConfig) validate() error {
	if c == nil || c.Lookup == nil {
		return errors.New("scram: ServerConfig.Lookup is required")
	}
	if c.RequireChannelBinding && c.ChannelBinding == nil {
		return errors.New("scram: RequireChannelBinding set without ChannelBinding")
	}
	return nil
}

func (c *ServerConfig) mockKeys(username string) ServerKeys {
	secret := c.MockSecret
	if secret == nil {
		processMockSecretOnce.Do(func() {
			processMockSecret = make([]byte, 32)
			rand.Read(processMockSecret)
		})
		secret = processMockSecret
	}
	h := c.MockHasher
	if h == nil {
		h = sha256Hasher
	}
	salt := Hasher(sha256Hasher).HMAC(secret, []byte("salt:"+username))[:DefaultSaltLen]
	keys := ServerKeys{
		StoredKey: make([]byte, h.Size()),
		ServerKey: make([]byte, h.Size()),
		KeyInfo:   KeyInfo{Salt: salt, Iters: orDefault(c.MockIters, DefaultMinIters), Hasher: h},
	}
	rand.Read(keys.StoredKey)
	rand.Read(keys.ServerKey)
	return keys
}

type convState int

const (
	stateInitial convState = iota
	stateFirstDone
	stateFinalSent // client only
	stateSucceeded
	stateFailed
)

// ServerConversation is one server-side SCRAM exchange. It is not safe for concurrent use.
type ServerConversation struct {
	cfg *ServerConfig

	state    convState
	keys     ServerKeys
	mock     bool
	username string
	// requested authzid, approved only after the proof is verified
	authzid string

	gs2Header       string
	clientFirstBare string
	serverFirst     string
	nonce           string

	clientKey []byte
}

// NewServerConversation starts a server exchange. The config must not be modified afterwards.
func NewServerConversation(cfg *ServerConfig) *ServerConversation {
	return &ServerConversation{cfg: cfg}
}

// Step processes a client message and returns the reply. On the final step a
// failure may return both a server-final-message carrying e= and an error.
// Any error ends the conversation.
func (s *ServerConversation) Step(in []byte) (out []byte, err error) {
	if err := s.cfg.validate(); err != nil {
		s.fail()
		return nil, err
	}
	switch s.state {
	case stateInitial:
		out, err = s.first(string(in))
		if err != nil {
			s.fail()
			return nil, err
		}
		s.state = stateFirstDone
		return out, nil
	case stateFirstDone:
		out, err = s.final(string(in))
		if err != nil {
			s.fail()
			var e Error
			if !errors.As(err, &e) {
				e = ErrOtherError
			}
			msg, _ := message.ServerFinal{Err: e}.Encode()
			return []byte(msg), err
		}
		s.state = stateSucceeded
		return out, nil
	default:
		return nil, ErrConversationFinished
	}
}

// Done reports whether the conversation has finished, successfully or not.
func (s *ServerConversation) Done() bool { return s.state >= stateSucceeded }

// Authenticated reports whether the client proved knowledge of the password.
func (s *ServerConversation) Authenticated() bool { return s.state == stateSucceeded }

// Username returns the username sent by the client.
func (s *ServerConversation) Username() string { return s.username }

// Authzid returns the authorization identity approved by Authorize, or "" if
// none was requested or the client has not authenticated.
func (s *ServerConversation) Authzid() string {
	if s.state != stateSucceeded {
		return ""
	}
	return s.authzid
}

// ClientKeys returns the client's keys recovered from its proof, or an error
// if the client has not authenticated. The keys are password-equivalent: they
// can be used to authenticate as this user to any server sharing the verifier.
func (s *ServerConversation) ClientKeys() (ClientKeys, error) {
	if s.state != stateSucceeded {
		return ClientKeys{}, ErrInvalidProof
	}
	return ClientKeys{
		ClientKey: append([]byte(nil), s.clientKey...),
		ServerKey: append([]byte(nil), s.keys.ServerKey...),
		KeyInfo: KeyInfo{
			Salt:   append([]byte(nil), s.keys.Salt...),
			Iters:  s.keys.Iters,
			Hasher: s.keys.Hasher,
		},
	}, nil
}

func (s *ServerConversation) fail() {
	s.state = stateFailed
	clear(s.clientKey)
	s.clientKey = nil
}

func (s *ServerConversation) first(in string) ([]byte, error) {
	cf, gs2, bare, err := message.ParseClientFirst(in)
	if err != nil {
		return nil, err
	}

	cb := s.cfg.ChannelBinding
	switch cf.GS2.CBFlag {
	case message.CBNone:
		if s.cfg.RequireChannelBinding {
			return nil, ErrChannelBindingsDontMatch
		}
	case message.CBUnsupported:
		// The client could have used channel binding but believes we do not support it: a downgrade.
		if cb != nil {
			return nil, ErrServerDoesSupportChannelBinding
		}
		if s.cfg.RequireChannelBinding {
			return nil, ErrChannelBindingsDontMatch
		}
	case message.CBUsed:
		if cb == nil {
			return nil, ErrChannelBindingNotSupported
		}
		if cf.GS2.CBName != cb.Type {
			return nil, ErrUnsupportedChannelBindingType
		}
	}

	// Rejecting here depends only on config, so it reveals nothing about the user.
	if cf.GS2.Authzid != "" && s.cfg.Authorize == nil {
		return nil, ErrAuthzidNotAllowed
	}
	s.authzid = cf.GS2.Authzid

	keys, err := s.cfg.Lookup(cf.Username)
	switch {
	case errors.Is(err, ErrUnknownUser):
		s.mock = true
		keys = s.cfg.mockKeys(cf.Username)
	case err != nil:
		return nil, err
	default:
		if err := keys.Validate(); err != nil {
			return nil, err
		}
		if err := keys.checkPolicy(orDefault(s.cfg.MinIters, DefaultMinIters), 0, orDefault(s.cfg.MinSaltLen, DefaultMinSaltLen)); err != nil {
			return nil, err
		}
	}

	nonce := cf.Nonce + newNonce()
	sf, err := message.ServerFirst{Nonce: nonce, Salt: keys.Salt, Iters: keys.Iters}.Encode()
	if err != nil {
		return nil, err
	}

	s.keys = keys
	s.username = cf.Username
	s.gs2Header = gs2
	s.clientFirstBare = bare
	s.serverFirst = sf
	s.nonce = nonce
	return []byte(sf), nil
}

func (s *ServerConversation) final(in string) ([]byte, error) {
	cf, withoutProof, err := message.ParseClientFinal(in)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(cf.Nonce), []byte(s.nonce)) != 1 {
		return nil, ErrInvalidProof
	}

	expectedCB := []byte(s.gs2Header)
	if s.cfg.ChannelBinding != nil && s.gs2Header[0] == message.CBUsed {
		expectedCB = append(expectedCB, s.cfg.ChannelBinding.Data...)
	}
	if !hmac.Equal(cf.ChannelBinding, expectedCB) {
		return nil, ErrChannelBindingsDontMatch
	}

	h := s.keys.Hasher
	am := authMessage(s.clientFirstBare, s.serverFirst, withoutProof)
	clientSig := h.ClientSignature(s.keys.StoredKey, am)
	clientKey := xor(cf.Proof, clientSig)
	if clientKey == nil {
		return nil, ErrInvalidProof
	}
	if !hmac.Equal(h.StoredKey(clientKey), s.keys.StoredKey) || s.mock {
		clear(clientKey)
		return nil, ErrInvalidProof
	}
	if s.authzid != "" {
		if err := s.cfg.Authorize(s.username, s.authzid); err != nil {
			clear(clientKey)
			return nil, errors.Join(ErrAuthzidNotAllowed, err)
		}
	}
	s.clientKey = clientKey

	out, err := message.ServerFinal{Verifier: h.ServerSignature(s.keys.ServerKey, am)}.Encode()
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}
