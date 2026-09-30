package scram

import (
	"errors"

	"github.com/gfx-labs/scram/message"
)

// Error is a SCRAM server-error-value. It is safe to send to the peer.
type Error = message.Error

// SCRAM server-error-values (RFC 5802 section 7).
const (
	ErrInvalidEncoding                 = message.ErrInvalidEncoding
	ErrExtensionsNotSupported          = message.ErrExtensionsNotSupported
	ErrInvalidProof                    = message.ErrInvalidProof
	ErrChannelBindingsDontMatch        = message.ErrChannelBindingsDontMatch
	ErrServerDoesSupportChannelBinding = message.ErrServerDoesSupportChannelBinding
	ErrChannelBindingNotSupported      = message.ErrChannelBindingNotSupported
	ErrUnsupportedChannelBindingType   = message.ErrUnsupportedChannelBindingType
	ErrUnknownUser                     = message.ErrUnknownUser
	ErrInvalidUsernameEncoding         = message.ErrInvalidUsernameEncoding
	ErrNoResources                     = message.ErrNoResources
	ErrOtherError                      = message.ErrOtherError
)

// Local errors. These describe configuration or peer misbehavior and are not sent on the wire.
var (
	ErrInvalidKeys            = errors.New("scram: keys are missing or have the wrong length")
	ErrIterationsOutOfRange   = errors.New("scram: iteration count out of range")
	ErrSaltTooShort           = errors.New("scram: salt too short")
	ErrNonceMismatch          = errors.New("scram: nonce mismatch")
	ErrInvalidServerSignature = errors.New("scram: invalid server signature")
	ErrAuthzidNotAllowed      = errors.New("scram: authorization identity not allowed")
	ErrConversationFinished   = errors.New("scram: conversation already finished")
)
