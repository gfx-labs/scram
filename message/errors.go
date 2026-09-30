package message

// Error is a SCRAM server-error-value (RFC 5802 section 7).
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidEncoding                 Error = "invalid-encoding"
	ErrExtensionsNotSupported          Error = "extensions-not-supported"
	ErrInvalidProof                    Error = "invalid-proof"
	ErrChannelBindingsDontMatch        Error = "channel-bindings-dont-match"
	ErrServerDoesSupportChannelBinding Error = "server-does-support-channel-binding"
	ErrChannelBindingNotSupported      Error = "channel-binding-not-supported"
	ErrUnsupportedChannelBindingType   Error = "unsupported-channel-binding-type"
	ErrUnknownUser                     Error = "unknown-user"
	ErrInvalidUsernameEncoding         Error = "invalid-username-encoding"
	ErrNoResources                     Error = "no-resources"
	ErrOtherError                      Error = "other-error"
)
