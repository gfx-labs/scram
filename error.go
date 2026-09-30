package scram

type scramError string

func (T scramError) Error() string {
	return string(T)
}

var _ error = scramError("")

const (
	ErrInvalidEncoding                 scramError = "invalid-encoding"
	ErrExtensionsNotSupported          scramError = "extensions-not-supported"
	ErrInvalidProof                    scramError = "invalid-proof"
	ErrChannelBindingsDontMatch        scramError = "channel-bindings-dont-match"
	ErrServerDoesSupportChannelBinding scramError = "server-does-support-channel-binding"
	ErrChannelBindingNotSupported      scramError = "channel-binding-not-supported"
	ErrUnsupportedChannelBindingType   scramError = "unsupported-channel-binding-type"
	ErrUnknownUser                     scramError = "unknown-user"
	ErrInvalidUsernameEncoding         scramError = "invalid-username-encoding"
	ErrNoResources                     scramError = "no-resources"
	ErrOtherError                      scramError = "other-error"
)
