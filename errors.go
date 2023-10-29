package tinyauth

import "fmt"

// ErrType categorizes the Err stored in tinyauth.Error.
type ErrType int

const (
	// ErrBadInput indicates that input was invalid.
	ErrBadInput ErrType = iota

	// ErrAuthFailed indicates that the authentication failed.
	ErrAuthFailed

	// ErrInternal indicates that an error was neither recognized as bad input
	// nor as explicit auth failure (for example, a data store was unreachable).
	ErrInternal
)

// Error is an augmenting wrapper error type.
type Error struct {
	Msg string
	Err error
	ErrType
}

// Error returns the string representation of the tinyauth.Error.
func (l *Error) Error() string {
	return fmt.Sprintf("%s: %s", l.Msg, l.Err.Error())
}

// Unwrap returns the wrapped error inside the tinyauth.Error.
func (l *Error) Unwrap() error { return l.Err }

// NewErrorBadInput constructs an Error with ErrType ErrBadInput.
func NewErrorBadInput(msg string, err error) *Error {
	return &Error{
		Msg:     msg,
		Err:     err,
		ErrType: ErrBadInput,
	}
}

// NewErrorBadInput constructs an Error with ErrType ErrInternal.
func NewErrorInternal(msg string, err error) *Error {
	return &Error{
		Msg:     msg,
		Err:     err,
		ErrType: ErrInternal,
	}
}

// NewErrorBadInput constructs an Error with ErrType ErrAuthFailed.
func NewErrorAuthFailed(msg string, err error) *Error {
	return &Error{
		Msg:     msg,
		Err:     err,
		ErrType: ErrAuthFailed,
	}
}
