package errors

import (
	"fmt"
)

// ErrorType categorizes errors for retry logic
type ErrorType int

const (
	// ErrorTypeTransient indicates temporary failures that should be retried
	ErrorTypeTransient ErrorType = iota
	// ErrorTypePermanent indicates configuration errors that won't be fixed by retry
	ErrorTypePermanent
	// ErrorTypeConfig indicates invalid configuration
	ErrorTypeConfig
)

// OperatorError wraps errors with context and type information
type OperatorError struct {
	Type    ErrorType
	Message string
	Cause   error
	Context map[string]interface{}
}

func (e *OperatorError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *OperatorError) Unwrap() error {
	return e.Cause
}

// WithContext adds context to the error
func (e *OperatorError) WithContext(key string, value interface{}) *OperatorError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// NewTransientError creates a transient error
func NewTransientError(message string, cause error) *OperatorError {
	return &OperatorError{
		Type:    ErrorTypeTransient,
		Message: message,
		Cause:   cause,
	}
}

// NewPermanentError creates a permanent error
func NewPermanentError(message string, cause error) *OperatorError {
	return &OperatorError{
		Type:    ErrorTypePermanent,
		Message: message,
		Cause:   cause,
	}
}

// NewConfigError creates a configuration error
func NewConfigError(message string, cause error) *OperatorError {
	return &OperatorError{
		Type:    ErrorTypeConfig,
		Message: message,
		Cause:   cause,
	}
}

// ShouldRetry checks if an error should be retried
func ShouldRetry(err error) bool {
	if opErr, ok := err.(*OperatorError); ok {
		return opErr.Type == ErrorTypeTransient
	}
	// Default to retry for unknown errors
	return true
}
