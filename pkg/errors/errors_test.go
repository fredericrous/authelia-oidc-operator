package errors

import (
	"errors"
	"testing"
)

func TestOperatorError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *OperatorError
		wantMsg string
	}{
		{"message only", &OperatorError{Message: "boom"}, "boom"},
		{"with cause", NewTransientError("outer", errors.New("inner")), "outer: inner"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}

func TestOperatorError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	wrapped := NewTransientError("outer", cause)
	if !errors.Is(wrapped, cause) {
		t.Errorf("errors.Is should match the wrapped cause; Unwrap returned %v", wrapped.Unwrap())
	}
	// Unwrap of an error with no cause should be nil.
	noCause := &OperatorError{Message: "bare"}
	if noCause.Unwrap() != nil {
		t.Errorf("Unwrap on cause-less error should be nil, got %v", noCause.Unwrap())
	}
}

func TestOperatorError_WithContext(t *testing.T) {
	e := NewPermanentError("msg", nil)
	e.WithContext("resource", "OIDCClient").WithContext("name", "duro")
	if e.Context["resource"] != "OIDCClient" || e.Context["name"] != "duro" {
		t.Errorf("Context not populated: %+v", e.Context)
	}
}

func TestConstructors_Type(t *testing.T) {
	cases := map[ErrorType]*OperatorError{
		ErrorTypeTransient: NewTransientError("a", nil),
		ErrorTypePermanent: NewPermanentError("b", nil),
		ErrorTypeConfig:    NewConfigError("c", nil),
	}
	for want, err := range cases {
		if err.Type != want {
			t.Errorf("constructor produced wrong type: got %d want %d", err.Type, want)
		}
	}
}

func TestShouldRetry(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"transient retries", NewTransientError("x", nil), true},
		{"permanent does not retry", NewPermanentError("x", nil), false},
		{"config does not retry", NewConfigError("x", nil), false},
		{"plain error defaults to retry", errors.New("unknown"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRetry(tc.err); got != tc.want {
				t.Errorf("ShouldRetry(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
