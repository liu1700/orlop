package client

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	// ErrNotFound matches API errors for resources that do not exist.
	ErrNotFound = errors.New("orlop: not found")
	// ErrConflict matches HTTP 409 responses.
	ErrConflict = errors.New("orlop: conflict")
	// ErrUnauthorized matches HTTP 401 responses.
	ErrUnauthorized = errors.New("orlop: unauthorized")
	// ErrForbidden matches HTTP 403 responses.
	ErrForbidden = errors.New("orlop: forbidden")
	// ErrRateLimited matches HTTP 429 responses.
	ErrRateLimited = errors.New("orlop: rate limited")
	// ErrQuotaExceeded matches the stable quota_exceeded API code.
	ErrQuotaExceeded = errors.New("orlop: quota exceeded")
	// ErrInsufficientCapacity matches the stable insufficient_capacity API code.
	ErrInsufficientCapacity = errors.New("orlop: insufficient capacity")
)

// APIError is returned for a non-2xx control-plane response. Callers can use
// errors.As to inspect the response and errors.Is with the sentinels above for
// common branches.
type APIError struct {
	Op         string
	Method     string
	Path       string
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	// Header is a clone of the response headers. It lets callers inspect
	// server-specific diagnostics without coupling the SDK to every header.
	Header http.Header
	// Body is the bounded (at most 64 KiB) raw response body. It preserves
	// diagnostics from newer servers whose error fields this SDK does not yet
	// understand.
	Body string
	// RetryAfter is the server-requested delay parsed from Retry-After. Zero
	// means the header was absent, invalid, or already elapsed.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	prefix := "orlop"
	if e.Op != "" {
		prefix += " " + e.Op
	}
	if e.Method != "" || e.Path != "" {
		prefix += fmt.Sprintf(" %s %s", e.Method, e.Path)
	}
	prefix += fmt.Sprintf(": status %d", e.StatusCode)
	if e.Code != "" {
		prefix += " (" + e.Code + ")"
	}
	if e.Message != "" {
		prefix += ": " + e.Message
	}
	return prefix
}

// Is maps status codes and stable server error codes to package sentinels.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound || e.Code == "not_found"
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests || e.Code == "rate_limited"
	case ErrQuotaExceeded:
		return e.Code == "quota_exceeded"
	case ErrInsufficientCapacity:
		return e.Code == "insufficient_capacity"
	default:
		return false
	}
}

// Retryable reports whether the HTTP response represents a normally transient
// condition. It does not decide whether replaying the operation is safe;
// transport errors and operation idempotency remain the caller's responsibility.
func (e *APIError) Retryable() bool {
	switch e.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func fakeNotFound(op, path, message string) error {
	return &APIError{
		Op:         op,
		Path:       path,
		StatusCode: http.StatusNotFound,
		Code:       "not_found",
		Message:    message,
	}
}
