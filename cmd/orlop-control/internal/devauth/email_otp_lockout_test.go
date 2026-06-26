package devauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

type captureMailer struct{ code string }

func (m *captureMailer) SendOTP(_ context.Context, _, code string, _ time.Time) error {
	m.code = code
	return nil
}

func otherCode(real string) string {
	if real == "000000" {
		return "111111"
	}
	return "000000"
}

func TestEmailOTPLocksOutAfterRepeatedWrongGuesses(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(pool, nil)
	ctx := context.Background()
	m := &captureMailer{}
	email := "lockout@example.com"
	if err := svc.StartEmailOTP(ctx, email, m); err != nil {
		t.Fatalf("StartEmailOTP: %v", err)
	}
	wrong := otherCode(m.code)

	locked := false
	for i := 0; i < 10; i++ {
		_, err := svc.VerifyEmailOTP(ctx, email, wrong)
		if errors.Is(err, devauth.ErrEmailOTPConsumed) {
			locked = true
			break
		}
		if !errors.Is(err, devauth.ErrEmailOTPInvalid) {
			t.Fatalf("wrong guess %d: got %v, want ErrEmailOTPInvalid", i, err)
		}
	}
	if !locked {
		t.Fatal("OTP was never locked out after repeated wrong guesses")
	}
	// The correct code is rejected too — the code is dead, not merely throttled.
	if _, err := svc.VerifyEmailOTP(ctx, email, m.code); !errors.Is(err, devauth.ErrEmailOTPConsumed) {
		t.Fatalf("correct code after lockout: got %v, want ErrEmailOTPConsumed", err)
	}
}

func TestEmailOTPAcceptsCorrectCodeWithinBudget(t *testing.T) {
	pool := openTestPool(t)
	svc := devauth.NewService(pool, nil)
	ctx := context.Background()
	m := &captureMailer{}
	email := "withinbudget@example.com"
	if err := svc.StartEmailOTP(ctx, email, m); err != nil {
		t.Fatalf("StartEmailOTP: %v", err)
	}
	// One wrong guess, then the correct code still works.
	if _, err := svc.VerifyEmailOTP(ctx, email, otherCode(m.code)); !errors.Is(err, devauth.ErrEmailOTPInvalid) {
		t.Fatalf("wrong guess: got %v, want ErrEmailOTPInvalid", err)
	}
	if _, err := svc.VerifyEmailOTP(ctx, email, m.code); err != nil {
		t.Fatalf("correct code within budget: got %v, want success", err)
	}
}
