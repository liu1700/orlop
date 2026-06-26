package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLogMailerOmitsOTPByDefault(t *testing.T) {
	var buf bytes.Buffer
	m := logMailer{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	if err := m.SendOTP(context.Background(), "you@example.com", "654321", time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "654321") {
		t.Fatalf("OTP code leaked to the log by default: %q", out)
	}
	if !strings.Contains(out, "you@example.com") {
		t.Fatalf("expected the email in the log line: %q", out)
	}
}

func TestLogMailerLogsOTPWhenDevFlagSet(t *testing.T) {
	var buf bytes.Buffer
	m := logMailer{logger: slog.New(slog.NewTextHandler(&buf, nil)), logCode: true}
	if err := m.SendOTP(context.Background(), "you@example.com", "654321", time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "654321") {
		t.Fatalf("dev flag set but OTP not logged: %q", buf.String())
	}
}
