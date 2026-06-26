package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/resend/resend-go/v3"
)

type resendMailer struct {
	apiKey string
	from   string
	client *resend.Client
}

func newResendMailer(apiKey, from string) *resendMailer {
	return &resendMailer{
		apiKey: apiKey,
		from:   from,
		client: resend.NewClient(apiKey),
	}
}

func (m *resendMailer) SendOTP(ctx context.Context, email, code string, expiresAt time.Time) error {
	expires := expiresAt.UTC().Format("15:04")
	params := &resend.SendEmailRequest{
		From:    m.from,
		To:      []string{email},
		Subject: "Your Orlop login code",
		Html:    otpEmailHTML(code, expires),
		Text:    otpEmailText(code, expires),
	}
	if _, err := m.client.Emails.SendWithContext(ctx, params); err != nil {
		return fmt.Errorf("resend send email: %w", err)
	}
	return nil
}

type logMailer struct {
	logger *slog.Logger
	// logCode includes the OTP in the log line. DEV ONLY (ORLOP_DEV_LOG_OTP=1):
	// a login OTP in the service log lets any log reader hijack a sign-in within
	// the code's TTL. Default false so a prod deploy that simply forgot to set
	// RESEND_API_KEY does not leak every OTP to its logs.
	logCode bool
}

func (m logMailer) SendOTP(_ context.Context, email, code string, expiresAt time.Time) error {
	attrs := []any{
		"event", "email_otp_delivery_skipped",
		"email", email,
		"expires_at", expiresAt,
	}
	if m.logCode {
		attrs = append(attrs, "code", code)
	} else {
		attrs = append(attrs, "note",
			"no mailer configured; set RESEND_API_KEY, or ORLOP_DEV_LOG_OTP=1 to log the code (dev only)")
	}
	m.logger.Info("email_otp_delivery_skipped", attrs...)
	return nil
}

// otpEmailHTML renders the login-code email. code is a server-generated 6-digit
// number and expires is a "15:04" UTC clock string, so neither needs escaping.
// We use a string replacer (not fmt) so the inline CSS can keep its "%" units.
func otpEmailHTML(code, expires string) string {
	return strings.NewReplacer("{{CODE}}", code, "{{EXPIRES}}", expires).Replace(otpEmailTemplate)
}

// otpEmailText is the plain-text fallback (and the part OS code-autofill reads).
func otpEmailText(code, expires string) string {
	return "Your Orlop login code\n\n    " + code + "\n\n" +
		"This code expires at " + expires + " UTC. For your security, don't share it with anyone.\n\n" +
		"If you didn't try to sign in, you can safely ignore this email — no one can access your account without this code.\n"
}

const otpEmailTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light only">
<title>Your Orlop login code</title>
</head>
<body style="margin:0;padding:0;background-color:#f5f5f5;-webkit-text-size-adjust:100%;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f5f5f5;">
  <tr>
    <td align="center" style="padding:40px 16px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:440px;background-color:#ffffff;border:1px solid #e5e5e5;border-radius:14px;">
        <tr>
          <td style="padding:32px 36px 0 36px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            <span style="font-size:19px;font-weight:700;letter-spacing:-0.02em;color:#0a0a0a;">Orlop</span><span style="display:inline-block;width:7px;height:7px;border-radius:50%;background-color:#a3e635;margin-left:3px;"></span>
          </td>
        </tr>
        <tr>
          <td style="padding:22px 36px 0 36px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            <div style="font-size:20px;font-weight:600;color:#0a0a0a;">Your login code</div>
            <div style="margin-top:6px;font-size:14px;line-height:22px;color:#737373;">Enter this code to finish signing in to Orlop.</div>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 36px 0 36px;">
            <div style="background-color:#fafafa;border:1px solid #e5e5e5;border-radius:10px;padding:20px 0;text-align:center;">
              <span style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace;font-size:34px;font-weight:700;letter-spacing:10px;color:#0a0a0a;padding-left:10px;">{{CODE}}</span>
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:18px 36px 0 36px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            <div style="font-size:13px;line-height:20px;color:#737373;">This code expires at <strong style="color:#0a0a0a;font-weight:600;">{{EXPIRES}} UTC</strong>. For your security, don&rsquo;t share it with anyone.</div>
          </td>
        </tr>
        <tr>
          <td style="padding:24px 36px 32px 36px;">
            <div style="border-top:1px solid #f0f0f0;padding-top:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:18px;color:#a3a3a3;">
              If you didn&rsquo;t try to sign in, you can safely ignore this email &mdash; no one can access your account without this code.
            </div>
          </td>
        </tr>
      </table>
      <div style="max-width:440px;padding:16px 36px 0 36px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:11px;color:#a3a3a3;text-align:center;">
        Orlop &middot; your agent&rsquo;s own computer
      </div>
    </td>
  </tr>
</table>
</body>
</html>`
