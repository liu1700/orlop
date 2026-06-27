package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
)

const userUsage = `usage:
  orlop-control user seed --tenant ID --email E [--database-url URL] [--base-url URL]
      Idempotent: creates the tenant if absent, the user if absent, and
      mints a fresh admin_session token. Prints a one-shot URL the
      operator pastes into a browser to register the session cookie.

  orlop-control user suspend --email E [--database-url URL]
      Marks the user suspended; outstanding access tokens stop validating
      on next use.

Reads DATABASE_URL from the environment if --database-url is not set.
`

func runUser(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New(userUsage)
	}
	switch args[0] {
	case "seed":
		return runUserSeed(ctx, out, args[1:])
	case "suspend":
		return runUserSuspend(ctx, out, args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(out, userUsage)
		return nil
	default:
		return fmt.Errorf("unknown user subcommand %q\n%s", args[0], userUsage)
	}
}

func runUserSeed(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("user seed", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tenantID := fs.String("tenant", "", "tenant id (required)")
	tenantName := fs.String("tenant-name", "", "tenant display name; defaults to tenant id")
	email := fs.String("email", "", "user email (required)")
	databaseURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string")
	baseURL := fs.String("base-url", "", "control-plane base URL for the printed admin session URL (e.g. https://control.orlop.example)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantID == "" || *email == "" {
		return errors.New("--tenant and --email are required")
	}
	if *databaseURL == "" {
		return errors.New("--database-url or DATABASE_URL is required")
	}
	if *tenantName == "" {
		*tenantName = *tenantID
	}

	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		return fmt.Errorf("open pgxpool: %w", err)
	}
	defer pool.Close()
	q := sqlcdb.New(pool)

	// Tenant: idempotent create.
	if _, err := q.GetTenant(ctx, *tenantID); err != nil {
		if !errors.Is(err, db.ErrNotFound) {
			return fmt.Errorf("get tenant: %w", err)
		}
		if _, err := q.CreateTenant(ctx, sqlcdb.CreateTenantParams{ID: *tenantID, Name: *tenantName}); err != nil {
			return fmt.Errorf("create tenant: %w", err)
		}
		fmt.Fprintf(out, "created tenant %s\n", *tenantID)
	}

	// User: idempotent create. CreateUser relies on the SQL DEFAULT
	// 'admin' role; admin is the only role under MVP.
	user, err := q.GetUserByEmail(ctx, *email)
	if errors.Is(err, db.ErrNotFound) {
		user, err = q.CreateUser(ctx, sqlcdb.CreateUserParams{Email: *email, TenantID: *tenantID})
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		fmt.Fprintf(out, "created user %s under tenant %s\n", *email, *tenantID)
	} else if err != nil {
		return fmt.Errorf("get user: %w", err)
	} else if user.TenantID != *tenantID {
		return fmt.Errorf("user %s is bound to tenant %s, not %s", *email, user.TenantID, *tenantID)
	}

	// Mint admin session token.
	svc := devauth.NewService(pool, nil)
	tok, expires, err := svc.IssueAdminSession(ctx, user.ID, *tenantID)
	if err != nil {
		return fmt.Errorf("issue admin session: %w", err)
	}

	fmt.Fprintf(out, "admin session token: %s\n", tok)
	fmt.Fprintf(out, "expires at:          %s\n", expires.Format("2006-01-02 15:04:05 MST"))
	if *baseURL != "" {
		u, err := url.Parse(*baseURL)
		if err != nil {
			return fmt.Errorf("parse --base-url: %w", err)
		}
		u.Path = "/device"
		q := u.Query()
		q.Set("session", tok)
		u.RawQuery = q.Encode()
		fmt.Fprintf(out, "approval URL:        %s\n", u.String())
	}
	return nil
}

func runUserSuspend(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("user suspend", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	email := fs.String("email", "", "user email (required)")
	databaseURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("--email is required")
	}
	if *databaseURL == "" {
		return errors.New("--database-url or DATABASE_URL is required")
	}

	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		return fmt.Errorf("open pgxpool: %w", err)
	}
	defer pool.Close()
	q := sqlcdb.New(pool)

	user, err := q.GetUserByEmail(ctx, *email)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if err := q.SuspendUser(ctx, user.ID); err != nil {
		return fmt.Errorf("suspend user: %w", err)
	}
	fmt.Fprintf(out, "suspended user %s\n", *email)
	return nil
}
