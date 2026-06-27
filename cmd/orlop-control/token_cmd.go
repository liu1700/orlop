package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/devauth"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage"
	"github.com/liu1700/orlop/cmd/orlop-control/internal/storage/postgres"
)

// defaultOwnerID is the demo account a standalone `token issue` provisions
// under when no --owner is given. A fixed UUID keeps repeated runs idempotent
// (one owner, many agents) without the caller having to mint and remember one.
const defaultOwnerID = "00000000-0000-0000-0000-000000000001"

// defaultGrantBytes is the initial disk grant a standalone allocation gets when
// --size is not set (1 GiB).
const defaultGrantBytes int64 = 1 << 30

const tokenUsage = `usage:
  orlop-control token issue --agent ID [--owner UUID] [--size BYTES]
                                  [--control-plane URL] [--mount-point PATH]
                                  [--database-url URL] [--json]

      Standalone path: provision an agent's disk allocation (idempotently) and
      mint a short-lived, agent-scoped enroll token for it — no external control
      plane or OAuth device flow needed. Trade the token at orlop-control
      server with ` + "`orlop mount --from-env`" + `.

      Possession of DATABASE_URL is the operator credential here, the same trust
      model as ` + "`user seed`" + ` and ` + "`ca init`" + `. The token is short-lived
      (` + "10m" + ` by design); mount promptly.

Reads DATABASE_URL from the environment if --database-url is not set.
`

func runToken(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New(tokenUsage)
	}
	switch args[0] {
	case "issue":
		return runTokenIssue(ctx, out, args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(out, tokenUsage)
		return nil
	default:
		return fmt.Errorf("unknown token subcommand %q\n%s", args[0], tokenUsage)
	}
}

func runTokenIssue(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	agentID := fs.String("agent", "", "agent id (required)")
	ownerID := fs.String("owner", defaultOwnerID, "owner account uuid")
	size := fs.Int64("size", defaultGrantBytes, "initial disk grant in bytes")
	controlPlane := fs.String("control-plane", "http://localhost:8080", "control-plane base URL printed in the ready-to-mount env block")
	mountPoint := fs.String("mount-point", "./agent-disk", "mount point printed in the ready-to-mount env block")
	databaseURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string")
	asJSON := fs.Bool("json", false, "print a machine-readable result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID == "" {
		return errors.New("--agent is required")
	}
	if *databaseURL == "" {
		return errors.New("--database-url or DATABASE_URL is required")
	}
	if *size <= 0 {
		*size = defaultGrantBytes
	}

	ownerUUID, err := uuid.Parse(*ownerID)
	if err != nil {
		return fmt.Errorf("--owner must be a uuid: %w", err)
	}

	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		return fmt.Errorf("open pgxpool: %w", err)
	}
	defer pool.Close()
	store := postgres.New(pool)

	// Provision the agent's disk the same way the service-to-service entity API
	// does (handleProvision), so the enroll token references a real allocation:
	// owner tenant -> owner user -> per-agent tenant -> agent allocation. Every
	// step is idempotent, so re-issuing for the same agent just reuses the rows.
	ownerTenant := tenantIDForOwner(*ownerID)
	if err := store.EnsureTenant(ctx, ownerTenant, ownerTenant); err != nil {
		return fmt.Errorf("ensure owner tenant: %w", err)
	}
	if err := store.EnsureUserWithID(ctx, storage.NewUser{
		ID:       ownerUUID,
		TenantID: ownerTenant,
		Email:    syntheticUserEmail(*ownerID),
	}); err != nil {
		return fmt.Errorf("ensure owner user: %w", err)
	}
	agentTenant := tenantForAgent(*agentID)
	if err := store.EnsureTenant(ctx, agentTenant, agentTenant); err != nil {
		return fmt.Errorf("ensure agent tenant: %w", err)
	}
	alloc, err := store.UpsertAgentAllocation(ctx, storage.NewAgentAllocation{
		UserID:    ownerUUID,
		AgentID:   *agentID,
		TenantID:  agentTenant,
		SizeBytes: *size,
	})
	if err != nil {
		return fmt.Errorf("upsert agent allocation: %w", err)
	}

	// Scope the token (and the cert it's traded for) to the agent's own tenant,
	// matching handleEnrollToken so /agent/enroll mints the per-agent SAN.
	svc := devauth.NewService(store, nil)
	token, expiresAt, err := svc.IssueAgentEnrollToken(ctx, fromUUID(ownerUUID), agentTenant, fromUUID(alloc.ID))
	if err != nil {
		return fmt.Errorf("mint enroll token: %w", err)
	}

	if *asJSON {
		return json.NewEncoder(out).Encode(struct {
			Token        string `json:"token"`
			ExpiresAt    string `json:"expires_at"`
			AgentID      string `json:"agent_id"`
			AllocationID string `json:"allocation_id"`
			ControlPlane string `json:"control_plane"`
		}{
			Token:        token,
			ExpiresAt:    expiresAt.UTC().Format(time.RFC3339),
			AgentID:      *agentID,
			AllocationID: alloc.ID.String(),
			ControlPlane: *controlPlane,
		})
	}

	fmt.Fprintf(out, "enroll token:  %s\n", token)
	fmt.Fprintf(out, "expires at:    %s\n", expiresAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(out, "agent id:      %s\n", *agentID)
	fmt.Fprintf(out, "allocation:    %s\n", alloc.ID.String())
	fmt.Fprintln(out)
	fmt.Fprintln(out, "mount it with:")
	fmt.Fprintf(out, "  export ORLOP_AGENT_ID=%s\n", *agentID)
	fmt.Fprintf(out, "  export ORLOP_MOUNT_POINT=%s\n", *mountPoint)
	fmt.Fprintf(out, "  export ORLOP_CONTROL_PLANE=%s\n", *controlPlane)
	fmt.Fprintf(out, "  export ORLOP_ENROLL_TOKEN=%s\n", token)
	fmt.Fprintf(out, "  orlop mount --from-env\n")
	return nil
}
