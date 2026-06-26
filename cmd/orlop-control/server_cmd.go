package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/liu1700/orlop/cmd/orlop-control/internal/db/sqlcdb"
)

// defaultServerTotalBytes is the capacity a standalone `server register` claims
// for the single data-plane node when --total-bytes is not set (10 GiB). It is
// the pool budget agent allocations are placed against, not a hard disk limit.
const defaultServerTotalBytes int64 = 10 << 30

const serverUsage = `usage:
  orlop-control server register [--data-addr HOST:PORT] [--ops-addr HOST:PORT]
                                      [--total-bytes N] [--status STATUS]
                                      [--database-url URL] [--json]

      Standalone path: register a data-plane server in the placement pool so
      ` + "`/agent/enroll`" + ` can place agents on it. Without a pool entry, enroll has
      nowhere to put a disk and returns 503. Idempotent on --data-addr (re-run
      to update ops-addr / capacity / status).

      --data-addr is where AGENTS reach the server (must match the server's TLS
      cert SAN, i.e. its tls.fqdn). --ops-addr is where the CONTROL plane reaches
      the server's ops API over mTLS. For a single local node both use the same
      host (e.g. localhost) so one self-provisioned cert covers both.

      Possession of DATABASE_URL is the operator credential here, the same trust
      model as ` + "`user seed`" + ` and ` + "`ca init`" + `.

Reads DATABASE_URL from the environment if --database-url is not set.
`

func runServer(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New(serverUsage)
	}
	switch args[0] {
	case "register":
		return runServerRegister(ctx, out, args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(out, serverUsage)
		return nil
	default:
		return fmt.Errorf("unknown server subcommand %q\n%s", args[0], serverUsage)
	}
}

func runServerRegister(ctx context.Context, out io.Writer, args []string) error {
	fs := flag.NewFlagSet("server register", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dataAddr := fs.String("data-addr", "localhost:8443", "address agents dial for the data plane (matches the server's tls.fqdn)")
	opsAddr := fs.String("ops-addr", "localhost:7878", "address the control plane dials for the server's ops API")
	totalBytes := fs.Int64("total-bytes", defaultServerTotalBytes, "pool capacity in bytes")
	status := fs.String("status", "available", "pool status; only 'available' servers are picked for placement")
	databaseURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string")
	asJSON := fs.Bool("json", false, "print a machine-readable result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *databaseURL == "" {
		return errors.New("--database-url or DATABASE_URL is required")
	}
	if *dataAddr == "" || *opsAddr == "" {
		return errors.New("--data-addr and --ops-addr are required")
	}
	if *totalBytes <= 0 {
		*totalBytes = defaultServerTotalBytes
	}

	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		return fmt.Errorf("open pgxpool: %w", err)
	}
	defer pool.Close()
	q := sqlcdb.New(pool)

	// Fresh registration starts fully free; re-registering resets free_bytes to
	// total, which is correct for a single-node demo (no concurrent reservations
	// to preserve). A multi-node operator would manage capacity out of band.
	row, err := q.UpsertServerPool(ctx, sqlcdb.UpsertServerPoolParams{
		DataAddr:   *dataAddr,
		OpsAddr:    *opsAddr,
		TotalBytes: *totalBytes,
		FreeBytes:  *totalBytes,
		Status:     *status,
	})
	if err != nil {
		return fmt.Errorf("upsert server pool: %w", err)
	}

	if *asJSON {
		return json.NewEncoder(out).Encode(struct {
			DataAddr   string `json:"data_addr"`
			OpsAddr    string `json:"ops_addr"`
			TotalBytes int64  `json:"total_bytes"`
			FreeBytes  int64  `json:"free_bytes"`
			Status     string `json:"status"`
		}{
			DataAddr:   row.DataAddr,
			OpsAddr:    row.OpsAddr,
			TotalBytes: row.TotalBytes,
			FreeBytes:  row.FreeBytes,
			Status:     row.Status,
		})
	}

	fmt.Fprintf(out, "registered server in pool:\n")
	fmt.Fprintf(out, "  data-addr:  %s  (agents dial this)\n", row.DataAddr)
	fmt.Fprintf(out, "  ops-addr:   %s  (control plane dials this)\n", row.OpsAddr)
	fmt.Fprintf(out, "  capacity:   %d bytes free / %d total\n", row.FreeBytes, row.TotalBytes)
	fmt.Fprintf(out, "  status:     %s\n", row.Status)
	return nil
}
